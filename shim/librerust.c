/*
 * reRust env-proxy shim (M1) + optional connect() interposition (M2.5).
 *
 * Injected into a repackaged APK next to the app's Rust libs and added to each
 * one's DT_NEEDED (patchelf). Why a constructor: hyper-util/reqwest resolve
 * proxy config from env vars when the first Client is built and cache it in a
 * process-wide OnceLock — so setting the env before any library constructor
 * runs wins for the entire process lifetime, no code patching involved.
 *
 * == M1: env-proxy plumbing (always compiled) ==
 * Proxy resolution order:
 *   1. RERUST_PROXY_BAKED  — compile-time default (-DRERUST_PROXY_BAKED='"http://127.0.0.1:9999"')
 *   2. /data/local/tmp/rerust_proxy — one-line file, adb-pushable, lets one
 *      build serve any proxy without rebuilding
 *
 * == M2.5: connect() interposition (only with -DRERUST_HOOK_CONNECT) ==
 * For Rust cores with NO env-proxy plumbing (HDO Box 4.4.6's libfjs: embedded
 * QuickJS driving hyper+rustls directly), there is nothing to setenv — the
 * redirect has to happen at the socket layer instead. This build defines an
 * exported connect() that resolves the real one via dlsym(RTLD_NEXT) and, for
 * TCP (AF_INET/AF_INET6) flows whose destination port equals RERUST_HOOK_PORT
 * (default 443), connects to the proxy instead and establishes an explicit
 * CONNECT tunnel before returning:
 *
 *   connect(fd, origin:443)            app calls as usual
 *     real_connect(fd, proxy)          EINPROGRESS on a nonblocking fd
 *     <we poll for writability>        TCP handshake to the proxy
 *     send "CONNECT origin:443 ..."    preamble, poll-guarded I/O
 *     recv "HTTP/1.1 2xx ..."          any non-2xx => connect fails
 *     return EINPROGRESS (nonblocking fd) / 0 (blocking fd)
 *
 * The nonblocking contract is the whole difficulty: tokio creates sockets
 * with O_NONBLOCK, so real connect returns EINPROGRESS and the app waits for
 * writability, then confirms via getsockopt(SO_ERROR). Doing the preamble
 * "synchronously" in the classic sense (recv on a nonblocking fd) would just
 * spin EAGAIN. Design chosen (v1, "sync tunnel inside connect"):
 *
 *   - After real_connect returns EINPROGRESS, WE wait for writability on the
 *     calling thread with a poll() deadline (RERUST_HOOK_TIMEOUT_MS, default
 *     1500). The calling thread is the one that owns the not-yet-registered
 *     fd (tokio registers it with epoll only after connect() returns), so no
 *     other thread can be polling it concurrently. The block is bounded.
 *   - We never touch O_NONBLOCK: all preamble I/O is poll-guarded (poll with
 *     remaining budget, then one send/recv; EAGAIN => wait again). A blocking
 *     fd and a nonblocking fd take the same code path.
 *   - On success we return the result the app expects for its own fd mode:
 *     EINPROGRESS for a nonblocking fd (the socket IS fully connected to the
 *     proxy with the tunnel up, so the app's subsequent writable-poll sees
 *     readiness and its SO_ERROR read returns 0 — exactly the state a very
 *     fast direct connect would have produced; epoll CTL_ADD reports
 *     already-ready fds even in edge-triggered mode, so tokio cannot hang),
 *     plain 0 for a blocking fd.
 *   - On any failure we shutdown(fd, SHUT_RDWR) so nothing dangles and fail
 *     the connect with the real errno (proxy refused / non-2xx => ECONNREFUSED
 *     etc). A flow we cannot tunnel fails loudly; it never leaks direct.
 *
 * Known-observable differences (documented in docs/research/m2_connect_hook_findings.md):
 *   - CONNECT carries the resolved origin IP, not the hostname (DNS stays
 *     direct, inside libc — getaddrinfo is not hooked). Post-trust-patch the
 *     TLS SNI recovers the name at the proxy.
 *   - getpeername() shows the proxy address.
 *   - happy-eyeballs dials open two tunnels; the app drops the loser.
 *
 * UDP is deliberately NOT touched (no sendto/recvfrom interposition):
 * QUIC/h3 attempts go direct and are expected to die at the trust layer (or
 * be sinkholed later), forcing the stack back to TCP where this hook lives.
 * Hooking UDP to a TCP-only proxy would just break QUIC without redirecting
 * it; killing UDP/443 outright is a deliberate future lever (M3), not v1.
 *
 * DT_NEEDED ORDER WARNING (repack.py must enforce this): bionic resolves
 * symbols breadth-first over the caller's DT_NEEDED list. patchelf appends
 * librerust.so AFTER libc.so, so libc's connect would win and the hook would
 * silently never fire. The repack pipeline moves libc.so behind the shim
 * (remove + re-add) for hook builds. Verified end-to-end on-device; if the
 * hook logs nothing, check the NEEDED order first (readelf -d).
 *
 * Log line(s) make the hook observable from the host (`adb logcat -s reRust`,
 * or stderr via `xcrun simctl launch --console-pty` on the iOS simulator):
 * one at ctor (armed/inactive) plus rate-limited per-flow lines. Unconfigured
 * M1-only builds stay fully silent so the shim is a no-op vs. the original.
 *
 * == iOS build (shim/build.sh --platform ios-sim|ios-device) ==
 * The same source compiles for Apple with three platform deltas:
 *   - logging goes to stderr (no liblog); visible through the sim console,
 *   - the /data/local/tmp config-file fallbacks do not exist there — proxy
 *     resolution is RERUST_PROXY env (lab override, wins over baked) then
 *     the baked value; the env override is checked on Android too (an env
 *     var an Android app never carries in practice, so behavior is
 *     unchanged there; it lets one binary serve any lab proxy),
 *   - the connect-hook needs SO_NOSIGPIPE (no MSG_NOSIGNAL on Darwin).
 * Injection is LC_LOAD_DYLIB into the main executable (repack_ipa.py), not
 * DT_NEEDED — the DT_NEEDED ordering notes above are Android-only.
 */
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "reRust", __VA_ARGS__)
#else
#define LOGI(...)                          \
    do {                                   \
        fprintf(stderr, "[reRust] " __VA_ARGS__); \
        fputc('\n', stderr);               \
    } while (0)
#endif

/* Darwin has no MSG_NOSIGNAL; SIGPIPE is disabled per-socket instead
 * (SO_NOSIGPIPE is set on every hooked fd before the preamble I/O). */
#if defined(__APPLE__) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#ifndef RERUST_PROXY_BAKED
#define RERUST_PROXY_BAKED ""
#endif

/* ------------------------------------------------------------------ */
/* M1: env-proxy constructor                                           */
/* ------------------------------------------------------------------ */

static void set_proxy_vars(const char *proxy) {
    const char *vars[] = {
        "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
        "ALL_PROXY", "all_proxy", NULL,
    };
    for (const char **v = vars; *v; v++)
        setenv(*v, proxy, 1);
}

#ifdef RERUST_HOOK_CONNECT

#ifndef RERUST_HOOK_BAKED
#define RERUST_HOOK_BAKED ""
#endif
#ifndef RERUST_HOOK_PORT
#define RERUST_HOOK_PORT 443
#endif
#ifndef RERUST_HOOK_TIMEOUT_MS
#define RERUST_HOOK_TIMEOUT_MS 1500
#endif

#define HOOK_CFG_FILE "/data/local/tmp/rerust_hook"

/* String scanned by repack.py to know this .so carries the hook (and thus
 * needs the DT_NEEDED ordering fix). Must stay in sync with repack.py. */
__attribute__((used))
const char rerust_connect_hook_marker[] = "rerust-connect-hook-v1";

static int g_hook_on;              /* compiled in AND configured */
static int g_proxy_port;           /* host byte order */
static struct in_addr g_proxy_v4;  /* proxy is IPv4-only: the bench endpoint is
                                    * the adb-reverse listener (127.0.0.1); a
                                    * v6 socket reaches it via a v4-mapped
                                    * address (below). Numeric hosts only —
                                    * resolving names in a constructor would
                                    * add a DNS dependency to the shim. */
static char g_proxy_str[64];       /* printable, for logs */

static int g_trigger_port = RERUST_HOOK_PORT;

/* Rate-limited per-flow observability: the first 25 flows always, then every
 * 100th. Failures always log (they are the diagnostic signal). */
static _Atomic unsigned g_flow_n;

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "reRust", __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* M2.5: connect() interposition                                       */
/* ------------------------------------------------------------------ */

/* The real connect. dlsym(RTLD_NEXT) is the portable answer; the raw syscall
 * is the fallback for the (not expected) case where RTLD_NEXT misses or
 * hands back our own symbol — falling through to our own connect would
 * recurse infinitely, so never call the resolved pointer without this guard. */
static int (*g_real_connect)(int, const struct sockaddr *, socklen_t);

static int sys_connect(int fd, const struct sockaddr *addr, socklen_t len) {
#if defined(__aarch64__) && defined(__NR_connect)
    /* aarch64: __NR_connect = 203 (asm-generic table) */
    return (int)syscall(__NR_connect, fd, addr, len);
#else
    (void)fd; (void)addr; (void)len;
    errno = ENOSYS;
    return -1;
#endif
}

static void resolve_real_connect(void) {
    void *h = dlsym(RTLD_NEXT, "connect");
    if (h && h != (void *)connect) {
        g_real_connect = (int (*)(int, const struct sockaddr *, socklen_t))h;
    } else {
        g_real_connect = sys_connect;
    }
}

/* "port" => 127.0.0.1:port ; "ipv4:port" => as-is. Returns 1 on success. */
static int parse_hook_target(char *spec) {
    char *colon = strchr(spec, ':');
    const char *host = "127.0.0.1";
    if (colon) {
        *colon = '\0';
        host = spec;
        spec = colon + 1;
    }
    int port = atoi(spec);
    if (port <= 0 || port > 65535 || inet_pton(AF_INET, host, &g_proxy_v4) != 1)
        return 0;
    g_proxy_port = port;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &g_proxy_v4, ip, sizeof ip);
    snprintf(g_proxy_str, sizeof g_proxy_str, "%s:%d", ip, g_proxy_port);
    return 1;
}

static void hook_init(void) {
    resolve_real_connect();

    char spec[128];
    /* Same resolution order as the M1 proxy: env override (lab), baked,
     * then — Android only — the adb-pushable config file. */
    const char *cfg = getenv("RERUST_HOOK");
    if (!cfg || !*cfg)
        cfg = RERUST_HOOK_BAKED;
    if (!*cfg) {
#ifndef __APPLE__
        FILE *f = fopen(HOOK_CFG_FILE, "r");
        if (!f) {
            /* A hook build that found no target is a bench misconfiguration
             * worth one ctor line — unlike the M1-only build, silence here
             * would look identical to "hook armed, no 443 flows yet". */
            LOGI("connect-hook compiled in but unconfigured (%s missing) — inactive", HOOK_CFG_FILE);
            return;
        }
        if (!fgets(spec, sizeof spec, f)) {
            fclose(f);
            LOGI("connect-hook: %s empty — inactive", HOOK_CFG_FILE);
            return;
        }
        fclose(f);
        spec[strcspn(spec, "\r\n")] = '\0';
        cfg = spec;
#else
        LOGI("connect-hook compiled in but unconfigured (no RERUST_HOOK, no baked target) — inactive");
        return;
#endif
    }

    char buf[128];
    snprintf(buf, sizeof buf, "%s", cfg);
    if (!parse_hook_target(buf)) {
        LOGI("connect-hook: bad target '%s' — inactive", cfg);
        return;
    }
    g_hook_on = 1;
    LOGI("connect-hook armed: :%d -> %s (timeout %dms)",
         g_trigger_port, g_proxy_str, (int)RERUST_HOOK_TIMEOUT_MS);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait for one poll event within the shared deadline.
 * Returns 0 with *revents set on readiness (POLLERR/HUP included — callers
 * disambiguate via SO_ERROR / recv), -1 on timeout/error with errno set. */
static int wait_event(int fd, short events, long deadline, short *revents) {
    for (;;) {
        long left = deadline - now_ms();
        if (left <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct pollfd p = { .fd = fd, .events = events, .revents = 0 };
        int r = poll(&p, 1, (int)left);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        *revents = p.revents;
        return 0;
    }
}

static int so_error(int fd) {
    int err = 0;
    socklen_t l = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
    return err;
}

static int send_all(int fd, const char *buf, size_t len, long deadline) {
    while (len) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                return -1;
            short rev;
            if (wait_event(fd, POLLOUT, deadline, &rev) != 0)
                return -1;
            if (rev & POLLERR) {
                errno = so_error(fd);
                return -1;
            }
            continue;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Offset of "\r\n\r\n" in buf[0..len), or (size_t)-1. Headers are small and
 * well-formed in practice; no rolling-KMP needed at 2 KiB. */
static size_t find_header_end(const char *buf, size_t len) {
    if (len < 4)
        return (size_t)-1;
    for (size_t i = 0; i + 4 <= len; i++)
        if (memcmp(buf + i, "\r\n\r\n", 4) == 0)
            return i;
    return (size_t)-1;
}

/* Status code from the first response line ("HTTP/1.x 200 ..."), or -1. */
static int parse_status_code(const char *buf, size_t len) {
    if (len < 12 || strncmp(buf, "HTTP/", 5) != 0)
        return -1;
    const char *sp = memchr(buf, ' ', len);
    if (!sp)
        return -1;
    return atoi(sp + 1); /* "  200" would be malformed anyway; atoi is enough */
}

/* Send the CONNECT preamble and consume the response through the blank line.
 * Everything after "\r\n\r\n" would be tunnel data we cannot push back —
 * proxies send nothing there until the client speaks, but if one ever does,
 * we log the over-read loudly because those bytes are lost. Returns 0 and
 * leaves errno alone on 2xx; -1 with errno set otherwise. */
static int tunnel_preamble(int fd, const char *authority, long deadline) {
    char req[512];
    int n = snprintf(req, sizeof req,
                     "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
                     authority, authority);
    if (n <= 0 || (size_t)n >= sizeof req) {
        errno = EPROTO;
        return -1;
    }
    if (send_all(fd, req, (size_t)n, deadline) != 0)
        return -1;

    char buf[2048];
    size_t have = 0;
    for (;;) {
        short rev;
        if (wait_event(fd, POLLIN, deadline, &rev) != 0)
            return -1; /* ETIMEDOUT (or poll error) */
        ssize_t r = recv(fd, buf + have, sizeof buf - have, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue; /* spurious readiness (HUP without data) */
            return -1;
        }
        if (r == 0) {
            errno = ECONNRESET; /* proxy hung up before answering */
            return -1;
        }
        have += (size_t)r;
        size_t end = find_header_end(buf, have);
        if (end == (size_t)-1) {
            if (have == sizeof buf) {
                errno = EPROTO; /* CONNECT response headers absurdly large */
                return -1;
            }
            continue;
        }
        int code = parse_status_code(buf, end);
        size_t trail = have - (end + 4);
        if (trail)
            LOGI("connect-hook: WARNING %zu tunnel byte(s) read past the "
                 "CONNECT response headers and lost", trail);
        if (code >= 200 && code < 300)
            return 0;
        LOGI("connect-hook: CONNECT %s refused: HTTP %d", authority, code);
        errno = code > 0 ? ECONNREFUSED : EPROTO;
        return -1;
    }
}

/* "1.2.3.4:443" / "[::1]:443" — the authority line of the ORIGINAL dial. */
static void authority_of(const struct sockaddr *sa, char *out, size_t outsz) {
    char ip[INET6_ADDRSTRLEN];
    unsigned port;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip);
        port = ntohs(a->sin_port);
        snprintf(out, outsz, "%s:%u", ip, port);
    } else {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof ip);
        port = ntohs(a->sin6_port);
        snprintf(out, outsz, "[%s]:%u", ip, port);
    }
}

/* Proxy sockaddr matching the socket's family. A v6 socket reaches the v4
 * proxy through a v4-mapped address (::ffff:a.b.c.d) — fine on default
 * dual-stack sockets; a V6ONLY socket would fail the connect visibly, which
 * is the honest outcome for a v4-only proxy target. */
static socklen_t build_proxy_addr(struct sockaddr_storage *ss, int orig_family) {
    memset(ss, 0, sizeof *ss);
    if (orig_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)ss;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)g_proxy_port);
        a->sin_addr = g_proxy_v4;
        return sizeof *a;
    }
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
    a->sin6_family = AF_INET6;
    a->sin6_port = htons((uint16_t)g_proxy_port);
    a->sin6_addr.s6_addr[10] = 0xff;
    a->sin6_addr.s6_addr[11] = 0xff;
    memcpy(&a->sin6_addr.s6_addr[12], &g_proxy_v4, 4);
    return sizeof *a;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!g_real_connect)
        resolve_real_connect();
    if (!g_hook_on || !addr || len < 2)
        return g_real_connect(fd, addr, len);

    const int af = addr->sa_family;
    if (af != AF_INET && af != AF_INET6)
        return g_real_connect(fd, addr, len); /* unix/netlink/etc — untouched */

    /* Port sits at offset 2 in both families; full-struct guards keep the
     * reads inside what the caller actually passed. */
    const size_t need = af == AF_INET ? sizeof(struct sockaddr_in)
                                      : sizeof(struct sockaddr_in6);
    if (len < need)
        return g_real_connect(fd, addr, len);

    unsigned dport = af == AF_INET
        ? ntohs(((const struct sockaddr_in *)addr)->sin_port)
        : ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    if (dport != (unsigned)g_trigger_port)
        return g_real_connect(fd, addr, len);

    char authority[INET6_ADDRSTRLEN + 8];
    authority_of(addr, authority, sizeof authority);

    unsigned n = atomic_fetch_add(&g_flow_n, 1) + 1;
    int log_flow = (n <= 25 || n % 100 == 0);

    long deadline = now_ms() + RERUST_HOOK_TIMEOUT_MS;

    struct sockaddr_storage pss;
    socklen_t plen = build_proxy_addr(&pss, af);
    int rc = g_real_connect(fd, (struct sockaddr *)&pss, plen);
#ifdef SO_NOSIGPIPE
    /* Darwin has no MSG_NOSIGNAL; keep the preamble I/O from SIGPIPE-killing
     * the app if the proxy dies mid-handshake. Harmless elsewhere. */
    int nosigpipe = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof nosigpipe);
#endif
    if (rc != 0 && errno != EINPROGRESS) {
        int e = errno; /* proxy unreachable — the honest failure */
        if (log_flow)
            LOGI("connect-hook: %s -> %s: proxy connect: %s",
                 authority, g_proxy_str, strerror(e));
        errno = e;
        return -1;
    }
    if (rc != 0) { /* EINPROGRESS: drive the handshake ourselves */
        short rev;
        if (wait_event(fd, POLLOUT, deadline, &rev) != 0) {
            int e = errno;
            int soerr = so_error(fd);
            shutdown(fd, SHUT_RDWR);
            errno = soerr ? soerr : e;
            if (log_flow)
                LOGI("connect-hook: %s: handshake wait: %s",
                     authority, strerror(errno));
            return -1;
        }
        int soerr = so_error(fd);
        if (soerr) {
            shutdown(fd, SHUT_RDWR);
            errno = soerr;
            if (log_flow)
                LOGI("connect-hook: %s -> %s: %s",
                     authority, g_proxy_str, strerror(errno));
            return -1;
        }
    }

    if (tunnel_preamble(fd, authority, deadline) != 0) {
        int e = errno;
        shutdown(fd, SHUT_RDWR);
        errno = e;
        LOGI("connect-hook: %s: tunnel failed: %s", authority, strerror(errno));
        return -1;
    }

    if (log_flow)
        LOGI("connect-hook: %s -> %s CONNECT ok (flow #%u)", authority, g_proxy_str, n);

    /* Result shape follows the fd, not our preference: a nonblocking fd must
     * come back EINPROGRESS so the app completes it the way it always does
     * (writable poll + SO_ERROR — both genuinely positive now); a blocking
     * fd reports plain success. F_GETFL failing is not worth failing the
     * flow over — assume blocking semantics. */
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0 && (fl & O_NONBLOCK)) {
        errno = EINPROGRESS;
        return -1;
    }
    return 0;
}

#endif /* RERUST_HOOK_CONNECT */

__attribute__((constructor))
static void rerust_init(void) {
    /* Resolution order: RERUST_PROXY env override (lab flexibility — one
     * binary, any proxy; Android apps never carry this var in practice, so
     * production behavior is unchanged), then the baked value, then the
     * adb-pushable config file (Android only — no such path on iOS). */
    const char *proxy = getenv("RERUST_PROXY");
    if (!proxy || !*proxy) {
        proxy = RERUST_PROXY_BAKED;
        if (!*proxy) {
#ifndef __APPLE__
            char buf[512];  /* config-file readback — Android only */
            FILE *f = fopen("/data/local/tmp/rerust_proxy", "r");
            if (f) {
                if (fgets(buf, sizeof buf, f)) {
                    buf[strcspn(buf, "\r\n")] = '\0';
                    proxy = buf;
                }
                fclose(f);
            }
#endif
        }
    }
    if (*proxy) {
        set_proxy_vars(proxy);
        LOGI("proxy set: %s", proxy);
    }

#ifdef RERUST_HOOK_CONNECT
    hook_init();
#endif
}
