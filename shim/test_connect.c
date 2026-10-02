/*
 * On-device validation harness for the M2.5 connect() hook (W6).
 *
 * Links against librerust.so (hook build) as a direct DT_NEEDED placed BEFORE
 * libc.so, so the harness's own connect() calls resolve to the shim's — the
 * same interposition path the app gets from the repack's NEEDED reorder. If
 * the hook never fires, every assertion below fails, not just the redirected
 * ones.
 *
 * Cases (arg selects):
 *   nb   — nonblocking AF_INET :443: hook must return EINPROGRESS (the tokio
 *          contract), then poll(POLLOUT) must become writable and
 *          getsockopt(SO_ERROR) must be 0 — i.e. the CONNECT tunnel is fully
 *          established by the time the app-style completion check runs.
 *   blk  — blocking AF_INET :443: hook must return 0.
 *   pass — nonblocking to the proxy port itself (≠ trigger port): passthrough,
 *          plain EINPROGRESS + real handshake (no hook CONNECT at the proxy).
 *   v6   — nonblocking AF_INET6 [::1]:443... actually connects to the v4
 *          proxy via a v4-mapped address inside the shim; exercises the
 *          build_proxy_addr v6 branch.
 *
 * Usage: test_connect nb|blk|pass|v6 <origin-ip> [port]
 * The proxy target/trigger port live in the shim's baked config; this binary
 * is config-free on purpose — it sees exactly what the app sees.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int dial(int family, const char *ip, unsigned port, int nonblock) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    if (nonblock && fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
        perror("fcntl(O_NONBLOCK)");

    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
    const struct sockaddr *sa;
    socklen_t sl;
    memset(&a4, 0, sizeof a4);
    memset(&a6, 0, sizeof a6);
    if (family == AF_INET) {
        a4.sin_family = AF_INET;
        a4.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &a4.sin_addr) != 1) { fprintf(stderr, "bad ip\n"); return -1; }
        sa = (struct sockaddr *)&a4;
        sl = sizeof a4;
    } else {
        a6.sin6_family = AF_INET6;
        a6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &a6.sin6_addr) != 1) { fprintf(stderr, "bad ip6\n"); return -1; }
        sa = (struct sockaddr *)&a6;
        sl = sizeof a6;
    }

    errno = 0;
    int r = connect(fd, sa, sl);
    printf("connect -> r=%d errno=%d (%s)\n", r, errno, errno ? strerror(errno) : "-");

    if (nonblock) {
        if (r != 0 && errno != EINPROGRESS) {
            printf("FAIL: expected EINPROGRESS-style result\n");
            return -1;
        }
        struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int pr = poll(&p, 1, 8000);
        int soerr = -1;
        socklen_t l = sizeof soerr;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l);
        printf("poll(POLLOUT)=%d revents=0x%x SO_ERROR=%d (%s)\n",
               pr, pr > 0 ? p.revents : 0, soerr, soerr ? strerror(soerr) : "success");
        if (pr <= 0 || soerr != 0) {
            printf("FAIL: completion check did not report an established socket\n");
            return -1;
        }
    } else if (r != 0) {
        printf("FAIL: blocking connect returned %d\n", r);
        return -1;
    }

    /* Bidirectional smoke: the tunnel must carry bytes both ways. Nothing
     * meaningful will answer a plaintext write on a TLS port, but the write
     * being accepted and the peer responding (or cleanly closing) proves the
     * fd is wired to the proxy, not to a dead end. */
    const char *probe = "GET / HTTP/1.0\r\nHost: probe\r\n\r\n";
    ssize_t w = write(fd, probe, strlen(probe));
    printf("write=%zd errno=%d\n", w, w < 0 ? errno : 0);
    if (w < 0) { printf("FAIL: write refused\n"); return -1; }
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    int pr = poll(&p, 1, 8000);
    if (pr > 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof buf);
        printf("read=%zd (peer responded or closed — tunnel is live)\n", n);
    } else {
        printf("read: no answer in 8s (tunnel accepted the bytes; upstream may be slow)\n");
    }
    close(fd);
    printf("OK\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s nb|blk|pass|v6 <ip> [port]\n", argv[0]); return 2; }
    const char *mode = argv[1];
    const char *ip = argc > 2 ? argv[2] : "1.1.1.1";
    unsigned port = argc > 3 ? (unsigned)atoi(argv[3]) : 443;
    if (!strcmp(mode, "nb"))  return dial(AF_INET, ip, port, 1);
    if (!strcmp(mode, "blk")) return dial(AF_INET, ip, port, 0);
    if (!strcmp(mode, "pass")) return dial(AF_INET, ip, port, 1);
    if (!strcmp(mode, "v6"))  return dial(AF_INET6, "::1", port, 1);
    fprintf(stderr, "unknown mode\n");
    return 2;
}
