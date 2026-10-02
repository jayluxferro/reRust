#!/bin/sh
# Build the reRust env-proxy shim for Android.
#
# usage: build.sh [-o OUT.so] [--proxy URL] [--hook-connect[=TARGET]]
#                 [--hook-port N] [--hook-timeout MS] [--api N] [--ndk DIR]
#                 [--clean]
#
#   --proxy URL   bake the proxy into the binary (-DRERUST_PROXY_BAKED).
#                 This is the flagship path: one .so, self-contained, no
#                 runtime file needed. Without it the shim reads
#                 /data/local/tmp/rerust_proxy at startup (adb-pushable,
#                 but blocked by SELinux on some production images — see
#                 docs/research/m1_shim_repack_results.md).
#
#   --hook-connect[=TARGET]
#                 additionally build the M2.5 connect() interposer
#                 (-DRERUST_HOOK_CONNECT) for Rust cores with NO env-proxy
#                 plumbing (embedded JS runtimes). TARGET is ipv4:port or a
#                 bare port (default 127.0.0.1:9999 — the adb-reverse bench
#                 endpoint); the file /data/local/tmp/rerust_hook overrides
#                 at runtime, same resolution order as the proxy. Combinable
#                 with --proxy: one env+hook build serves every Rust lib.
#                 NOTE: hook builds export connect() — repack.py must place
#                 the shim BEFORE libc.so in DT_NEEDED or bionic resolves
#                 libc's connect and the hook silently never fires.
#   --hook-port N   destination port to intercept (default 443).
#   --hook-timeout MS  tunnel-establishment deadline (default 1500).
#
# Output default: /tmp/rerust-work/librerust.so (binaries are never committed).
#
# Why aarch64 + API 24: the shim targets repacked release APKs whose native
# cores are arm64-only in practice (our benchmark target ships arm64-v8a
# exclusively); API 24 covers every device that can run them and is the first
# API with the modern linker namespace semantics the injection relies on.
set -eu

PROXY=""
HOOK_TARGET=""
HOOK_PORT=443
HOOK_TIMEOUT=1500
OUT="/tmp/rerust-work/librerust.so"
API=24
# NOTE: ANDROID_NDK_HOME is deliberately *not* consulted first — on this
# machine it points at an ancient NDK 21 in a different SDK root; the pinned
# default below is the one the pipeline is validated against. Override with
# --ndk if your layout differs.
if [ -z "${RERUST_NDK:-}" ]; then
  for c in "${ANDROID_NDK:-}" "${ANDROID_NDK_HOME:-}" "$ANDROID_SDK_ROOT"/ndk/* "$ANDROID_HOME"/ndk/* "$HOME"/Android/Sdk/ndk/*; do
    [ -d "$c" ] && NDK="$c" && break
  done
else
  NDK="$RERUST_NDK"
fi
[ -n "${NDK:-}" ] || { echo "Android NDK not found: set ANDROID_NDK or install under $ANDROID_SDK_ROOT/ndk"; exit 1; }
if [ ! -d "$NDK" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then NDK="$ANDROID_NDK_HOME"; fi

while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUT="$2"; shift 2 ;;
        --proxy) PROXY="$2"; shift 2 ;;
        --hook-connect)
            HOOK_TARGET="127.0.0.1:9999"; shift ;;
        --hook-connect=*)
            HOOK_TARGET="${1#*=}"
            # bare port => the adb-reverse loopback endpoint
            case "$HOOK_TARGET" in
                [0-9]*) : ;;
                *) echo "bad --hook-connect target: $HOOK_TARGET" >&2; exit 2 ;;
            esac
            case "$HOOK_TARGET" in
                *:*) [ -n "$(echo "$HOOK_TARGET" | grep -E '^[0-9.]+:[0-9]+$')" ] \
                     || { echo "bad --hook-connect target (want ipv4:port): $HOOK_TARGET" >&2; exit 2; } ;;
                *) [ -n "$(echo "$HOOK_TARGET" | grep -E '^[0-9]+$')" ] \
                   && HOOK_TARGET="127.0.0.1:$HOOK_TARGET" \
                   || { echo "bad --hook-connect port: $HOOK_TARGET" >&2; exit 2; } ;;
            esac
            shift ;;
        --hook-port) HOOK_PORT="$2"; shift 2 ;;
        --hook-timeout) HOOK_TIMEOUT="$2"; shift 2 ;;
        --api) API="$2"; shift 2 ;;
        --ndk) NDK="$2"; shift 2 ;;
        --clean) rm -f "$OUT"; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

PREBUILT="$NDK/toolchains/llvm/prebuilt"
if [ ! -d "$PREBUILT" ]; then
    echo "error: NDK toolchain not found under $PREBUILT (set --ndk or ANDROID_NDK_HOME)" >&2
    exit 1
fi
# The prebuilt dir name follows the *host* arch (darwin-x86_64 even on Apple
# Silicon — NDK ships x64 toolchain binaries that run fine under Rosetta).
HOST_DIR=$(ls "$PREBUILT" | head -1)
CC="$PREBUILT/$HOST_DIR/bin/aarch64-linux-android${API}-clang"

BAKE_ARGS=""
if [ -n "$PROXY" ]; then
    echo "baking proxy: $PROXY"
    # Quoting trap: -D macro values are not shell-stripped by the compiler —
    # whatever characters arrive in argv *are* the macro replacement list. The
    # escaped quotes below therefore survive INTO the compiler and act as the C
    # string delimiters. (Doing it via an intermediate variable + unquoted
    # expansion instead puts literal '"' characters into the env value — v1 of
    # this script shipped that bug; the logcat line exposes it immediately as
    #   proxy set: "http://..."   ← quotes in the VALUE, invalid proxy URL.)
    BAKE_ARGS="-DRERUST_PROXY_BAKED=\"$PROXY\""
fi

HOOK_ARGS=""
if [ -n "$HOOK_TARGET" ]; then
    echo "baking connect-hook: :$HOOK_PORT -> $HOOK_TARGET (timeout ${HOOK_TIMEOUT}ms)"
    HOOK_ARGS="-DRERUST_HOOK_CONNECT -DRERUST_HOOK_BAKED=\"$HOOK_TARGET\" \
-DRERUST_HOOK_PORT=$HOOK_PORT -DRERUST_HOOK_TIMEOUT_MS=$HOOK_TIMEOUT"
fi

mkdir -p "$(dirname "$OUT")"
# -llog: __android_log_print bootstrap evidence. Everything else is freestanding
# libc so the shim stays tiny and adds no new dependency surface to the app.
"$CC" -O2 -fPIC -shared -Wall -Wextra \
    -Wl,-soname,librerust.so \
    $BAKE_ARGS $HOOK_ARGS \
    -o "$OUT" \
    "$(dirname "$0")/librerust.c" \
    -llog

echo "built: $OUT"
ls -l "$OUT"
