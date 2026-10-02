#!/usr/bin/env python3
"""reRust full repack pipeline: shim → inject → zipalign → sign (SPEC M1).

This is the `rerust patch` flow end-to-end, kept as a thin orchestration
script while the CLI's `patch` command (src/rerust/cli.py, W1-owned) gets
wired to the same functions.

    scripts/repack_apk.py app.apk --proxy http://10.0.2.2:8080 --out app.rerust.apk

Pipeline:
  1. build shim — baked with the proxy URL (flagship: self-contained .so,
     no runtime file needed). --no-bake uses the file-reading shim instead
     (/data/local/tmp/rerust_proxy; blocked by SELinux on some images).
     --shim <path> skips the build entirely and injects what you pass.
  2. inject — src/rerust/repack.py: patchelf DT_NEEDED + zip rebuild.
  3. zipalign -f -p 4 — 4-byte align everything, 4 KiB page-align stored
     .so files (Android 15 16 KiB-page devices would want `-P 16`; our
     bench emulator reports PAGE_SIZE 4096, and the target APK keeps
     extractNativeLibs=true, which does not require page alignment at all —
     we align anyway so the output is also valid if the flag is flipped).
  4. apksigner sign — Android debug keystore (~/.android/debug.keystore,
     androiddebugkey/android, generated via keytool if missing). Same key
     reinstalled over itself upgrades; a different signature than the
     store app is expected and fine for a bench install.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from rerust.repack import repack_apk  # noqa: E402  (path set above)

import os

def _find_sdk():
    for v in (os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME"),
              str(pathlib.Path.home() / "Android" / "Sdk"), "/opt/android-sdk"):
        if v and pathlib.Path(v).is_dir():
            return v
    raise SystemExit("Android SDK not found: set ANDROID_SDK_ROOT or ANDROID_HOME")

DEFAULT_SDK = _find_sdk()

def _find_ndk():
    v = os.environ.get("ANDROID_NDK") or os.environ.get("ANDROID_NDK_HOME")
    if v and pathlib.Path(v).is_dir():
        return v
    base = pathlib.Path(DEFAULT_SDK) / "ndk"
    if base.is_dir():
        cands = sorted(x for x in base.iterdir() if x.is_dir())
        if cands:
            return str(cands[-1])
    raise SystemExit("Android NDK not found: set ANDROID_NDK or install under $ANDROID_SDK_ROOT/ndk")

DEFAULT_NDK = _find_ndk()
KEYSTORE = Path.home() / ".android" / "debug.keystore"
KS_ALIAS, KS_PASS = "androiddebugkey", "android"


def sh(cmd: list[str], **kw) -> None:
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kw)


def ensure_keystore() -> None:
    if KEYSTORE.exists():
        return
    print(f"generating debug keystore: {KEYSTORE}")
    KEYSTORE.parent.mkdir(parents=True, exist_ok=True)
    sh([
        "keytool", "-genkeypair", "-v",
        "-keystore", str(KEYSTORE),
        "-alias", KS_ALIAS,
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
        "-storepass", KS_PASS, "-keypass", KS_PASS,
        "-dname", "CN=Android Debug,O=Android,C=US",
    ])


def build_shim(proxy: str | None, ndk: str, out: Path,
               hook_target: str | None = None, hook_port: int | None = None,
               hook_timeout: int | None = None) -> Path:
    cmd = [str(REPO / "shim" / "build.sh"), "--ndk", ndk, "-o", str(out)]
    if proxy:
        cmd += ["--proxy", proxy]
    if hook_target:
        cmd += [f"--hook-connect={hook_target}"]
    if hook_port is not None:
        cmd += ["--hook-port", str(hook_port)]
    if hook_timeout is not None:
        cmd += ["--hook-timeout", str(hook_timeout)]
    sh(cmd)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("apk")
    p.add_argument("--proxy", help="proxy URL to bake into the shim")
    p.add_argument("--out", required=True)
    p.add_argument("--shim", help="prebuilt shim to inject (skips step 1)")
    p.add_argument("--also-patch", action="append", default=[], metavar="LIB",
                   help="also add DT_NEEDED to this lib (name or lib/<abi>/<name>); "
                        "e.g. --also-patch libflutter.so for a does-the-shim-load diagnostic")
    p.add_argument("--hook-connect", nargs="?", const="127.0.0.1:9999", default=None,
                   metavar="HOST:PORT",
                   help="build the M2.5 connect() hook into the shim (target ipv4:port or "
                        "bare port; default 127.0.0.1:9999, the adb-reverse endpoint). For "
                        "Rust libs with no env-proxy plumbing (libfjs). Combinable with "
                        "--proxy: one env+hook build serves every Rust lib")
    p.add_argument("--hook-port", type=int, default=443, metavar="N",
                   help="destination port the connect hook intercepts (default 443)")
    p.add_argument("--hook-timeout", type=int, default=1500, metavar="MS",
                   help="tunnel-establishment deadline per connect (default 1500)")
    p.add_argument("--redirect", choices=("env", "all"), default=None,
                   help="env: shim env-proxy-marker libs only (M1). all: also hook-shim "
                        "rustls libs lacking the marker (M2.5); requires --hook-connect. "
                        "default: 'all' iff --hook-connect was given, else 'env'")
    p.add_argument("--no-bake", action="store_true",
                   help="use the file-reading shim (reads /data/local/tmp/rerust_proxy)")
    p.add_argument("--build-tools", default=f"{DEFAULT_SDK}/build-tools/36.0.0")
    p.add_argument("--ndk", default=DEFAULT_NDK)
    p.add_argument("--workdir", default="/tmp/rerust-work")
    p.add_argument("--no-trust", action="store_true",
                   help="skip the rustls trust patch (shim-only repack)")
    p.add_argument("--patterns", default=str(REPO / "patterns"),
                   help="trust pattern DB dir")
    p.add_argument("--require-trust", action="store_true",
                   help="exit 2 if any rustls lib was left unpatched (no DB entry for its fingerprint)")
    args = p.parse_args(argv)

    if args.redirect is None:
        args.redirect = "all" if args.hook_connect else "env"
    if args.redirect == "all" and not args.hook_connect:
        p.error("--redirect=all needs --hook-connect (the hook is what redirects "
                "libs without env plumbing)")

    if not args.proxy and not args.no_bake and not args.shim and not args.hook_connect:
        p.error("need --proxy URL (baked flagship path), --hook-connect, --no-bake or --shim")

    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)

    # 1. shim
    if args.shim:
        shim = Path(args.shim)
    elif args.no_bake:
        shim = build_shim(None, args.ndk, work / "librerust.so",
                          args.hook_connect, args.hook_port, args.hook_timeout)
    else:
        safe = (args.proxy or "") .replace("://", "_").replace(":", "-").replace("/", "_") \
            or "hook"
        if args.hook_connect:
            safe += f"_hook{args.hook_connect.replace(':', '-')}"
        shim = build_shim(args.proxy, args.ndk, work / f"librerust_baked_{safe}.so",
                          args.hook_connect, args.hook_port, args.hook_timeout)

    # 2. inject (+ trust patch unless disabled)
    unsigned = work / (Path(args.out).stem + ".unsigned.apk")
    report = repack_apk(args.apk, shim, unsigned, also_patch=args.also_patch,
                        patterns_dir=None if args.no_trust else args.patterns,
                        redirect=args.redirect)
    print(f"redirect mode: {report.redirect}")
    print(f"patched: {', '.join(report.patched) or 'NOTHING (no env-proxy libs found!)'}")
    if report.hook_patched:
        print(f"connect-hooked: {', '.join(report.hook_patched)}")
    for t in report.trust_patched:
        state = "already" if t["already_applied"] else "patched"
        print(f"trust {state}: {t['lib']} @ {t['file_offset']} ({t['pattern']}, {t['db_file']})")
    for t in report.trust_skipped:
        print(f"trust SKIPPED: {t['lib']} — {t['reason']}", file=sys.stderr)
    if args.require_trust and report.trust_skipped:
        print("error: --require-trust set but rustls libs remain unpatched", file=sys.stderr)
        return 2

    # 3. align (-p: page-align the stored .so entries to 4096 — see docstring)
    aligned = work / (Path(args.out).stem + ".aligned.apk")
    sh([str(Path(args.build_tools) / "zipalign"), "-f", "-p", "4", str(unsigned), str(aligned)])

    # 4. sign
    ensure_keystore()
    out = Path(args.out).resolve()
    sh([
        str(Path(args.build_tools) / "apksigner"), "sign",
        "--ks", str(KEYSTORE), "--ks-key-alias", KS_ALIAS,
        "--ks-pass", f"pass:{KS_PASS}", "--key-pass", f"pass:{KS_PASS}",
        "--out", str(out), str(aligned),
    ])
    sh([str(Path(args.build_tools) / "apksigner"), "verify", str(out)])

    print(f"\nrepacked: {out}")
    print(f"  shim:   {shim}")
    print(f"  libs:   {', '.join(report.patched + report.hook_patched)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
