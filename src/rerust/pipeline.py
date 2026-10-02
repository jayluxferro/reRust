"""Full repack pipeline: shim build → inject → zipalign → sign (SPEC M1).

Ported from scripts/repack_apk.py (which is now a thin dev wrapper delegating
to pipeline.main here) so `rerust patch` works from an INSTALLED wheel: the
shim sources are resolved through rerust.assets and copied into the workdir
for the NDK build — no repo layout is assumed at runtime.

Pipeline steps, unchanged in substance from the script days:
  1. build shim — baked with the proxy URL (flagship: self-contained .so).
     --no-bake uses the file-reading shim (/data/local/tmp/rerust_proxy;
     blocked by SELinux on some images). --shim <path> skips the build.
  2. inject — rerust.repack.repack_apk: patchelf DT_NEEDED + zip rebuild
     (+ rustls trust patch from the pattern DB unless disabled).
  3. zipalign -f -p 4 — 4-byte align everything, 4 KiB page-align stored .so
     files (Android 15 16 KiB-page devices would want -P 16; the bench
     emulator reports PAGE_SIZE 4096 and the target keeps
     extractNativeLibs=true, which needs no page alignment — aligned anyway).
  4. apksigner sign — Android debug keystore (~/.android/debug.keystore,
     androiddebugkey/android, generated via keytool if missing). Reinstalling
     over the same key upgrades; a different signature than the store app is
     expected and fine on a bench.

Exit-code contract (kept from the script): 0 = repacked and verified;
2 = usage/config error (missing SDK/NDK, bad flag combination, missing input);
1 = a pipeline step failed (compiler/patchelf/zipalign/apksigner non-zero,
repack error). SDK/NDK resolution is lazy — only touched when a shim build
actually happens, so --shim works on machines without an NDK.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from . import assets
from .repack import repack_apk

KEYSTORE = Path.home() / ".android" / "debug.keystore"
KS_ALIAS, KS_PASS = "androiddebugkey", "android"

# Pinned build-tools the pipeline is validated against (scripts-era default).
BUILD_TOOLS_VERSION = "36.0.0"


def sh(cmd: list[str], **kw) -> None:
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kw)


def find_sdk() -> str:
    for v in (os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME"),
              str(Path.home() / "Android" / "Sdk"), "/opt/android-sdk"):
        if v and Path(v).is_dir():
            return v
    raise FileNotFoundError(
        "Android SDK not found: set ANDROID_SDK_ROOT or ANDROID_HOME"
    )


def find_ndk(sdk: str | None = None) -> str:
    v = os.environ.get("ANDROID_NDK") or os.environ.get("ANDROID_NDK_HOME")
    if v and Path(v).is_dir():
        return v
    base = Path(sdk if sdk is not None else find_sdk()) / "ndk"
    if base.is_dir():
        cands = sorted(x for x in base.iterdir() if x.is_dir())
        if cands:
            return str(cands[-1])
    raise FileNotFoundError(
        "Android NDK not found: set ANDROID_NDK or install under $ANDROID_SDK_ROOT/ndk"
    )


def ensure_keystore(keystore: Path = KEYSTORE) -> Path:
    """The debug keystore, generated via keytool on first use."""
    if keystore.exists():
        return keystore
    print(f"generating debug keystore: {keystore}")
    keystore.parent.mkdir(parents=True, exist_ok=True)
    sh([
        "keytool", "-genkeypair", "-v",
        "-keystore", str(keystore),
        "-alias", KS_ALIAS,
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
        "-storepass", KS_PASS, "-keypass", KS_PASS,
        "-dname", "CN=Android Debug,O=Android,C=US",
    ])
    return keystore


def build_shim(
    proxy: str | None,
    ndk: str,
    out: Path,
    *,
    source_dir: Path,
    hook_target: str | None = None,
    hook_port: int | None = None,
    hook_timeout: int | None = None,
) -> Path:
    """Compile librerust.so from the sources in `source_dir` (extracted by
    assets.extract_shim_sources — works from a repo checkout OR a wheel)."""
    cmd = [str(source_dir / "build.sh"), "--ndk", ndk, "-o", str(out)]
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


def run_patch(args: argparse.Namespace) -> int:
    """The `rerust patch` flow, shared by the CLI and scripts/repack_apk.py.

    Takes the parsed argparse namespace (both frontends use identical flag
    names); returns the process exit code.
    """
    redirect = args.redirect
    if redirect is None:
        redirect = "all" if args.hook_connect else "env"
    if redirect == "all" and not args.hook_connect:
        print("error: --redirect=all needs --hook-connect (the hook is what "
              "redirects libs without env plumbing)", file=sys.stderr)
        return 2
    if not args.proxy and not args.no_bake and not args.shim and not args.hook_connect:
        print("error: need --proxy URL (baked flagship path), --hook-connect, "
              "--no-bake or --shim", file=sys.stderr)
        return 2
    if not Path(args.apk).exists():
        print(f"error: {args.apk} not found", file=sys.stderr)
        return 2
    # run_patch owns the --out default so both frontends (and tests) get it.
    if not args.out:
        args.out = str(Path(args.apk).with_suffix("")) + ".rerust.apk"

    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)

    # 1. shim
    if args.shim:
        shim = Path(args.shim)
    else:
        # NDK is only needed on this path — resolution is lazy so --shim works
        # on machines without one.
        try:
            ndk = args.ndk or find_ndk()
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        sources = work / "shim-sources"
        if assets.extract_shim_sources(sources) is None:
            print("error: shim sources not found (no repo checkout, no packaged "
                  "assets) — cannot build the shim; pass --shim", file=sys.stderr)
            return 2
        if args.no_bake:
            shim = build_shim(None, ndk, work / "librerust.so", source_dir=sources,
                              hook_target=args.hook_connect, hook_port=args.hook_port,
                              hook_timeout=args.hook_timeout)
        else:
            safe = (args.proxy or "").replace("://", "_").replace(":", "-").replace("/", "_") \
                or "hook"
            if args.hook_connect:
                safe += f"_hook{args.hook_connect.replace(':', '-')}"
            shim = build_shim(args.proxy, ndk, work / f"librerust_baked_{safe}.so",
                              source_dir=sources, hook_target=args.hook_connect,
                              hook_port=args.hook_port, hook_timeout=args.hook_timeout)

    # 2. inject (+ trust patch unless disabled)
    patterns = args.patterns or assets.patterns_dir()
    if patterns is None and not args.no_trust:
        print("warning: no pattern DB found (repo or packaged) — trust patching disabled",
              file=sys.stderr)
    try:
        unsigned = work / (Path(args.out).stem + ".unsigned.apk")
        report = repack_apk(args.apk, shim, unsigned, also_patch=args.also_patch,
                            patterns_dir=None if args.no_trust else patterns,
                            redirect=redirect)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
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

    # 3. align (-p: page-align the stored .so entries to 4096)
    build_tools = args.build_tools or str(Path(find_sdk()) / "build-tools" / BUILD_TOOLS_VERSION)
    aligned = work / (Path(args.out).stem + ".aligned.apk")
    try:
        sh([str(Path(build_tools) / "zipalign"), "-f", "-p", "4", str(unsigned), str(aligned)])

        # 4. sign
        keystore = ensure_keystore()
        out = Path(args.out).resolve()
        sh([
            str(Path(build_tools) / "apksigner"), "sign",
            "--ks", str(keystore), "--ks-key-alias", KS_ALIAS,
            "--ks-pass", f"pass:{KS_PASS}", "--key-pass", f"pass:{KS_PASS}",
            "--out", str(out), str(aligned),
        ])
        sh([str(Path(build_tools) / "apksigner"), "verify", str(out)])
    except FileNotFoundError as e:
        print(f"error: {e.filename or e} — Android build-tools missing? "
              f"(looked under {build_tools})", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"error: pipeline step failed ({e.cmd[0] if e.cmd else e})", file=sys.stderr)
        return 1

    print(f"\nrepacked: {out}")
    print(f"  shim:   {shim}")
    print(f"  libs:   {', '.join(report.patched + report.hook_patched)}")
    return 0


def add_patch_args(p: argparse.ArgumentParser) -> None:
    """The shared flag surface for `rerust patch` and scripts/repack_apk.py."""
    p.add_argument("apk")
    p.add_argument("--proxy", help="proxy URL to bake into the shim")
    p.add_argument("--out", help="output APK path (default: <input>.rerust.apk)")
    p.add_argument("--shim", help="prebuilt shim to inject (skips the NDK build)")
    p.add_argument("--no-bake", action="store_true",
                   help="use the file-reading shim (reads /data/local/tmp/rerust_proxy)")
    p.add_argument("--also-patch", action="append", default=[], metavar="LIB",
                   help="also add DT_NEEDED to this lib (name or lib/<abi>/<name>)")
    p.add_argument("--hook-connect", nargs="?", const="127.0.0.1:9999", default=None,
                   metavar="HOST:PORT",
                   help="build the M2.5 connect() hook into the shim (target ipv4:port or "
                        "bare port; default 127.0.0.1:9999, the adb-reverse endpoint)")
    p.add_argument("--hook-port", type=int, default=443, metavar="N",
                   help="destination port the connect hook intercepts (default 443)")
    p.add_argument("--hook-timeout", type=int, default=1500, metavar="MS",
                   help="tunnel-establishment deadline per connect (default 1500)")
    p.add_argument("--redirect", choices=("env", "all"), default=None,
                   help="env: shim env-proxy-marker libs only (M1). all: also hook-shim "
                        "rustls libs lacking the marker (M2.5); requires --hook-connect. "
                        "default: 'all' iff --hook-connect was given, else 'env'")
    p.add_argument("--ndk", help="Android NDK dir (default: env / newest under the SDK)")
    p.add_argument("--build-tools",
                   help=f"build-tools dir with zipalign+apksigner "
                        f"(default: <sdk>/build-tools/{BUILD_TOOLS_VERSION})")
    p.add_argument("--workdir", default="/tmp/rerust-work")
    p.add_argument("--no-trust", action="store_true", help="skip the rustls trust patch")
    p.add_argument("--patterns", help="trust pattern DB dir (default: repo checkout or "
                                      "packaged assets)")
    p.add_argument("--require-trust", action="store_true",
                   help="exit 2 if any rustls lib was left unpatched")


def main(argv: list[str] | None = None) -> int:
    """Entry for scripts/repack_apk.py (dev wrapper)."""
    p = argparse.ArgumentParser(
        prog="rerust-repack-pipeline",
        description="reRust full repack pipeline: shim → inject → zipalign → sign.",
    )
    add_patch_args(p)
    args = p.parse_args(argv)
    if not args.out:
        args.out = str(Path(args.apk).with_suffix("")) + ".rerust.apk"
    return run_patch(args)
