"""IPA repack: inject the env-proxy shim and defeat rustls trust on iOS.

Mirror of :mod:`rerust.repack` (Android) for .ipa payloads — same two SPEC
moves (M1 env proxy + T1 trust defeat), different loader mechanics:

* Injection is LC_LOAD_DYLIB (padding-only command insertion, see
  :mod:`rerust.macho`) instead of a patchelf DT_NEEDED append. The shim is a
  Frameworks/ dylib; the load command path is
  ``@executable_path/Frameworks/librerust.dylib``, which resolves for every
  binary we inject (``@executable_path`` is always the main executable's dir,
  so a shimmed helper dylib inside Frameworks/ still finds it).
* The shim's constructor runs before the app's static initializers either way
  (dylib constructors run at load time, and the main executable's load
  commands are processed first), so the first reqwest Client — and every one
  after it — sees the proxy environment. On iOS there is no /data/local/tmp
  fallback: the proxy is baked in or read from getenv (app sandbox has no
  pushable scratch space).
* Trust patching works on Mach-O *slices*: a fat binary is fingerprinted and
  patched per slice (arch-agnostic regexes, one DB entry per arch —
  ``target.arch: arm64-ios`` gates which slices a pattern applies to), then
  spliced back at equal size. iOS App Store builds ship thin arm64 slices;
  simulator builds of fat pods may carry x86_64 too.

The output .ipa is re-signed ad-hoc (``codesign -f -s -``) — our byte surgery
invalidates the embedded signature and even the simulator refuses to launch
code whose signature doesn't match its content. Ad-hoc is enough for local
installs; a real device additionally needs development signing + a
provisioned device (and App-Store-distributed targets are FairPlay-encrypted
and out of scope entirely — see docs/lab-setup.md).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import apk_inspect, assets, fingerprint, macho, trust

SHIM_NAME = "librerust.dylib"

# Same discriminating marker as the Android repack (see repack.py for why
# ALL_PROXY and not the wider set — Dart's libflutter would false-positive).
ENV_PROXY_MARKERS = (b"ALL_PROXY",)

# Load-command path the shim is referenced by, in two shapes chosen per slice:
#
# - @rpath (48-byte LC_LOAD_DYLIB): the primary form. Real ld leaves tight
#   header padding — the farm app's rust dylib arm64 slice has exactly 48 B —
#   and the @executable_path form's command is 72 B, which simply does not
#   fit. Resolution needs an LC_RPATH somewhere in the loader chain; Xcode
#   app structures ship @executable_path/Frameworks runpaths (and the
#   simulator e2e in docs/lab-setup.md is the standing proof it resolves).
# - @executable_path/Frameworks (72-byte LC): the fallback when even 48 B
#   don't fit — needs no rpath, only padding.
SHIM_INSTALL_NAME = "@rpath/" + SHIM_NAME
SHIM_INSTALL_NAME_FALLBACK = "@executable_path/Frameworks/" + SHIM_NAME

# select_pattern gates on exact arch equality; Mach-O slice arch names get an
# OS suffix so an iOS arm64 pattern can never fire on an Android aarch64 lib
# even if someone copies the yaml (the codegen differs far too much anyway).
_SLICE_ARCH = {"arm64": "arm64-ios", "x86_64": "x86_64-ios"}

# Binaries we never touch: the Flutter engine is huge, Dart carries its own
# ALL_PROXY string (the false-positive repack.py warns about), and patching
# it buys nothing — the Rust core is never inside libflutter.
_SKIP_NAMES = re.compile(r"^(Flutter|flutter_framework|App)\Z")


def has_env_proxy(data: bytes) -> bool:
    """True if the binary carries hyper-util's env-proxy plumbing."""
    return any(m in data for m in ENV_PROXY_MARKERS)


def _has_shim_anywhere(data: bytes) -> bool:
    """Shim LC (either install-name shape) present in any slice?"""
    try:
        sls = macho.slices(data)
    except macho.MachOError:
        return False
    return any(
        macho.has_dylib(data[sl.offset : sl.offset + sl.size], 0, name)
        for sl in sls
        for name in (SHIM_INSTALL_NAME, SHIM_INSTALL_NAME_FALLBACK)
    )


def _insert_shim_everywhere(data: bytes) -> bytes:
    """LC_LOAD_DYLIB into EVERY 64-bit slice of a thin or fat image.

    A fat main executable loads whichever slice dyld selects — patching only
    arm64 would let an x86_64 process start unshimmed. The injector grows a
    slice by one load command, so this goes through macho.map_slices (fat
    header rebuilt) rather than the size-frozen patch_slice; slices() only
    yields 64-bit images, which is the whole iOS world we target. Per slice:
    the 48-byte @rpath form first, the 72-byte @executable_path form only
    when even 48 B of header padding are missing (see SHIM_INSTALL_NAME).
    """

    def add(blob: bytes, sl: macho.Slice) -> bytes:
        for name in (SHIM_INSTALL_NAME, SHIM_INSTALL_NAME_FALLBACK):
            if macho.has_dylib(blob, 0, name):
                return blob
        try:
            return macho.insert_load_dylib(blob, 0, SHIM_INSTALL_NAME)
        except macho.MachOError as e:
            if "no header padding" not in str(e):
                raise
            return macho.insert_load_dylib(blob, 0, SHIM_INSTALL_NAME_FALLBACK)

    return macho.map_slices(data, add)


@dataclass
class IpaReport:
    """What was done — printed by the CLI and consumed by tests."""

    ipa: str
    out: str
    shim: str
    shim_sha256: str
    app_dir: str  # Payload/<app>.app inside the archive
    patched: list[str] = field(default_factory=list)  # + LC_LOAD_DYLIB
    shims_added: list[str] = field(default_factory=list)
    inspected: list[str] = field(default_factory=list)  # Mach-O entries seen
    trust_patched: list[dict] = field(default_factory=list)
    trust_skipped: list[dict] = field(default_factory=list)
    signed: bool = False


def _app_dir(z: zipfile.ZipFile) -> str:
    """The single Payload/<name>.app/ directory an .ipa must contain."""
    dirs = {
        n.split("/")[0] + "/" + n.split("/")[1]
        for n in z.namelist()
        if n.startswith("Payload/") and n.count("/") >= 1 and ".app/" in n
    }
    apps = sorted({d for d in dirs if d.endswith(".app")})
    if len(apps) != 1:
        raise ValueError(f"expected exactly one Payload/*.app, found {apps or 'none'}")
    return apps[0]


def _bundle_executable(z: zipfile.ZipFile, app_dir: str) -> str:
    """CFBundleExecutable from the bundle's Info.plist (default: bundle name)."""
    import plistlib

    raw = z.read(f"{app_dir}/Info.plist")
    info = plistlib.loads(raw)
    name = info.get("CFBundleExecutable")
    if not name:
        raise ValueError(f"{app_dir}/Info.plist has no CFBundleExecutable")
    return name


def _codesign(app_path: Path, patched_rel: list[str], codesign_bin: str) -> None:
    """Re-sign ad-hoc: the shim + every byte-surgered nested binary, then the app.

    Order matters: `codesign <app>` seals nested code by reference — every
    nested binary must already carry a signature matching its BYTES. Our
    surgery invalidates the ones we patched (and the shim never had one), so
    each of them is re-signed explicitly before the bundle. Flutter frameworks
    pass through untouched and stay valid. The main executable is the
    exception: signing the bundle regenerates its CodeDirectory in place, so
    the caller drops it from `patched_rel`. No --deep — it would re-sign
    untouched code, invalidating nothing but proving nothing.
    """
    targets = []
    shim = app_path / "Frameworks" / SHIM_NAME
    if shim.exists():
        targets.append((shim, "shim dylib"))
    for rel in patched_rel:
        targets.append((app_path / rel, rel))
    targets.append((app_path, "app bundle"))
    for target, label in targets:
        # not check=True: codesign's stderr is the useful part and a bare
        # CalledProcessError would bury it — surface it in the RuntimeError
        # the CLI already catches.
        r = subprocess.run(
            [codesign_bin, "--force", "--sign", "-", str(target)],
            capture_output=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"ad-hoc codesign failed for the {label} ({target}): "
                + r.stderr.decode(errors="replace").strip()
            )


def repack_ipa(
    ipa: str | Path,
    shim: str | Path,
    out: str | Path,
    *,
    also_patch: list[str] = (),
    patterns_dir: str | Path | None = None,
    sign: bool = True,
    codesign_bin: str = "codesign",
) -> IpaReport:
    """Rewrite `ipa` with the shim injected and trust patches applied.

    `also_patch`: entry names (zip paths or bare basenames) to shim despite
    missing env-proxy markers — same false-negative escape hatch as the
    Android repack (marker merged away by LTO, or a diagnostic "does the shim
    load at all?" run).

    `patterns_dir`: trust pattern DB (patterns/). None disables trust
    patching; a rustls slice without a matching DB entry lands in
    trust_skipped — loudly, never silently (same contract as Android).

    `sign`: ad-hoc re-sign the result (default). Off only for tests on
    synthetic zips; an unsigned repack will not launch on any iOS runtime.
    """
    ipa, shim, out = Path(ipa), Path(shim), Path(out)
    shim_data = shim.read_bytes()
    trust_entries = trust.load_patterns(patterns_dir) if patterns_dir else None

    forced = set(also_patch)

    with zipfile.ZipFile(ipa) as zin:
        app_dir = _app_dir(zin)
        main_exe = _bundle_executable(zin, app_dir)

        rewritten: dict[str, bytes] = {}  # zip path -> new bytes
        inspected: list[str] = []
        patched: list[str] = []
        shims_added: list[str] = []  # entries written THIS run (honest report)
        already_shimmed: list[str] = []
        trust_patched: list[dict] = []
        trust_skipped: list[dict] = []

        for name, data in apk_inspect._read_macho_entries(zin).items():
            if _SKIP_NAMES.fullmatch(Path(name).stem):
                continue  # engine/engine-adjacent: never a target (see _SKIP_NAMES)
            # Targets: the main executable, or code under Frameworks/ or
            # PlugIns/. Everything else that happens to start with Mach-O
            # magic (preview dylibs, xpc helpers in odd places) is left alone.
            is_main = name == f"{app_dir}/{main_exe}"
            in_fw = f"{app_dir}/Frameworks/" in name or f"{app_dir}/PlugIns/" in name
            if not (is_main or in_fw):
                continue
            inspected.append(name)
            forced_hit = name in forced or Path(name).name in forced
            if not has_env_proxy(data) and not forced_hit and trust_entries is None:
                continue

            new_data = data
            # T1 trust patch, per slice (see module docstring).
            if trust_entries is not None:
                try:
                    slices = macho.slices(new_data)
                except macho.MachOError as e:
                    trust_skipped.append({"lib": name, "reason": f"unparsable container: {e}"})
                    slices = []
                for sl in slices:
                    blob = new_data[sl.offset : sl.offset + sl.size]
                    arch = _SLICE_ARCH.get(sl.arch)
                    if arch is None:
                        continue
                    fp = fingerprint.fingerprint_bytes(blob)
                    if not (
                        fp["markers"].get("rustls_error_strings")
                        or any(c == "rustls" for c, _ in fp["crates"])
                    ):
                        continue
                    analyzed = fingerprint.analyze(fp)
                    entry = trust.select_pattern(
                        trust_entries, fp["crates"], arch, analyzed.get("tls_stack")
                    )
                    if entry is None:
                        trust_skipped.append({
                            "lib": f"{name}#{sl.arch}",
                            "reason": "rustls present, no pattern DB entry for this fingerprint",
                        })
                        continue
                    patched_blob, off, already = trust.apply_trust(blob, entry)
                    trust_patched.append({
                        "lib": f"{name}#{sl.arch}",
                        "pattern": entry.name,
                        "db_file": entry.db_file,
                        "file_offset": hex(sl.offset + off),
                        "already_applied": already,
                    })
                    if not already:
                        new_data = macho.patch_slice(new_data, sl, patched_blob)

            # M1 shim injection.
            if has_env_proxy(new_data) or forced_hit:
                if _has_shim_anywhere(new_data):
                    already_shimmed.append(name)  # re-repack of a shimmed bundle
                else:
                    new_data = _insert_shim_everywhere(new_data)
                    patched.append(name)
            if new_data != data:
                rewritten[name] = new_data

        if not patched and not rewritten and not already_shimmed and not trust_patched:
            raise ValueError(
                f"no injection target in {ipa}: no binary under {app_dir} carries the "
                f"env-proxy marker and nothing matched --also-patch {sorted(forced)}"
            )

        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w") as zout:
            zout.comment = zin.comment
            for info in zin.infolist():
                name = info.filename
                if name in rewritten:
                    zi = zipfile.ZipInfo(name, date_time=info.date_time)
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.create_system = info.create_system
                    zi.external_attr = info.external_attr  # keep +x on Mach-O
                    zout.writestr(zi, rewritten[name])
                else:
                    zout.writestr(info, zin.read(name))
            shim_entry = f"{app_dir}/Frameworks/{SHIM_NAME}"
            if shim_entry not in rewritten and shim_entry not in zin.namelist():
                # Only add the dylib when this run actually introduced it — a
                # re-repack over an already-shimmed bundle must not produce a
                # duplicate zip entry (zipfile would happily write two).
                zi = zipfile.ZipInfo(shim_entry, date_time=info.date_time)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3  # Unix, so the mode bits are honored
                zi.external_attr = 0o755 << 16
                zout.writestr(zi, shim_data)
                shims_added.append(shim_entry)

    if sign:
        with tempfile.TemporaryDirectory(prefix="rerust-ipa-") as td:
            stage = Path(td) / "stage"
            with zipfile.ZipFile(out) as z:
                z.extractall(stage)
            # zip paths → app-relative; the main executable is re-signed by
            # the bundle signing itself (its CodeDirectory is regenerated).
            patched_rel = [
                name[len(app_dir) + 1 :]
                for name in patched
                if name[len(app_dir) + 1 :] != main_exe
            ]
            _codesign(stage / app_dir, patched_rel, codesign_bin)
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
                for p in sorted(stage.rglob("*")):
                    if p.is_file():
                        zout.write(p, p.relative_to(stage).as_posix())

    return IpaReport(
        ipa=str(ipa),
        out=str(out),
        shim=str(shim),
        shim_sha256=hashlib.sha256(shim_data).hexdigest(),
        app_dir=app_dir,
        patched=sorted(patched),
        shims_added=shims_added,
        inspected=sorted(inspected),
        trust_patched=trust_patched,
        trust_skipped=trust_skipped,
        signed=sign,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rerust-repack-ipa",
        description="Inject the env-proxy shim (+ optional trust patch) into an "
        ".ipa (ad-hoc re-signed; simulator/lab installs).",
    )
    p.add_argument("ipa")
    p.add_argument("--shim", required=True, help="path to a built librerust.dylib")
    p.add_argument("--out", required=True)
    p.add_argument("--also-patch", action="append", default=[],
                   help="bundle entry (name or path) to shim despite missing markers")
    p.add_argument("--patterns", default=None,
                   help="trust pattern DB dir (default: repo patterns/ next to this package)")
    p.add_argument("--no-trust", action="store_true", help="shim only; skip trust patching")
    p.add_argument("--no-sign", action="store_true",
                   help="skip the ad-hoc re-sign (output will not launch)")
    p.add_argument("--codesign", default="codesign", help="codesign binary to use")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not Path(args.shim).exists():
        print(f"error: shim not found: {args.shim}", file=sys.stderr)
        return 2
    from . import assets

    patterns = None if args.no_trust else (args.patterns or assets.patterns_dir())
    try:
        report = repack_ipa(
            args.ipa, args.shim, args.out,
            also_patch=args.also_patch, patterns_dir=patterns,
            sign=not args.no_sign, codesign_bin=args.codesign,
        )
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report.__dict__, indent=2))
    else:
        print(f"app bundle: {report.app_dir}")
        print(f"patched ({len(report.patched)}):")
        for n in report.patched:
            print(f"  + LC_LOAD_DYLIB {SHIM_INSTALL_NAME}: {n}")
        for n in report.shims_added:
            print(f"  + added {n}")
        for t in report.trust_patched:
            state = "already" if t["already_applied"] else "patched"
            print(f"  + trust {state}: {t['lib']} @ {t['file_offset']} ({t['pattern']}, {t['db_file']})")
        for t in report.trust_skipped:
            print(f"  ! trust SKIPPED: {t['lib']} — {t['reason']}", file=sys.stderr)
        print(f"shim: {report.shim} sha256={report.shim_sha256[:16]}…")
        print(f"out:  {report.out} ({'ad-hoc signed' if report.signed else 'NOT signed'})")
    return 0


def run_patch_ipa(args: argparse.Namespace) -> int:
    """The `rerust patch <file.ipa>` flow — iOS analog of pipeline.run_patch.

    Same argparse namespace as the Android path (rerust.pipeline's flag
    surface), so `rerust patch` dispatches without a second command. Flags
    that are Android-only (--ndk, --build-tools, --hook-*, --redirect,
    --no-bake) are ignored here; iOS-specific knobs live in --no-sign /
    --codesign. The shim builds through shim/build.sh --platform ios-sim
    (xcrun, no NDK), or comes from --shim for cross-machine workflows.
    """
    import shutil

    src = Path(args.apk)
    if not src.exists():
        print(f"error: {src} not found", file=sys.stderr)
        return 2
    if not zipfile.is_zipfile(src):
        # cmd_patch routes bare Mach-O images here on magic; the repack needs
        # a bundle (Payload/*.app) to place the shim into Frameworks/ and to
        # codesign. Say so instead of failing deep inside zipfile.
        print(f"error: {src} is a bare Mach-O image — `rerust patch` repacks "
              ".ipa bundles; wrap the app first: `ditto -c -k --sequesterRsrc "
              "--keepParent Runner.app app.ipa`", file=sys.stderr)
        return 2
    out = args.out or str(src.with_suffix("")) + ".rerust.ipa"
    work = Path(getattr(args, "workdir", "/tmp/rerust-work"))
    work.mkdir(parents=True, exist_ok=True)

    if args.shim:
        shim = Path(args.shim)
        if not shim.exists():
            print(f"error: shim not found: {shim}", file=sys.stderr)
            return 2
    else:
        if not args.proxy:
            print("error: need --proxy URL (baked) or --shim — iOS has no "
                  "file-based fallback (app sandbox, no pushable path)",
                  file=sys.stderr)
            return 2
        sources = assets.extract_shim_sources(work / "shim-sources")
        if sources is None or not (sources / "build.sh").exists():
            print("error: shim sources not found (no repo checkout, no "
                  "packaged assets) — cannot build the shim; pass --shim",
                  file=sys.stderr)
            return 2
        build_sh = sources / "build.sh"
        if not shutil.which("xcrun"):
            print("error: xcrun not found — the iOS shim needs Xcode's "
                  "iphonesimulator SDK; pass --shim to skip the build",
                  file=sys.stderr)
            return 2
        safe = (args.proxy or "").replace("://", "_").replace(":", "-").replace("/", "_")
        shim = work / f"librerust_baked_{safe}.dylib"
        print(f"building ios-sim shim (xcrun) → {shim}")
        try:
            subprocess.run(
                ["sh", str(build_sh), "--platform", "ios-sim",
                 "--proxy", args.proxy, "-o", str(shim)],
                check=True,
            )
        except subprocess.CalledProcessError:
            print("error: shim build failed", file=sys.stderr)
            return 1

    patterns = getattr(args, "patterns", None) or assets.patterns_dir()
    if patterns is None and not args.no_trust:
        print("warning: no pattern DB found (repo or packaged) — trust patching disabled",
              file=sys.stderr)
    try:
        report = repack_ipa(
            src, shim, out,
            also_patch=getattr(args, "also_patch", ()),
            patterns_dir=None if args.no_trust else patterns,
            sign=not getattr(args, "no_sign", False),
            codesign_bin=getattr(args, "codesign", "codesign"),
        )
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"app bundle: {report.app_dir}")
    print(f"patched: {', '.join(report.patched) or 'NOTHING (no env-proxy libs found!)'}")
    for t in report.trust_patched:
        state = "already" if t["already_applied"] else "patched"
        print(f"trust {state}: {t['lib']} @ {t['file_offset']} ({t['pattern']}, {t['db_file']})")
    for t in report.trust_skipped:
        print(f"trust SKIPPED: {t['lib']} — {t['reason']}", file=sys.stderr)
    if getattr(args, "require_trust", False) and report.trust_skipped:
        print("error: --require-trust set but rustls libs remain unpatched", file=sys.stderr)
        return 2
    print(f"\nrepacked: {Path(out).resolve()}")
    print(f"  shim:   {shim}")
    print(f"  libs:   {', '.join(report.patched)}")
    print("  install: xcrun simctl install booted <out>; xcrun simctl launch ...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
