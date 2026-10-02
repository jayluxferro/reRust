"""APK repack: inject the env-proxy shim and defeat rustls trust (SPEC M1 + T1).

Zip surgery only — no APK signing, no SDK tools (those live in the
scripts/repack_apk.py wrapper, which calls zipalign + apksigner after this).
Dependencies: patchelf (DT_NEEDED) + the pattern DB (yaml, via trust.py).

How shim injection works: every lib/<abi>/*.so whose rodata carries the
hyper-util env-proxy plumbing gets ``DT_NEEDED librerust.so`` appended
(patchelf) and the shim dropped next to it. The shim's ELF constructor runs
setenv() before any Rust static init, so the first reqwest Client — and every
one after it — resolves its proxy config from the environment.

Marker choice, deliberately narrower than "looks like Rust": ALL_PROXY is the
discriminating string of hyper-util's env-proxy table (the full
HTTP_PROXY..all_proxy run is compiled as one unit next to it). Matching
HTTPS_PROXY too would false-positive on Flutter apps' libapp.so/libflutter.so
(Dart embeds the substring for its own HttpClient) — we would patch megabytes
of engine for nothing. Verified on real targets: ALL_PROXY hits exactly
librhttp.so, the only lib with reqwest inside.

Redirect modes:
  "env" (default) — shim only libs with the ALL_PROXY marker (M1).
  "all"           — ALSO shim libs whose fingerprint says rustls but which
                    lack the env marker (M2.5 connect-hook). These have no
                    env plumbing to configure (embedded JS runtimes:
                    QuickJS driving hyper+rustls directly), so their shim
                    must be the connect-hook build; repack refuses a
                    hook-less shim in this mode rather than injecting
                    something that redirects nothing. The caller passes the
                    hook shim for ALL targets — an env+hook combined build
                    serves both classes in one file (the hook only touches
                    port 443, so it never collides with the env-proxy path,
                    which dials the proxy's own port).

Hook builds and DT_NEEDED order (the part that silently decides whether the
hook works at all): bionic resolves symbols breadth-first over the caller's
DT_NEEDED list. libc.so exports connect, so if it sits in front of the shim
the hook never fires — no error, no log, just unredirected traffic. The
placement of a freshly added DT_NEEDED entry is patchelf-version-dependent
(the version validated on-device prepends, which is already correct; an
appending one would need libc pushed behind), so the order is verified and
repaired if needed — see _patch_needed. Harmless for plain shims (they
export nothing), applied automatically whenever the shim carries the hook
marker, regardless of redirect mode.

How trust patching works (patterns_dir given): every Rust lib whose
fingerprint says rustls gets the DB entry matching crate@version+arch(+extras)
applied — see trust.py. Trust patching is independent of shim injection
(a rustls lib without env plumbing, e.g. an embedded-runtime lib, still gets its
verify patch — with --redirect=all its redirect comes from the connect hook
in the same pass).
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

from . import fingerprint, trust

SHIM_NAME = "librerust.so"

# See module docstring for why this is ALL_PROXY and not the wider var set.
ENV_PROXY_MARKERS = (b"ALL_PROXY",)

# rodata string the hook build of the shim embeds (shim/librerust.c). Its
# presence is what repack keys the DT_NEEDED ordering fix on — the shim
# self-identifies instead of the caller having to pass a matching flag.
CONNECT_HOOK_MARKER = b"rerust-connect-hook-v1"

# Old signatures must go: stale MANIFEST.MF digests + *.SF/*.RSA would fail v1
# verification after we rewrite entries, and apksigner regenerates all of them
# anyway. Everything else under META-INF (services/, .version, ...) is kept.
_SIG_ENTRY = re.compile(r"^META-INF/(MANIFEST\.MF$|.*\.(SF|RSA|DSA|EC)$)")

_LIB_ENTRY = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")


def has_env_proxy(data: bytes) -> bool:
    """True if the binary carries hyper-util's env-proxy plumbing."""
    return any(m in data for m in ENV_PROXY_MARKERS)


def shim_is_hook(shim_data: bytes) -> bool:
    """True if the shim is a connect-hook build (exports connect())."""
    return CONNECT_HOOK_MARKER in shim_data


@dataclass
class RepackReport:
    """What was done — printed by the CLI and consumed by tests."""

    apk: str
    out: str
    shim: str
    shim_sha256: str
    patched: list[str] = field(default_factory=list)  # zip paths rewritten
    shims_added: list[str] = field(default_factory=list)  # lib/<abi>/librerust.so
    inspected: list[str] = field(default_factory=list)  # .so seen, no marker
    trust_patched: list[dict] = field(default_factory=list)  # T1 applications
    trust_skipped: list[dict] = field(default_factory=list)  # rustls w/o DB entry
    redirect: str = "env"  # "env" | "all"
    hook_patched: list[str] = field(default_factory=list)  # M2.5 (rustls, no env) libs


def _dt_needed(path: Path, tool: str) -> list[str]:
    out = subprocess.run(
        [tool, "--print-needed", str(path)], capture_output=True, text=True
    )
    if out.returncode != 0:
        raise RuntimeError(f"patchelf --print-needed failed on {path}: {out.stderr.strip()}")
    return out.stdout.split()


def _remove_needed(path: Path, tool: str, lib: str) -> None:
    out = subprocess.run(
        [tool, "--remove-needed", lib, str(path)], capture_output=True, text=True
    )
    if out.returncode != 0:
        raise RuntimeError(f"patchelf --remove-needed failed on {path}: {out.stderr.strip()}")
    if lib in _dt_needed(path, tool):
        raise RuntimeError(f"patchelf claimed success but {lib} still in {path}")


def _add_needed(path: Path, tool: str, lib: str) -> None:
    """Add DT_NEEDED, skipping libs that already carry it (repack idempotence).

    patchelf --add-needed would happily append a duplicate entry on re-runs;
    duplicate NEEDED names make the linker load the shim twice — harmless for
    setenv but noise in the report, and a second constructor pass.
    """
    if lib in _dt_needed(path, tool):
        return
    out = subprocess.run(
        [tool, "--add-needed", lib, str(path)], capture_output=True, text=True
    )
    if out.returncode != 0:
        raise RuntimeError(f"patchelf --add-needed failed on {path}: {out.stderr.strip()}")
    if lib not in _dt_needed(path, tool):
        raise RuntimeError(f"patchelf claimed success but {lib} missing from {path}")


def _patch_needed(path: Path, tool: str, hook: bool) -> None:
    """Attach the shim; for hook builds, ensure it sits BEFORE libc.so.

    Why order matters: bionic resolves a symbol breadth-first over the
    caller's DT_NEEDED list. If libc.so resolves connect first, the hook
    silently never fires — no error, no log, unredirected traffic.

    patchelf's --add-needed placement is implementation-defined for our
    purpose: the version validated on-device (brew, 2026-10) PREPENDS the
    new entry (shim lands in front of libc — already correct), but append
    semantics would be wrong, so the result is verified and repaired:
      A. prepend-semantics repair: remove + re-add the shim, which hoists
         it to the front (this is what current patchelf needs, if anything);
      B. append-semantics repair: remove + re-add libc.so, which pushes
         libc behind the shim.
    The postcondition is checked after every step; only relative order of
    shim vs libc matters (the shim exports just connect). Idempotent: a
    re-run over an already-ordered lib verifies true immediately.
    Plain shims export nothing and take the plain add path.
    """
    _add_needed(path, tool, SHIM_NAME)
    if not hook:
        return

    def ordered() -> bool:
        needed = _dt_needed(path, tool)
        return "libc.so" not in needed or needed.index(SHIM_NAME) < needed.index("libc.so")

    if ordered():
        return
    _remove_needed(path, tool, SHIM_NAME)
    _add_needed(path, tool, SHIM_NAME)
    if ordered():
        return
    _remove_needed(path, tool, "libc.so")
    _add_needed(path, tool, "libc.so")
    if not ordered():
        raise RuntimeError(
            f"DT_NEEDED order: {SHIM_NAME} must precede libc.so for a "
            f"connect-hook build, got {_dt_needed(path, tool)} on {path}"
        )


def repack_apk(
    apk: str | Path,
    shim: str | Path,
    out: str | Path,
    *,
    also_patch: list[str] = (),
    patchelf_bin: str = "patchelf",
    patterns_dir: str | Path | None = None,
    redirect: str = "env",
) -> RepackReport:
    """Rewrite `apk` with the shim injected and trust patches applied.

    The output zip is NOT aligned or signed — pipe it through zipalign +
    apksigner (scripts/repack_apk.py does). All rewritten native libs are
    re-stored uncompressed: valid whether the manifest says
    extractNativeLibs true or false, and required for page-aligned direct
    loading on the false side.

    `also_patch`: zip paths (or bare basenames) to shim even though they lack
    the env-proxy markers — for false negatives (marker string merged away by
    LTO) and diagnostic builds ("does the shim load at all in this app?").

    `patterns_dir`: trust pattern DB (patterns/). None disables trust
    patching entirely (shim-only repack); a rustls lib that HAS no matching
    DB entry is reported in trust_skipped — loudly, never silently.

    `redirect`: "env" (default, M1 only) or "all" (M1 + M2.5: also shim
    rustls libs with no env marker via the connect hook — requires the shim
    to be a hook build, enforced, since a plain shim would inject DT_NEEDED
    that redirects nothing for exactly those libs).
    """
    if redirect not in ("env", "all"):
        raise ValueError(f"redirect must be 'env' or 'all', got {redirect!r}")
    apk, shim, out = Path(apk), Path(shim), Path(out)
    shim_data = shim.read_bytes()
    hook = shim_is_hook(shim_data)
    if redirect == "all" and not hook:
        raise ValueError(
            "redirect='all' needs a connect-hook shim (build with "
            "shim/build.sh --hook-connect); this librerust.so has no hook "
            f"marker ({CONNECT_HOOK_MARKER.decode()})"
        )
    trust_entries = trust.load_patterns(patterns_dir) if patterns_dir else None

    # patchelf is the only non-Python step; keep it injectable so tests can
    # exercise the zip logic without the tool (or an arm64 toolchain).
    def patch(path: Path) -> None:
        _patch_needed(path, patchelf_bin, hook)

    with zipfile.ZipFile(apk) as zin:
        targets: dict[str, bytes] = {}  # zip path -> shim-target bytes
        trust_only: dict[str, bytes] = {}  # zip path -> trust-patched, no shim
        hook_targets: list[str] = []  # shimmed via the rustls-no-env rule only
        abis: set[str] = set()
        inspected: list[str] = []
        trust_patched: list[dict] = []
        trust_skipped: list[dict] = []
        existing_shims: set[str] = set()  # lib/<abi>/librerust.so already in the APK
        forced = {
            n if "/" in n else f"lib/*/{n}" for n in also_patch
        }
        for info in zin.infolist():
            m = _LIB_ENTRY.fullmatch(info.filename)
            if not m:
                continue
            abi, fname = m.groups()
            inspected.append(info.filename)
            if fname == SHIM_NAME:
                existing_shims.add(info.filename)
                continue  # already shimmed APK — keep the entry as-is below
            data = zin.read(info.filename)
            changed = False

            # Fingerprint once for both consumers (trust selection and the
            # redirect=all candidate rule).
            fp = None
            if trust_entries is not None or redirect == "all":
                fp = fingerprint.fingerprint_bytes(data)
            is_rustls = bool(fp) and (
                fp["markers"].get("rustls_error_strings")
                or any(c == "rustls" for c, _ in fp["crates"])
            )

            # Trust (T1): keyed on the lib's own fingerprint, independent of
            # env-proxy presence — libfjs-style stacks get patched here too.
            if trust_entries is not None and is_rustls:
                analyzed = fingerprint.analyze(fp)
                entry = trust.select_pattern(
                    trust_entries,
                    fp["crates"],
                    trust.ABI_ARCH.get(abi, abi),
                    analyzed.get("tls_stack"),
                )
                if entry is None:
                    trust_skipped.append({
                        "lib": info.filename,
                        "reason": "rustls present, no pattern DB entry for this fingerprint",
                    })
                else:
                    data, off, already = trust.apply_trust(data, entry)
                    trust_patched.append({
                        "lib": info.filename,
                        "pattern": entry.name,
                        "db_file": entry.db_file,
                        "file_offset": hex(off),
                        "already_applied": already,
                    })
                    if not already:
                        changed = True

            forced_hit = any(
                re.fullmatch(pat.replace("*", "[^/]*"), info.filename)
                for pat in forced
            )
            env_hit = has_env_proxy(data)
            hook_hit = redirect == "all" and is_rustls and not env_hit and not forced_hit
            if env_hit or forced_hit or hook_hit:
                if hook_hit:
                    hook_targets.append(info.filename)
                targets[info.filename] = data
                abis.add(abi)
            elif changed:
                trust_only[info.filename] = data

        with tempfile.TemporaryDirectory(prefix="rerust-repack-") as td:
            work = Path(td)
            # Materialize every rewritten lib (shim targets + trust-only) so
            # patchelf works on real files; the zip is rebuilt from these.
            staged: dict[str, Path] = {}
            for name, data in {**targets, **trust_only}.items():
                dst = work / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(data)
                staged[name] = dst
            for abi in abis:
                shim_dst = work / "shim" / abi / SHIM_NAME
                shim_dst.parent.mkdir(parents=True, exist_ok=True)
                shim_dst.write_bytes(shim_data)

            for name, path in staged.items():
                if name in targets:
                    patch(path)

            out.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(out, "w") as zout:
                zout.comment = zin.comment
                for info in zin.infolist():
                    name = info.filename
                    if _SIG_ENTRY.match(name):
                        continue
                    if name in staged:
                        zi = zipfile.ZipInfo(name, date_time=info.date_time)
                        zi.compress_type = zipfile.ZIP_STORED
                        zi.create_system = info.create_system
                        zi.external_attr = info.external_attr  # keep file mode
                        zout.writestr(zi, staged[name].read_bytes())
                    else:
                        # writestr(ZipInfo, ...) reuses the original
                        # compress_type/date/attrs — entries pass through
                        # byte-identical in content, same method.
                        zout.writestr(info, zin.read(name))
                for abi in sorted(abis):
                    entry = f"lib/{abi}/{SHIM_NAME}"
                    if entry in existing_shims:
                        continue  # second pass over a shimmed APK — never duplicate
                    zi = zipfile.ZipInfo(entry, date_time=info.date_time)
                    zi.compress_type = zipfile.ZIP_STORED
                    zi.create_system = 3  # Unix, so the mode bits are honored
                    zi.external_attr = 0o755 << 16
                    zout.writestr(zi, shim_data)

    return RepackReport(
        apk=str(apk),
        out=str(out),
        shim=str(shim),
        shim_sha256=hashlib.sha256(shim_data).hexdigest(),
        patched=sorted(n for n in targets if n not in hook_targets),
        shims_added=sorted(f"lib/{a}/{SHIM_NAME}" for a in abis),
        inspected=sorted(inspected),
        trust_patched=trust_patched,
        trust_skipped=trust_skipped,
        redirect=redirect,
        hook_patched=sorted(hook_targets),
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rerust-repack",
        description="Inject the env-proxy shim (+ optional trust patch) into an "
        "APK (no sign/align — see scripts/repack_apk.py for the full pipeline).",
    )
    p.add_argument("apk")
    p.add_argument("--shim", required=True, help="path to a built librerust.so")
    p.add_argument("--out", required=True)
    p.add_argument("--also-patch", action="append", default=[],
                   help="lib (name or lib/<abi>/<name> glob) to shim despite missing markers")
    p.add_argument("--redirect", choices=("env", "all"), default="env",
                   help="env: shim only env-proxy-marker libs (M1). all: also hook-shim "
                        "rustls libs with no env marker (M2.5, needs a --hook-connect shim "
                        "build) (default: env)")
    p.add_argument("--patterns", default=None,
                   help="trust pattern DB dir (default: repo patterns/ next to this package)")
    p.add_argument("--no-trust", action="store_true", help="shim only; skip trust patching")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not Path(args.shim).exists():
        print(f"error: shim not found: {args.shim}", file=sys.stderr)
        return 2
    patterns = None if args.no_trust else (args.patterns or Path(__file__).resolve().parents[2] / "patterns")
    try:
        report = repack_apk(args.apk, args.shim, args.out, also_patch=args.also_patch,
                            patterns_dir=patterns, redirect=args.redirect)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report.__dict__, indent=2))
    else:
        print(f"redirect mode: {report.redirect}")
        print(f"patched ({len(report.patched)}):")
        for n in report.patched:
            print(f"  + DT_NEEDED {SHIM_NAME}: {n}")
        for n in report.hook_patched:
            print(f"  + DT_NEEDED {SHIM_NAME} (connect-hook, rustls w/o env): {n}")
        for n in report.shims_added:
            print(f"  + added {n}")
        for t in report.trust_patched:
            state = "already" if t["already_applied"] else "patched"
            print(f"  + trust {state}: {t['lib']} @ {t['file_offset']} ({t['pattern']}, {t['db_file']})")
        for t in report.trust_skipped:
            print(f"  ! trust SKIPPED: {t['lib']} — {t['reason']}", file=sys.stderr)
        print(f"shim: {report.shim} sha256={report.shim_sha256[:16]}…")
        print(f"out:  {report.out} (not aligned/signed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
