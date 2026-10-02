"""reRust CLI.

`inspect` is end-to-end (stdlib only); `patch` delegates to the repack
pipeline (scripts/repack_apk.py — needs a repo checkout plus Android SDK/NDK);
`frida` emits a runtime Frida agent (SPEC M2, spawn mode).

The `inspect --json` document schema is documented (and stable within 0.x) on
:mod:`rerust.apk_inspect`; the generated Frida agent's contract is documented
on :mod:`rerust.frida_script`.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

from . import assets, frida_script, pipeline, trust
from .apk_inspect import inspect_apk, read_native_libs

# Exit codes for `inspect`: 0 = report produced; 1 = ran fine but no Rust
# libraries found (not a reRust target); 2 = input error (missing file,
# not an APK/zip).


def cmd_inspect(args: argparse.Namespace) -> int:
    apk = Path(args.apk)
    if not apk.exists():
        print(f"error: {apk} not found", file=sys.stderr)
        return 2
    try:
        out = inspect_apk(apk)
    except (zipfile.BadZipFile, ValueError):
        print(f"error: {apk} is not an APK/zip or a native library", file=sys.stderr)
        return 2
    if not out["libs"]:
        print("no Rust libraries found — not a reRust target")
        return 1
    if args.json:
        print(json.dumps(out, indent=2))
        return 0
    for name, report in out["libs"].items():
        print(f"\n== {name}  [{report['relevance']}]")
        if report["crates"]:
            print("  crates:")
            for cname, ver in report["crates"]:
                print(f"    {cname} {ver}")
        print("  markers:", ", ".join(k for k, v in report["markers"].items() if v) or "none")
        for note in report["notes"]:
            print(f"  → {note}")
    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    """Repack with the env-proxy shim + rustls trust patch (SPEC M1 + T1).

    Runs rerust.pipeline in-process — works from a repo checkout AND an
    installed wheel (shim sources and the pattern DB resolve via rerust.assets).
    """
    if not args.out:
        args.out = str(Path(args.apk).with_suffix("")) + ".rerust.apk"
    return pipeline.run_patch(args)


def cmd_frida(args: argparse.Namespace) -> int:
    """Emit the Frida agent (SPEC M2): env-proxy hook + trust patch + observer.

    Script to stdout (pipe into `frida -f <pkg> -l -`), or --out to save it.
    --list is a dry run showing what would be embedded. Exit codes as for
    `inspect`.
    """
    target = Path(args.target)
    if not target.exists():
        print(f"error: {target} not found", file=sys.stderr)
        return 2
    try:
        proxy = frida_script.validate_proxy(args.proxy)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        libs = read_native_libs(target)
    except (zipfile.BadZipFile, ValueError, OSError):
        print(f"error: {target} is not an APK/zip or a native library", file=sys.stderr)
        return 2

    db = Path(args.patterns) if args.patterns else assets.patterns_dir()
    if db is not None and db.is_dir():
        try:
            entries = trust.load_patterns(db)
        except Exception as e:  # malformed yaml must not kill the emitter
            print(f"error: pattern DB unreadable ({db}): {e}", file=sys.stderr)
            return 2
    else:
        entries = []
        print("warning: no pattern DB found (repo or packaged) — agent will be "
              "env+observe only", file=sys.stderr)

    specs, warnings, saw_rust = frida_script.build_patches(libs, entries)
    if not saw_rust:
        print("no Rust libraries found — not a reRust target")
        return 1

    if args.list_mode:
        print(f"target: {target}")
        print(f"proxy:  {proxy}")
        if specs:
            print("trust patches to embed:")
            for s in specs:
                print(f"  {s.lib_path} -> {s.module}+0x{s.offset:x}  {s.pattern_name}"
                      f" ({s.db_file}, derived on sha256 {s.source_sha256[:12]}…)")
        else:
            print("trust patches to embed: none — agent will be env+observe only")
        for w in warnings:
            print(f"  ! {w}")
        return 0

    script = frida_script.emit_script(target.name, proxy, specs, warnings)
    if args.out:
        Path(args.out).write_text(script)
        print(f"agent written to {args.out} ({len(specs)} patch(es), {len(warnings)} warning(s))",
              file=sys.stderr)
    else:
        sys.stdout.write(script)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rerust", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("inspect", help="fingerprint the Rust core of an APK (or a bare .so)")
    pi.add_argument("apk")
    pi.add_argument("--json", action="store_true", help="emit the machine-readable document (schema: rerust.apk_inspect)")
    pi.set_defaults(fn=cmd_inspect)
    pp = sub.add_parser("patch", help="repackage with the env-proxy shim + rustls trust patch (M1 + T1)")
    pipeline.add_patch_args(pp)
    pp.set_defaults(fn=cmd_patch)
    pf = sub.add_parser("frida", help="emit a Frida runtime agent (env-proxy + trust patch + observer)")
    pf.add_argument("target", help="APK/zip or native lib to fingerprint")
    pf.add_argument("--proxy", required=True, help="proxy URL injected via getenv, e.g. http://10.0.2.2:8083")
    pf.add_argument("--out", help="write the agent script here (default: stdout)")
    pf.add_argument("--list", dest="list_mode", action="store_true", help="dry run: show what would be embedded")
    pf.add_argument("--patterns", default=None,
                    help="trust pattern DB dir (default: repo patterns/ next to this package)")
    pf.set_defaults(fn=cmd_frida)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
