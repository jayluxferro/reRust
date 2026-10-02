"""Tests for rerust.repack_ipa — zip + Mach-O surgery only, no codesign.

sign=False everywhere (an unsigned repack will not launch anywhere, but the
launch story is the simulator e2e's job — docs/lab-setup.md §iOS); what we're
testing here is target selection (main executable + Frameworks/PlugIns scope,
engine skip), per-slice trust gating on the arm64-ios arch spelling, fat-aware
LC_LOAD_DYLIB injection, idempotence, and the CLI dispatch.
"""

import os
import plistlib
import zipfile
from pathlib import Path

import pytest

from macho_fixtures import (
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    rustls_slice_strings,
    make_fat,
    make_thin,
)

from rerust import assets, cli, macho, trust
from rerust.repack_ipa import SHIM_INSTALL_NAME, SHIM_NAME, has_env_proxy, repack_ipa

SHIM_BYTES = b"fake-librerust-dylib-bytes"
PLIST = plistlib.dumps(
    {"CFBundleExecutable": "Farm", "CFBundleIdentifier": "com.example.farm"},
    fmt=plistlib.FMT_BINARY,
)
# A code-like needle IN FRONT of the fingerprint strings: the real pattern
# window is __text instructions, never the string pool — if the needle were
# inside a rustls path string, the stub would overwrite the version substring
# and the second repack's fingerprint would (correctly) stop selecting the
# entry. Keeping the strings intact is what makes the already-applied path
# (0 window hits + exactly one stub) the exercised one.
MATCH_BYTES = bytes.fromhex("aa55aa55deadbeefaa55aa55cafebabef00d")
MATCH = " ".join(f"{b:02x}" for b in MATCH_BYTES)
CONTENT = MATCH_BYTES + b"\x00" * 48 + rustls_slice_strings()
# The real 0.23.45/arm64-ios stub (assembler-verified; see the DB entry) —
# used verbatim so the idempotence story is the shipped one.
STUB = "e9 1f 80 52 09 01 00 39 1f 05 00 f9 1f 09 00 f9 c0 03 5f d6"
STUB_BYTES = bytes.fromhex(STUB.replace(" ", ""))


def make_ipa(tmp_path, *, name="in.ipa", app="Farm.app", exe="Farm", main=None,
             entries=(), plist=PLIST):
    plist = (plistlib.dumps({"CFBundleExecutable": exe}, fmt=plistlib.FMT_BINARY)
             if plist == "auto" else plist)
    ipa = tmp_path / name
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr(f"Payload/{app}/{exe}", make_thin(CONTENT)
                   if main is None else main)
        z.writestr(f"Payload/{app}/Info.plist", plist)
        for n, data in entries:
            z.writestr(n, data)
    return ipa


def make_shim(tmp_path, data=SHIM_BYTES, name="librerust.dylib"):
    shim = tmp_path / name
    shim.write_bytes(data)
    return shim


def make_patterns(tmp_path, *, version="0.23.45", arch="arm64-ios", match=MATCH,
                  patch_offset=0):
    """A one-entry DB matched by the fixture's fingerprint — the shipped DB
    needs the full extras (webpki/pki-types/hyper versions) that the synthetic
    fixture deliberately doesn't carry."""
    db = tmp_path / "patterns"
    db.mkdir()
    (db / f"rustls-{version}_{arch}.yaml").write_text(f"""
target:
  crate: rustls
  version: "{version}"
  arch: "{arch}"
  extras: {{}}
derived_from:
  binary_sha256: "{"0" * 64}"
patches:
  - name: test-force-ok
    what: unit-test stub
    match: >-
      {match}
    patch_offset: {patch_offset}
    patch_bytes: "{STUB}"
""")
    return db


def test_has_env_proxy_needs_all_proxy():
    assert has_env_proxy(b"junk" + b"ALL_PROXY" + b"junk")
    assert not has_env_proxy(b"HTTPS_PROXY alone is a decoy")
    assert not has_env_proxy(b"")


def test_repack_injects_lc_load_dylib_and_preserves(tmp_path):
    ipa, shim, out = make_ipa(tmp_path), make_shim(tmp_path), tmp_path / "out.ipa"
    report = repack_ipa(ipa, shim, out, sign=False)

    assert report.app_dir == "Payload/Farm.app"
    assert report.patched == ["Payload/Farm.app/Farm"]
    assert report.shims_added == ["Payload/Farm.app/Frameworks/" + SHIM_NAME]
    assert report.signed is False

    with zipfile.ZipFile(out) as z:
        exe = z.read("Payload/Farm.app/Farm")
        assert macho.has_dylib(exe, 0, SHIM_INSTALL_NAME)
        assert z.read("Payload/Farm.app/Frameworks/" + SHIM_NAME) == SHIM_BYTES
        mode = (z.getinfo("Payload/Farm.app/Frameworks/" + SHIM_NAME).external_attr >> 16) & 0o777
        assert mode == 0o755
        # untouched entries pass through byte-identical
        assert z.read("Payload/Farm.app/Info.plist") == PLIST
        assert z.read("Payload/Farm.app/Farm") != make_thin(CONTENT)


def test_cf_bundle_executable_names_the_target(tmp_path):
    ipa = make_ipa(tmp_path, app="Odd.app", exe="OddMain", plist="auto")
    report = repack_ipa(ipa, make_shim(tmp_path), tmp_path / "o.ipa", sign=False)
    assert report.patched == ["Payload/Odd.app/OddMain"]


def test_trust_patch_applied_per_slice(tmp_path):
    ipa, out = make_ipa(tmp_path), tmp_path / "out.ipa"
    db = make_patterns(tmp_path)
    report = repack_ipa(ipa, make_shim(tmp_path), out, patterns_dir=db, sign=False)

    assert len(report.trust_patched) == 1
    t = report.trust_patched[0]
    assert t["lib"] == "Payload/Farm.app/Farm#arm64"
    assert t["pattern"] == "test-force-ok"
    assert t["already_applied"] is False
    assert report.trust_skipped == []
    # shim still lands (the fixture carries ALL_PROXY) — both moves in one run
    assert report.patched == ["Payload/Farm.app/Farm"]

    with zipfile.ZipFile(out) as z:
        exe = z.read("Payload/Farm.app/Farm")
    assert MATCH_BYTES not in exe                  # match window overwritten
    assert exe.count(STUB_BYTES) == 1
    assert trust.find_sites(exe, MATCH) == []      # window no longer matches
    # the stub sits exactly where the window started
    off = trust.find_sites(make_thin(CONTENT), MATCH)[0]
    assert exe[off : off + len(STUB_BYTES)] == STUB_BYTES


def test_trust_skip_is_loud_not_silent(tmp_path):
    db = make_patterns(tmp_path, version="0.23.99")  # right crate, wrong version
    report = repack_ipa(make_ipa(tmp_path), make_shim(tmp_path),
                        tmp_path / "out.ipa", patterns_dir=db, sign=False)
    assert report.trust_patched == []
    assert len(report.trust_skipped) == 1
    assert "no pattern DB entry" in report.trust_skipped[0]["reason"]
    # the shim move is unaffected by the trust skip
    assert report.patched == ["Payload/Farm.app/Farm"]


def test_repack_is_idempotent(tmp_path):
    db = make_patterns(tmp_path)
    shim = make_shim(tmp_path)
    out1, out2 = tmp_path / "one.ipa", tmp_path / "two.ipa"
    repack_ipa(make_ipa(tmp_path), shim, out1, patterns_dir=db, sign=False)
    r2 = repack_ipa(out1, shim, out2, patterns_dir=db, sign=False)

    assert r2.patched == []                       # nothing new to inject
    assert r2.shims_added == []                   # shim entry already present
    assert [t["already_applied"] for t in r2.trust_patched] == [True]
    with zipfile.ZipFile(out2) as z:
        names = z.namelist()
        assert names.count("Payload/Farm.app/Frameworks/" + SHIM_NAME) == 1
        assert z.read("Payload/Farm.app/Farm").count(STUB_BYTES) == 1


def test_also_patch_forces_markerless_framework(tmp_path):
    helper = make_thin(b"\x00" * 64, filetype=macho.MH_DYLIB)
    ipa = make_ipa(tmp_path, entries=[("Payload/Farm.app/Frameworks/Helper", helper)])
    report = repack_ipa(ipa, make_shim(tmp_path), tmp_path / "out.ipa",
                        also_patch=["Helper"], sign=False)
    assert "Payload/Farm.app/Frameworks/Helper" in report.patched
    with zipfile.ZipFile(tmp_path / "out.ipa") as z:
        assert macho.has_dylib(z.read("Payload/Farm.app/Frameworks/Helper"), 0,
                               SHIM_INSTALL_NAME)


def test_scope_stray_and_engine_never_touched(tmp_path):
    stray = make_thin(rustls_slice_strings())  # full rustls profile, wrong place
    engine = make_thin(rustls_slice_strings())  # stem Flutter → _SKIP_NAMES
    ipa = make_ipa(tmp_path, entries=[
        ("Payload/Farm.app/stray_dylib", stray),
        ("Payload/Farm.app/Frameworks/Flutter", engine),
    ])
    report = repack_ipa(ipa, make_shim(tmp_path), tmp_path / "out.ipa",
                        patterns_dir=make_patterns(tmp_path), sign=False)
    assert report.inspected == ["Payload/Farm.app/Farm"]


def test_fat_main_patched_on_arm64_x86_64_skipped_loudly(tmp_path):
    fat = make_fat([
        make_thin(CONTENT),
        make_thin(CONTENT, cputype=CPU_TYPE_X86_64),
    ])
    ipa, out = make_ipa(tmp_path, main=fat), tmp_path / "out.ipa"
    report = repack_ipa(ipa, make_shim(tmp_path), out,
                        patterns_dir=make_patterns(tmp_path), sign=False)

    # the shim lands in EVERY slice; trust hits only the arm64-ios-gated one
    assert report.patched == ["Payload/Farm.app/Farm"]
    assert len(report.trust_patched) == 1
    assert report.trust_patched[0]["lib"] == "Payload/Farm.app/Farm#arm64"
    assert report.trust_skipped == [{
        "lib": "Payload/Farm.app/Farm#x86_64",
        "reason": "rustls present, no pattern DB entry for this fingerprint",
    }]
    with zipfile.ZipFile(out) as z:
        exe = z.read("Payload/Farm.app/Farm")
    arm, x86 = macho.slices(exe)
    assert macho.has_dylib(exe[arm.offset : arm.offset + arm.size], 0, SHIM_INSTALL_NAME)
    assert macho.has_dylib(exe[x86.offset : x86.offset + x86.size], 0, SHIM_INSTALL_NAME)
    assert exe[arm.offset : arm.offset + arm.size].count(STUB_BYTES) == 1
    assert exe[x86.offset : x86.offset + x86.size].count(STUB_BYTES) == 0


def test_no_target_raises(tmp_path):
    plain = make_thin(b"\x00" * 256)  # no rustls strings, no ALL_PROXY
    ipa = make_ipa(tmp_path, main=plain)
    with pytest.raises(ValueError, match="no injection target"):
        repack_ipa(ipa, make_shim(tmp_path), tmp_path / "o.ipa", sign=False)


def test_broken_bundle_layout_raises(tmp_path):
    ipa = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr("Payload/NotAnApp/binary", make_thin())
    with pytest.raises(ValueError, match="Payload/\\*.app"):
        repack_ipa(ipa, make_shim(tmp_path), tmp_path / "o.ipa", sign=False)


def test_codesign_order_shim_patched_then_bundle(tmp_path, monkeypatch):
    """sign=True must re-sign every byte-surgered nested binary BEFORE the
    bundle (codesign seals nested code by reference), skip the main
    executable (bundle signing regenerates its CodeDirectory), and put the
    bundle last. Recorded through a fake --codesign so no real signing runs
    on synthetic Mach-O."""
    helper = make_thin(b"\x00" * 64, filetype=macho.MH_DYLIB)
    ipa = make_ipa(tmp_path, entries=[("Payload/Farm.app/Frameworks/Helper", helper)])
    log = tmp_path / "codesign.log"
    fake = tmp_path / "fake-codesign"
    fake.write_text(f"#!/bin/sh\necho \"$@\" >> '{log}'\nexit 0\n")
    fake.chmod(0o755)
    report = repack_ipa(ipa, make_shim(tmp_path), tmp_path / "out.ipa",
                        also_patch=["Helper"], sign=True, codesign_bin=str(fake))
    assert report.signed is True
    calls = log.read_text().splitlines()
    assert len(calls) == 3
    assert calls[0].endswith("Frameworks/" + SHIM_NAME)
    assert calls[1].endswith("Frameworks/Helper")
    assert calls[2].endswith("Farm.app")
    assert not any(c.endswith("/Farm") for c in calls)  # main exe: bundle-signed


# ---- CLI dispatch -----------------------------------------------------------


def test_cli_patch_ipa_dispatch(tmp_path):
    ipa, out = make_ipa(tmp_path), tmp_path / "cli.ipa"
    rc = cli.main(["patch", str(ipa), "--shim", str(make_shim(tmp_path)),
                   "--out", str(out), "--no-sign", "--no-trust"])
    assert rc == 0
    with zipfile.ZipFile(out) as z:
        assert "Payload/Farm.app/Frameworks/" + SHIM_NAME in z.namelist()
        assert macho.has_dylib(z.read("Payload/Farm.app/Farm"), 0, SHIM_INSTALL_NAME)


def test_cli_patch_bare_macho_clear_error(tmp_path, capsys):
    bare = tmp_path / "libx.dylib"
    bare.write_bytes(make_thin(b"\x00" * 64))
    rc = cli.main(["patch", str(bare), "--shim", str(make_shim(tmp_path)), "--no-sign"])
    assert rc == 2
    assert "bare Mach-O" in capsys.readouterr().err


def test_cli_patch_missing_shim_errors(tmp_path, capsys):
    rc = cli.main(["patch", str(make_ipa(tmp_path)), "--shim", str(tmp_path / "nope.dylib"),
                   "--no-sign"])
    assert rc == 2


@pytest.mark.skipif(
    not (os.environ.get("RERUST_TEST_IPA") and os.environ.get("RERUST_TEST_SHIM")),
    reason="set RERUST_TEST_IPA (an .ipa) and RERUST_TEST_SHIM (a built "
           "librerust.dylib) to run the real-binary repack",
)
def test_real_ipa_repack(tmp_path):
    """The shipped DB against a real app archive. sign=False: the e2e run
    signs through the CLI; here we assert the surgery, not the signature."""
    out = tmp_path / "real.rerust.ipa"
    report = repack_ipa(
        os.environ["RERUST_TEST_IPA"], os.environ["RERUST_TEST_SHIM"], out,
        patterns_dir=assets.patterns_dir(), sign=False,
    )
    assert report.patched, "real ipa must expose at least one env-proxy lib"
    assert report.trust_patched or report.trust_skipped, \
        "a rustls lib must be classified (patched or loudly skipped)"
    with zipfile.ZipFile(out) as z:
        assert z.read(f"{report.app_dir}/Frameworks/{SHIM_NAME}") == \
            Path(os.environ["RERUST_TEST_SHIM"]).read_bytes()
