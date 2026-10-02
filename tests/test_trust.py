"""trust.py — DB selection, wildcard matcher semantics, D4 enforcement."""

import os
import zipfile
from pathlib import Path

import pytest

from rerust.trust import (
    PatternAmbiguous,
    PatternEntry,
    PatternNotFound,
    apply_trust,
    find_sites,
    load_patterns,
    pattern_regex,
    select_pattern,
)

PATTERN_YAML = """
target:
  crate: rustls
  version: 0.23.37
  arch: aarch64
  extras:
    crypto: ring
derived_from:
  binary_sha256: "deadbeef"
patches:
  - name: test-force-ok
    match: "fd 7b ?? a9 f? 03 00 91"
    patch_offset: 4
    patch_bytes: "c0 03 5f d6"
"""

REAL_APK = os.environ.get("RERUST_TEST_APK_437") or "/nonexistent"
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture()
def db(tmp_path):
    (tmp_path / "rustls-0.23.37_aarch64.yaml").write_text(PATTERN_YAML)
    return tmp_path


# --- selection is fingerprint-gated --------------------------------------------


def test_load_and_select(db):
    entries = load_patterns(db)
    assert len(entries) == 1 and entries[0].name == "test-force-ok"
    e = select_pattern(
        entries, [("rustls", "0.23.37"), ("ring", "0.17.14")], "aarch64", "rustls+ring"
    )
    assert e is entries[0]


def test_select_version_mismatch(db):
    entries = load_patterns(db)
    assert select_pattern(entries, [("rustls", "0.23.38")], "aarch64", "rustls+ring") is None


def test_select_crypto_mismatch(db):
    entries = load_patterns(db)
    assert select_pattern(entries, [("rustls", "0.23.37")], "aarch64", "rustls+aws-lc") is None


def test_select_arch_mismatch(db):
    entries = load_patterns(db)
    assert select_pattern(entries, [("rustls", "0.23.37")], "x86_64", "rustls+ring") is None


# --- matcher semantics ---------------------------------------------------------


def test_nibble_wildcards():
    rx = pattern_regex("fd 7b ?? a9 f? 03")
    assert rx.search(b"\xfd\x7b\x00\xa9\xf3\x03")
    assert rx.search(b"\xfd\x7b\xff\xa9\xfa\x03")
    assert not rx.search(b"\xfd\x7b\x00\xa9\x08\x03")  # f? pins the high nibble
    assert not rx.search(b"\xfd\x7c\x00\xa9\xf1\x03")


def test_wildcard_matches_all_bytes():
    # '??' must match 0x0a/0x0d too — no '.' anywhere in our classes
    assert pattern_regex("?? ??").search(b"\n\r")


def test_overlapping_sites_counted():
    assert find_sites(bytes.fromhex("fdfdfdfd"), "fd fd fd") == [0, 1]


def test_bad_token_rejected():
    with pytest.raises(ValueError):
        pattern_regex("fd zz")


# --- application + D4 enforcement ---------------------------------------------


def _entry(**kw):
    base = dict(
        db_file="t.yaml", crate="rustls", version="0.23.37", arch="aarch64",
        extras={}, name="p", match_text="aa bb ?? dd", patch_offset=2,
        patch_bytes=bytes([0x99, 0x88]), source_sha256="src",
    )
    base.update(kw)
    return PatternEntry(**base)


def test_apply_unique():
    data = bytes([1, 2, 0xAA, 0xBB, 0x00, 0xDD, 5, 6])
    out, off, already = apply_trust(data, _entry())
    assert off == 2 and already is False
    assert out == bytes([1, 2, 0xAA, 0xBB, 0x99, 0x88, 5, 6])


def test_apply_ambiguous_refuses():
    data = bytes([0xAA, 0xBB, 0x00, 0xDD]) * 2
    with pytest.raises(PatternAmbiguous):
        apply_trust(data, _entry())


def test_apply_not_found_refuses():
    with pytest.raises(PatternNotFound):
        apply_trust(b"\x00" * 64, _entry())


def test_apply_offset0_is_idempotent_after_pattern_destroyed():
    # patch_offset 0 overwrites the match itself: second pass finds 0 sites,
    # and must recognize the single patch-bytes occurrence as already-applied
    e = _entry(match_text="aa bb cc dd", patch_offset=0, patch_bytes=bytes([0x99, 0x88]))
    data = bytes([1, 0xAA, 0xBB, 0xCC, 0xDD, 2])
    out, off, already = apply_trust(data, e)
    assert already is False and out[1:3] == b"\x99\x88"
    out2, off2, already2 = apply_trust(out, e)
    assert already2 is True and out2 == out


# --- real-target regression (DB <-> binary contract) ---------------------------


@pytest.mark.skipif(not Path(REAL_APK).exists(), reason="target apk not present")
def test_repo_pattern_hits_known_offset_on_real_binary():
    with zipfile.ZipFile(REAL_APK) as z:
        data = z.read("lib/arm64-v8a/librhttp.so")
    entries = load_patterns(REPO / "patterns")
    e = select_pattern(
        entries,
        [("rustls", "0.23.37"), ("rustls-webpki", "0.103.10"),
         ("rustls-pki-types", "1.14.0"), ("reqwest", "0.12.28"), ("hyper", "1.9.0")],
        "aarch64", "rustls+ring",
    )
    assert e is not None, "repo DB entry not selected for the 4.3.7 fingerprint"
    out, off, already = apply_trust(data, e)
    assert already is False
    assert off == 0x309A1C  # derivation: docs/research/rustls-trust-patch-derivation.md (file-verified)
    # v2 stub (2026-02-14): mov w9,#0x16 ; strb w9,[x8] ; str xzr,[x8,#8] ;
    # str xzr,[x8,#0x10] ; ret — Ok tag 0x16 read from the target's own
    # dispatcher (cmp w8,#0x16 at 0x335038); v1's tag-0 write was
    # runtime-rejected. 20 bytes so the sequence is unique in the binary
    # (12-byte form collides with NoVerifier's folded bodies at 0x2dc9f8).
    assert out[0x309A1C : 0x309A1C + 20] == bytes.fromhex(
        "c9028052090100391f0500f91f0900f9c0035fd6"
    )
