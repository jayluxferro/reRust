"""Real-target regression for the 4.4.6 corpus (libfjs + librhttp).

Same DB <-> binary contract as test_repack.py's 4.3.7 test, extended to the
two 4.4.6 stacks: the DB entry selected by the classified fingerprint must
apply at exactly the derived offset with exactly the stub bytes, and a second
application must be recognized as already-applied (D4 idempotence).

The binaries are extracted from the v8a APK; its arm64 libs are
byte-identical to the universal APK's (sha256-checked 2026-10-02), so either
source works. Offsets and derivations: patterns/rustls-0.23.38_aarch64_ring.yaml
and patterns/rustls-0.23.40_aarch64_awslc.yaml.
"""

import zipfile
from pathlib import Path

import pytest

from rerust.trust import (
    apply_trust,
    load_patterns,
    select_pattern,
)

REPO = Path(__file__).resolve().parents[1]
import os
import pathlib
APK_446 = pathlib.Path(os.environ.get("RERUST_TEST_APK_446") or "/nonexistent")

# Fingerprint tuples exactly as `rerust classify` reports them for these libs.
LIBFJS_CRATES = [
    ("aws-lc-rs", "1.17.0"),
    ("hyper", "1.9.0"),
    ("hyper-rustls", "0.27.9"),
    ("hyper-util", "0.1.20"),
    ("ring", "0.17.14"),
    ("rustls", "0.23.38"),
    ("rustls-pki-types", "1.14.0"),
    ("rustls-webpki", "0.103.13"),
    ("tokio-rustls", "0.26.4"),
]
LIBRHTTP_CRATES = [
    ("aws-lc-rs", "1.17.0"),
    ("hyper", "1.10.1"),
    ("hyper-rustls", "0.27.9"),
    ("hyper-util", "0.1.20"),
    ("reqwest", "0.13.4"),
    ("rustls", "0.23.40"),
    ("rustls-pki-types", "1.14.1"),
    ("rustls-platform-verifier", "0.7.0"),
    ("rustls-webpki", "0.103.13"),
    ("tokio-rustls", "0.26.4"),
]

# The 20-byte force-Ok stub with 4.4.6's Ok tag 0xFF (each binary's tag was
# re-derived from its OWN dispatcher cmps — see the yamls' ok_tag_convention).
STUB_0xFF = bytes.fromhex("e91f8052090100391f0500f91f0900f9c0035fd6")

# The librhttp DB entry patches the FOURTH verifier (0x3fe558) — the live
# rejector per bench falsification: bench 1 (webpki patch) and bench 2
# (platform patch) each still produced `tlsv1 alert unknown ca`, so the DB
# entry moved to the only remaining unpatched vs_cert. The two parked
# windows (census A webpki, census C platform) must stay byte-identical
# after the apply — the pipeline is one-patch-per-lib by design, and these
# assertions pin that no swap quietly kept an old site.
WEBPKI_SITE_PARKED = 0x360868
PLATFORM_SITE_PARKED = 0x407C88


@pytest.fixture(scope="module")
def patterns():
    return load_patterns(REPO / "patterns")


def _lib_from_apk(member: str) -> bytes:
    with zipfile.ZipFile(APK_446) as z:
        return z.read(member)


@pytest.mark.skipif(not APK_446.exists(), reason="set RERUST_TEST_APK_446 to run")
@pytest.mark.parametrize(
    ("member", "crates", "tls_stack", "offset"),
    [
        ("lib/arm64-v8a/libfjs.so", LIBFJS_CRATES, "rustls+ring", 0x64B5A8),
        ("lib/arm64-v8a/librhttp.so", LIBRHTTP_CRATES, "rustls+aws-lc", 0x3FE558),
    ],
)
def test_repo_pattern_hits_known_offset_on_real_binary(
    patterns, member, crates, tls_stack, offset
):
    data = _lib_from_apk(member)
    e = select_pattern(patterns, crates, "aarch64", tls_stack)
    assert e is not None, f"repo DB entry not selected for {member} fingerprint"
    out, off, already = apply_trust(data, e)
    assert already is False
    assert off == offset  # derivations in the entry yamls
    assert out[offset : offset + len(STUB_0xFF)] == STUB_0xFF
    # second application must recognize the patch (count==1 idempotence)
    out2, _, already2 = apply_trust(out, e)
    assert already2 is True and out2 == out
    if member.endswith("librhttp.so"):
        # Both parked verifier windows (census A webpki @0x360868, census C
        # platform @0x407c88) must be untouched: the DB entry patches
        # exactly one site, and neither bench falsification (benches 1-2)
        # left a stale stub behind. Pristine-vs-patched comparison, plus a
        # not-the-stub check (a stale patch would pass self-comparison).
        for parked in (WEBPKI_SITE_PARKED, PLATFORM_SITE_PARKED):
            window = slice(parked, parked + len(STUB_0xFF))
            assert out[window] == data[window], hex(parked)
            assert out[window] != STUB_0xFF, hex(parked)


def test_446_stacks_do_not_cross_select(patterns):
    """Each stack's fingerprint must not select the other stack's entry —
    the 0.23.37 lesson (windows are version+codegen specific) enforced at
    the selection layer, not just the matcher layer."""
    assert (
        select_pattern(patterns, LIBFJS_CRATES, "aarch64", "rustls+aws-lc") is None
    )
    assert select_pattern(patterns, LIBRHTTP_CRATES, "aarch64", "rustls+ring") is None
    # and the 0.23.37 entry must not fire for either 4.4.6 stack
    assert select_pattern(patterns, LIBFJS_CRATES, "aarch64", "rustls+ring") is not None
    e = select_pattern(patterns, LIBRHTTP_CRATES, "aarch64", "rustls+aws-lc")
    assert e is not None and e.version == "0.23.40"
