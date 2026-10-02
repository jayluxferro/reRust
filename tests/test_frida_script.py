"""Frida emitter: fingerprint→script contract, D4 gating, real-target smoke."""

import os
from pathlib import Path

import pytest

from rerust.frida_script import build_patches, emit_script, validate_proxy
from rerust.trust import load_patterns

from fixtures import (
    FRIDA_MATCH,
    lib_with_match,
    make_lib,
    make_pattern_db,
    rust_glue_like,
)

REPO_PATTERNS = Path(__file__).resolve().parents[1] / "patterns"
TARGET_APK = os.environ.get("RERUST_TEST_APK_437") or "/nonexistent"


@pytest.fixture()
def db(tmp_path):
    return load_patterns(make_pattern_db(tmp_path / "patterns"))


class TestValidateProxy:
    def test_accepts_http(self):
        assert validate_proxy("http://10.0.2.2:8083") == "http://10.0.2.2:8083"

    def test_accepts_socks5(self):
        assert validate_proxy("socks5h://127.0.0.1:9050")

    @pytest.mark.parametrize("bad", ["", "10.0.2.2:8083", "ftp://x:1", "http://"])
    def test_rejects_garbage(self, bad):
        with pytest.raises(ValueError):
            validate_proxy(bad)


class TestBuildPatches:
    def test_match_yields_one_spec(self, db):
        data = lib_with_match()
        specs, warnings, saw_rust = build_patches({"lib/arm64-v8a/librhttp.so": data}, db)
        assert saw_rust is True
        assert warnings == []
        assert len(specs) == 1
        s = specs[0]
        # Offset must come from scanning THIS lib's bytes, not the yaml.
        site = data.find(FRIDA_MATCH)
        assert s.offset == site + 4  # + patch_offset
        assert s.orig_bytes == data[s.offset : s.offset + 4] == bytes.fromhex("12345678")
        assert s.patch_bytes == bytes.fromhex("aabbccdd")
        assert s.module == "librhttp.so"
        assert s.frida_arch == "arm64"
        assert s.pattern_name == "test-force-ok"

    def test_non_rust_lib_with_matching_bytes_is_skipped(self, db):
        # The is_rust gate comes FIRST: pattern-matching bytes in a non-Rust
        # lib must never produce a patch.
        data = make_lib(b"filler", FRIDA_MATCH)
        specs, warnings, saw_rust = build_patches({"lib/arm64-v8a/libblob.so": data}, db)
        assert specs == []
        assert saw_rust is False

    def test_non_networking_lib_is_silent(self, db):
        specs, warnings, saw_rust = build_patches(
            {"lib/arm64-v8a/libglue.so": rust_glue_like()}, db
        )
        assert specs == []
        assert saw_rust is True
        # No rustls → informational; not worth a warning.
        assert warnings == []

    def test_rustls_lib_without_matching_fingerprint_warns(self, db):
        # rustls present, but crate versions don't match the DB target.
        from fixtures import cargo_path

        data = make_lib(cargo_path("rustls", "0.23.99"), cargo_path("ring", "0.17.14"))
        specs, warnings, _ = build_patches({"lib/arm64-v8a/librhttp.so": data}, db)
        assert specs == []
        assert any("no pattern DB entry" in w for w in warnings)

    def test_ambiguous_match_refuses_to_embed(self, db):
        data = lib_with_match() + FRIDA_MATCH + b"\x00"  # two sites
        specs, warnings, _ = build_patches({"lib/arm64-v8a/librhttp.so": data}, db)
        assert specs == []
        assert any("refusing to embed" in w and "2 sites" in w for w in warnings)

    def test_arch_mismatch_skips_pattern(self, db):
        # Same bytes, but in an armeabi-v7a lib — the aarch64 pattern must not apply.
        data = lib_with_match()
        specs, warnings, saw_rust = build_patches({"lib/armeabi-v7a/librhttp.so": data}, db)
        assert specs == []
        assert saw_rust is True
        assert any("no pattern DB entry" in w for w in warnings)

    def test_bare_lib_unknown_abi_warns(self, db):
        data = lib_with_match()
        specs, warnings, saw_rust = build_patches({"librhttp.so": data}, db)
        assert specs == []
        assert saw_rust is True
        assert any("ABI unknown" in w for w in warnings)


class TestEmitScript:
    @pytest.fixture()
    def built(self, db):
        data = lib_with_match()
        specs, warnings, _ = build_patches({"lib/arm64-v8a/librhttp.so": data}, db)
        return emit_script("app.apk", "http://10.0.2.2:8083", specs, warnings), specs, data

    def test_env_hook_content(self, built):
        js, _, _ = built
        for needle in (
            "getenv",
            '"HTTP_PROXY"',
            "k.toLowerCase()",  # lowercase variants covered
            "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http://10.0.2.2:8083",
            "SPAWN MODE REQUIRED",
        ):
            assert needle in js, needle

    def test_patch_content(self, built):
        js, specs, data = built
        s = specs[0]
        assert f"offset: 0x{s.offset:x}" in js
        assert 'arch: "arm64"' in js
        assert "Memory.patchCode" in js
        # tri-state seatbelt: orig + patch arrays both embedded
        assert str(list(s.orig_bytes)) in js
        assert str(list(s.patch_bytes)) in js
        assert "already applied" in js
        assert "differ from the recorded original" in js
        # provenance in the JS
        assert s.db_file in js and s.source_sha256 in js

    def test_observer_and_bootstrap(self, built):
        js, _, _ = built
        assert "installConnectObserver" in js
        assert "[reRust]" in js
        assert "family === 2" in js and "family === 10" in js  # AF_INET / AF_INET6
        assert "Process.findModuleByName" in js
        assert "android_dlopen_ext" in js

    def test_stable_frida_core_only(self, built):
        js, _, _ = built
        # The agent must not require frida beyond the stable core.
        for forbidden in ("ApiResolver", "Stalker", "Java.use", "send("):
            assert forbidden not in js

    def test_no_patches_warns_in_script(self):
        specs, warnings, _ = build_patches({}, [])
        js = emit_script("app.apk", "http://10.0.2.2:8083", specs, warnings)
        assert "PATCHES = [" in js
        assert "env+observe only" in js  # the required in-script warning
        assert "Memory.patchCode" in js  # code present but unreachable w/ 0 patches

    def test_warnings_surface_in_header_and_runtime(self, db):
        data = lib_with_match() + FRIDA_MATCH + b"\x00"
        specs, warnings, _ = build_patches({"lib/arm64-v8a/librhttp.so": data}, db)
        js = emit_script("app.apk", "http://10.0.2.2:8083", specs, warnings)
        assert "refusing to embed" in js          # header comment
        assert "SETUP_WARNINGS" in js             # runtime echo
        assert "refusing to embed" in js


class TestRealTarget:
    """Mission smoke: the real APK + real pattern DB must embed the 0.23.37
    patch at 0x309a1c. Skipped when either is not on this machine."""

    @pytest.fixture(scope="class")
    def built(self):
        from rerust.apk_inspect import read_native_libs

        libs = read_native_libs(TARGET_APK)
        entries = load_patterns(REPO_PATTERNS)
        return build_patches(libs, entries)

    @pytest.mark.skipif(
        not os.path.exists(TARGET_APK) or not REPO_PATTERNS.is_dir(),
        reason="target APK or patterns/ not available",
    )
    def test_embeds_rustls_patch_at_expected_offset(self, built):
        specs, warnings, saw_rust = built
        assert saw_rust is True
        assert warnings == [], warnings
        s = [x for x in specs if x.module == "librhttp.so"]
        assert len(s) == 1
        assert s[0].offset == 0x309A1C
        assert s[0].frida_arch == "arm64"
        assert s[0].patch_bytes == bytes.fromhex("c9028052090100391f0500f91f0900f9c0035fd6")
        # seatbelt bytes = the ORIGINAL 20 bytes at the patch site
        assert len(s[0].orig_bytes) == 20

    @pytest.mark.skipif(
        not os.path.exists(TARGET_APK) or not REPO_PATTERNS.is_dir(),
        reason="target APK or patterns/ not available",
    )
    def test_script_contains_expected_literals(self, built):
        specs, warnings, _ = built
        js = emit_script("some_app_v8a.apk", "http://127.0.0.1:8083", specs, warnings)
        assert "0x309a1c" in js
        assert '"librhttp.so"' in js
        assert "server-cert-verify-force-ok" in js
        assert "http://127.0.0.1:8083" in js
