"""APK walking, lib selection, schema stability — plus the real-target
integration test (skipped when the APK is not on this machine)."""

import os

import pytest

from rerust.apk_inspect import inspect_apk, iter_native_libs

from fixtures import (
    cargo_path,
    librhttp_like,
    make_apk,
    make_lib,
    rust_glue_like,
)

# Exact key list is part of the schema contract (order included).
LIB_KEYS = [
    "is_rust",
    "crates",
    "markers",
    "tls_stack",
    "trust_flavor",
    "http3",
    "env_proxy",
    "relevance",
    "notes",
]


class TestLibSelection:
    def test_native_lib_path_matching(self):
        assert iter_native_libs(
            [
                "lib/arm64-v8a/librhttp.so",
                "lib/armeabi-v7a/librhttp.so",
                "assets/data.bin",
                "META-INF/MANIFEST.MF",
                "lib/arm64-v8a/",  # dir entry
                "lib/arm64-v8a/sub/libdeep.so",  # too deep
                "lib/arm64-v8a/readme.txt",  # not .so
            ]
        ) == ["lib/arm64-v8a/librhttp.so", "lib/armeabi-v7a/librhttp.so"]


class TestInspectApk:
    @pytest.fixture()
    def apk(self, tmp_path):
        path = tmp_path / "app.apk"
        make_apk(
            path,
            {
                "lib/arm64-v8a/librhttp.so": librhttp_like(),
                "lib/arm64-v8a/libglue.so": rust_glue_like(),
                "lib/arm64-v8a/libnative.so": make_lib(b"plain native, no rust"),  # excluded
                "assets/index.bin": b"\x00" * 64,
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0",
            },
        )
        return path

    def test_report_composition(self, apk):
        out = inspect_apk(apk)
        assert out["apk"] == "app.apk"
        assert set(out["libs"]) == {"lib/arm64-v8a/librhttp.so", "lib/arm64-v8a/libglue.so"}

    def test_schema_is_exact(self, apk):
        out = inspect_apk(apk)
        lib = out["libs"]["lib/arm64-v8a/librhttp.so"]
        assert list(lib) == LIB_KEYS
        assert list(lib["markers"]) == [
            "rustls_error_strings",
            "env_proxy_support",
            "connect_tunnel",
            "socks_support",
            "reqwest",
            "hyper_util",
            "mozilla_root_anchors",
        ]

    def test_primary_and_informational_tiers(self, apk):
        libs = inspect_apk(apk)["libs"]
        http = libs["lib/arm64-v8a/librhttp.so"]
        assert http["relevance"] == "primary"
        assert http["tls_stack"] == "rustls+ring"
        assert http["trust_flavor"] == "webpki-roots"
        assert http["env_proxy"] is True
        glue = libs["lib/arm64-v8a/libglue.so"]
        assert glue["relevance"] == "informational"
        assert glue["tls_stack"] is None

    def test_apk_without_rust_yields_empty_libs(self, tmp_path):
        path = tmp_path / "plain.apk"
        make_apk(path, {"lib/arm64-v8a/libnative.so": make_lib(b"no rust here")})
        assert inspect_apk(path)["libs"] == {}

    def test_bare_so_file_input(self, tmp_path):
        so = tmp_path / "librhttp.so"
        so.write_bytes(librhttp_like())
        out = inspect_apk(so)
        assert list(out["libs"]) == ["librhttp.so"]
        assert out["libs"]["librhttp.so"]["relevance"] == "primary"


# --- real target --------------------------------------------------------------

TARGET_APK = os.environ.get("RERUST_TEST_APK_437") or "/nonexistent"

pytestmark = pytest.mark.skipif(
    not os.path.exists(TARGET_APK),
    reason=f"target APK not available: {TARGET_APK}",
)


class TestRealTarget:
    """SPEC success metric: `rerust inspect` reproduces the ground-truth
    fingerprint of the reference target unaided."""

    @pytest.fixture(scope="class")
    def libs(self):
        return inspect_apk(TARGET_APK)["libs"]

    def test_librhttp_is_primary(self, libs):
        lib = libs["lib/arm64-v8a/librhttp.so"]
        assert lib["relevance"] == "primary"

    def test_librhttp_ground_truth_crates(self, libs):
        crates = {tuple(c) for c in libs["lib/arm64-v8a/librhttp.so"]["crates"]}
        assert {("rustls", "0.23.37"), ("reqwest", "0.12.28"), ("ring", "0.17.14")} <= crates

    def test_librhttp_markers(self, libs):
        markers = libs["lib/arm64-v8a/librhttp.so"]["markers"]
        assert markers["env_proxy_support"] is True
        assert markers["mozilla_root_anchors"] is True

    def test_librhttp_trust_flavor(self, libs):
        assert libs["lib/arm64-v8a/librhttp.so"]["trust_flavor"] == "webpki-roots"

    def test_app_rust_glue_is_informational(self, libs):
        assert libs["lib/arm64-v8a/librust_lib_some_app.so"]["relevance"] == "informational"
