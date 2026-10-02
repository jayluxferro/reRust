"""Regex + marker semantics on synthetic fixtures."""

from rerust.fingerprint import (
    MARKERS,
    MOZILLA_ANCHOR_SUBJECTS,
    fingerprint_bytes,
)

from fixtures import cargo_path, make_lib


def crates_of(data: bytes) -> set[tuple[str, str]]:
    return {tuple(c) for c in fingerprint_bytes(data)["crates"]}


class TestCratePath:
    def test_posix_path(self):
        data = make_lib(cargo_path("rustls", "0.23.37", "posix"))
        assert crates_of(data) == {("rustls", "0.23.37")}
        assert fingerprint_bytes(data)["is_rust"] is True

    def test_windows_path(self):
        data = make_lib(cargo_path("reqwest", "0.12.28", "windows"))
        assert crates_of(data) == {("reqwest", "0.12.28")}

    def test_both_styles_in_one_binary(self):
        # Real target: CI-built libs carry /home/runner/..., the app vendor's
        # Windows-built libs carry C:\\Users\\... — one lib can mix.
        data = make_lib(
            cargo_path("hyper", "1.9.0", "posix"),
            cargo_path("rustls", "0.23.37", "windows"),
        )
        assert crates_of(data) == {("hyper", "1.9.0"), ("rustls", "0.23.37")}

    def test_hyphenated_crate_name(self):
        # Greedy name class + backtracking must land on the LAST version, so
        # the name keeps its hyphens: hyper-rustls, not "hyper".
        data = make_lib(cargo_path("hyper-rustls", "0.27.7", "posix"))
        assert crates_of(data) == {("hyper-rustls", "0.27.7")}

    def test_prerelease_and_build_metadata_versions(self):
        data = make_lib(
            cargo_path("h3", "0.0.8", "posix"),
            cargo_path("pkg", "1.0.0-rc.1", "posix"),
            cargo_path("other", "2.3.4+build.7", "posix"),
        )
        assert crates_of(data) == {("h3", "0.0.8"), ("pkg", "1.0.0-rc.1"), ("other", "2.3.4+build.7")}

    def test_dedup_and_sort(self):
        p = cargo_path("rustls", "0.23.37", "posix")
        data = make_lib(p, p, cargo_path("base64", "0.22.1", "posix"))
        cs = sorted({tuple(c) for c in fingerprint_bytes(data)["crates"]})
        assert cs == [("base64", "0.22.1"), ("rustls", "0.23.37")]

    def test_bare_version_string_without_registry_prefix_is_ignored(self):
        # The registry-path prefix is load-bearing: apps embed plenty of
        # `name-1.2.3`-looking strings that are not crate provenance.
        data = make_lib(b"rustls-0.23.37", b"some-lib-1.2.3 changelog entry")
        assert crates_of(data) == set()
        assert fingerprint_bytes(data)["is_rust"] is False

    def test_two_component_version_is_ignored(self):
        data = make_lib(cargo_path("rustls", "0.23", "posix"))
        assert crates_of(data) == set()

    def test_no_match_on_clean_blob(self):
        report = fingerprint_bytes(b"\x7fELF" + b"\x00" * 256)
        assert report == {
            "is_rust": False,
            "crates": [],
            "markers": {k: False for k in report["markers"]},
        }

    def test_rustc_sysroot_marker_alone_is_rust(self):
        data = make_lib(b"something", rustc_marker=True)
        report = fingerprint_bytes(data)
        assert report["is_rust"] is True
        assert report["crates"] == []


class TestMarkers:
    def test_all_keys_always_present(self):
        # Schema stability: consumers rely on every key existing.
        markers = fingerprint_bytes(b"\x7fELF\x00")["markers"]
        assert set(markers) == set(MARKERS) | {"mozilla_root_anchors"}
        assert all(v is False for v in markers.values())

    def test_merged_run_satisfies_env_proxy(self):
        # LTO merges short strings into runs; the real target shows the env
        # var names as one merged run. The marker must fire on it.
        run = b"ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy"
        assert fingerprint_bytes(make_lib(run))["markers"]["env_proxy_support"] is True

    def test_each_marker_fires_on_its_own_sentence(self):
        for key, pattern in MARKERS.items():
            data = make_lib(pattern)
            assert fingerprint_bytes(data)["markers"][key] is True, key

    def test_partial_sentence_does_not_fire(self):
        data = make_lib(b"invalid peer")  # not the full rustls Display string
        assert fingerprint_bytes(data)["markers"]["rustls_error_strings"] is False

    def test_mozilla_anchors_need_two_distinct_subjects(self):
        one = make_lib(MOZILLA_ANCHOR_SUBJECTS[0])
        assert fingerprint_bytes(one)["markers"]["mozilla_root_anchors"] is False
        two = make_lib(MOZILLA_ANCHOR_SUBJECTS[0], MOZILLA_ANCHOR_SUBJECTS[1])
        assert fingerprint_bytes(two)["markers"]["mozilla_root_anchors"] is True

    def test_single_pinned_ca_does_not_trip_mozilla(self):
        # SPEC risk: app-level pinning embeds ONE CA. A lone "DigiCert Global
        # Root CA" subject must not read as a compiled-in webpki-roots set.
        data = make_lib(b"DigiCert Global Root CA", b"O=My App Pinning CA")
        assert fingerprint_bytes(data)["markers"]["mozilla_root_anchors"] is False
