"""Classifier semantics: TLS stack, trust flavor, HTTP/3, relevance, notes."""

from rerust.fingerprint import analyze, classify, fingerprint_bytes

from fixtures import cargo_path, make_lib


def analyzed(*fragments: bytes, markers: dict[str, bool] | None = None) -> dict:
    data = make_lib(*fragments)
    report = fingerprint_bytes(data)
    if markers:
        report["markers"].update(markers)
    return analyze(report)


class TestTlsStack:
    def test_rustls_with_ring(self):
        a = analyzed(cargo_path("rustls", "0.23.37"), cargo_path("ring", "0.17.14"))
        assert a["tls_stack"] == "rustls+ring"

    def test_rustls_with_aws_lc(self):
        a = analyzed(cargo_path("rustls", "0.23.37"), cargo_path("aws-lc-rs", "1.14.0"))
        assert a["tls_stack"] == "rustls+aws-lc"

    def test_rustls_without_identified_backend(self):
        a = analyzed(cargo_path("rustls", "0.23.37"))
        assert a["tls_stack"] == "rustls"

    def test_rustls_via_display_strings_only(self):
        # Panic paths optimized out entirely; rustls Display strings remain.
        a = analyzed(b"invalid peer certificate: ")
        assert a["tls_stack"] == "rustls"

    def test_native_tls_via_platform_shims(self):
        a = analyzed(cargo_path("schannel", "0.1.27"))
        assert a["tls_stack"] == "native-tls"

    def test_openssl(self):
        a = analyzed(cargo_path("openssl-sys", "0.9.109"))
        assert a["tls_stack"] == "openssl"

    def test_boring(self):
        a = analyzed(cargo_path("boring-sys", "4.0.15"))
        assert a["tls_stack"] == "boring"

    def test_rquest_wins_over_rustls(self):
        # rquest bundles its own (impersonating) TLS; the more specific
        # identification must win even though rustls is also linked in.
        a = analyzed(cargo_path("rquest", "3.1.2"), cargo_path("rustls", "0.23.37"))
        assert a["tls_stack"] == "rquest"

    def test_no_tls(self):
        a = analyzed(cargo_path("tokio", "1.34.0"))
        assert a["tls_stack"] is None


class TestTrustFlavor:
    def test_native_certs(self):
        a = analyzed(cargo_path("rustls-native-certs", "0.8.1"))
        assert a["trust_flavor"] == "native-certs"

    def test_native_certs_wins_over_anchors(self):
        # Actionable answer first: system CA install works for this app even
        # if a webpki-roots fallback set is also present.
        a = analyzed(
            cargo_path("rustls-native-certs", "0.8.1"),
            b"DigiCert Global Root CA",
            b"ISRG Root X1",
        )
        assert a["trust_flavor"] == "native-certs"

    def test_webpki_roots_via_anchor_marker(self):
        # The webpki-roots crate never appears in panic paths (pure data) —
        # the Mozilla anchor set is the fingerprint.
        a = analyzed(b"ISRG Root X1", b"Certainly Root R1")
        assert a["trust_flavor"] == "webpki-roots"

    def test_webpki_roots_via_crate_name(self):
        a = analyzed(cargo_path("webpki-roots", "0.26.0"))
        assert a["trust_flavor"] == "webpki-roots"

    def test_unknown_when_rustls_but_no_evidence(self):
        a = analyzed(cargo_path("rustls", "0.23.37"))
        assert a["trust_flavor"] is None
        assert any("custom verifier" in n for n in a["notes"])


class TestHttp3AndRelevance:
    def test_http3_via_quinn_proto(self):
        a = analyzed(cargo_path("quinn-proto", "0.11.14"))
        assert a["http3"] is True

    def test_http3_via_h3(self):
        a = analyzed(cargo_path("h3", "0.0.8"))
        assert a["http3"] is True

    def test_no_http3(self):
        a = analyzed(cargo_path("hyper", "1.9.0"))
        assert a["http3"] is False

    def test_primary_needs_tls_or_env_proxy(self):
        a = analyzed(cargo_path("rustls", "0.23.37"))
        assert a["relevance"] == "primary"

    def test_informational_rust_lib(self):
        # e.g. librust_lib_some_app.so — Rust, but not a networking core.
        a = analyzed(cargo_path("flutter_rust_bridge", "2.12.0"))
        assert a["relevance"] == "informational"
        # Interception advice would be noise on a non-networking lib.
        assert a["notes"] == ["no TLS/proxy markers — not a networking core (informational)"]


class TestNotes:
    def test_m1_shim_recommended_when_env_proxy(self):
        a = analyzed(
            cargo_path("rustls", "0.23.37"),
            b"ALL_PROXY",
            markers={"env_proxy_support": True},
        )
        assert any("M1 shim" in n for n in a["notes"])

    def test_m3_fallback_when_no_plumbing(self):
        a = analyzed(cargo_path("rustls", "0.23.37"))
        assert any("M3 transparent redirect" in n for n in a["notes"])

    def test_webpki_roots_note_names_patch_modes(self):
        a = analyzed(cargo_path("rustls", "0.23.37"), b"ISRG Root X1", b"Certainly Root E1")
        assert any("T1 verify-branch" in n and "T2 anchor-swap" in n for n in a["notes"])

    def test_classify_accepts_raw_fingerprint(self):
        report = fingerprint_bytes(make_lib(cargo_path("rustls", "0.23.37"), b"ALL_PROXY"))
        notes = classify(report)
        assert notes == analyze(report)["notes"]
