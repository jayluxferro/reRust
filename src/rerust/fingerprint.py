"""Binary fingerprinting: crate extraction, string markers, classification.

## Why strings survive stripping

`strip` removes `.symtab` but leaves `.rodata` untouched, and Rust binaries keep
two string families there that are stable across rebuilds of the same crate set:

1. **Panic-location strings.** `panic!`/`#[track_caller]` bake in absolute source
   paths, usually the crates.io registry checkout — POSIX or Windows style
   depending on the builder::

       /home/runner/.cargo/registry/src/index.crates.io-<hash>/<crate>-<ver>/src/...
       C:\\Users\\<user>\\.cargo\\registry\\src\\index.crates.io-<hash>\\<crate>-<ver>\\src\\...

   These give *crate-exact* versions from a stripped binary — the version-keyed
   patch DB (patterns/, SPEC D4) hangs entirely off :data:`CRATE_PATH`.

2. **Sentence-level marker strings** (:data:`MARKERS`). Single crate words are
   unreliable: LTO merges short strings into runs, so e.g. `rustls` often only
   occurs inside a longer run. Hence whole-sentence anchors like
   `invalid peer certificate: ` (a rustls ``Display`` string) rather than
   substring guesses. Verified against the real target: see
   docs/research/librhttp-notes.md.

## Per-library analysis schema (stable)

:func:`fingerprint_bytes` returns the raw fingerprint,
:func:`analyze` adds the derived interpretation fields. ``rerust inspect --json``
embeds exactly these dicts under ``"libs"`` — the full document schema is
documented (and frozen for 0.x) on :mod:`rerust.apk_inspect`.
"""

from __future__ import annotations

import re

# --- string extraction --------------------------------------------------------

# Panic-location crate paths. Note the required `.cargo/registry/src/
# index.crates.io-<hash>/` prefix: a bare `rustls-0.23.37` string in rodata is
# NOT enough (apps legitimately embed unrelated version-looking strings), which
# is what keeps the crate list false-positive-free. Name class is greedy and
# includes `-`, so `hyper-rustls-0.27.7` backtracks to name=`hyper-rustls`,
# version=`0.27.7` (the LAST `\d+\.\d+\.\d+` wins).
CRATE_PATH = re.compile(
    rb"(?:[A-Za-z]:\\|/)[^\x00-\x1f\"']*?\.cargo[\\/]+registry[\\/]+src[\\/]+"
    rb"index\.crates\.io-[0-9a-f]{8,}[\\/]+([A-Za-z0-9_.+-]+)-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)"
)

# rustc sysroot paths (`/rustc/<commit-hash>/library/...`) — proves a Rust build
# even when no registry crate survived (e.g. std-only, or paths from the build
# cache rather than the registry).
RUST_MARKER = re.compile(rb"/rustc/[0-9a-f]{30,}/")

# Whole-binary markers. Keys are part of the JSON schema; every key is always
# present (False, not missing) so consumers can rely on the shape.
MARKERS: dict[str, bytes] = {
    "rustls_error_strings": rb"invalid peer certificate: ",
    "env_proxy_support": rb"ALL_PROXY",
    "connect_tunnel": rb"tunneling HTTPS over proxy",
    "socks_support": rb"connect_socks is only called for socks proxies",
    "reqwest": rb"reqwest::connect::",
    "hyper_util": rb"hyper_util::client::legacy",
}

# The `webpki-roots` crate itself never shows up in panic paths (pure data, no
# panics) — its Mozilla anchor *set* in .rodata is the fingerprint instead.
# Requiring >=2 DISTINCT known root subjects makes this robust: an app that
# embeds one or two pinned CAs (SPEC risk: app-level pinning) can contain a
# single "DigiCert Global Root CA" subject, but not the Mozilla spread. Also
# shields non-Rust libs that happen to bundle a cert or two from being flagged.
MOZILLA_ANCHOR_SUBJECTS: tuple[bytes, ...] = (
    rb"DigiCert Global Root CA",
    rb"DigiCert Global Root G2",
    rb"ISRG Root X1",
    rb"ISRG Root X2",
    rb"Certainly Root R1",
    rb"Certainly Root E1",
    rb"GlobalSign Root CA",
    rb"Microsoft RSA Root Certificate Authority 2017",
    rb"Microsoft ECC Root Certificate Authority 2017",
    rb"Go Daddy Root Certificate Authority",
    b"Amazon Root CA",
)
MOZILLA_ANCHOR_MIN_DISTINCT = 2


def fingerprint_bytes(data: bytes) -> dict:
    """Raw fingerprint of one binary blob (a native lib's bytes)."""
    crates = sorted({(m.group(1).decode(), m.group(2).decode()) for m in CRATE_PATH.finditer(data)})
    is_rust = bool(RUST_MARKER.search(data) or crates)
    markers = {k: bool(re.search(p, data)) for k, p in MARKERS.items()}
    markers["mozilla_root_anchors"] = (
        sum(s in data for s in MOZILLA_ANCHOR_SUBJECTS) >= MOZILLA_ANCHOR_MIN_DISTINCT
    )
    return {"is_rust": is_rust, "crates": crates, "markers": markers}


# --- classification -----------------------------------------------------------

# TLS stack flavors, most specific first. `openssl` precedes `native-tls`
# because a native-tls build over openssl still exposes `openssl-sys`, and the
# backend name is the more precise answer for the analyst.
_TLS_CRATE_SETS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("rquest", ("rquest",)),
    ("boring", ("boring", "boring-sys", "hyper-boring", "tokio-boring")),
    ("openssl", ("openssl", "openssl-sys")),
    ("native-tls", ("native-tls", "schannel", "security-framework", "security-framework-sys")),
    ("rustls", ("rustls",)),
)

_HTTP3_CRATES = {"quinn", "quinn-proto", "quinn-udp", "h3", "h3-quinn"}


def tls_stack(crates: list[tuple[str, str]], markers: dict[str, bool]) -> str | None:
    """Identify the in-process TLS stack, or None if no TLS evidence."""
    names = {n for n, _ in crates}
    stack = next((s for s, crate_names in _TLS_CRATE_SETS if names & set(crate_names)), None)
    if stack is None and markers.get("rustls_error_strings"):
        # Panic paths stripped/optimized away entirely, but rustls Display
        # strings remain — they only ship inside rustls itself.
        stack = "rustls"
    if stack == "rustls":
        backends = []
        if "ring" in names:
            backends.append("ring")
        if names & {"aws-lc-rs", "aws-lc-sys"}:
            backends.append("aws-lc")
        if backends:
            return "rustls+" + "+".join(backends)
    return stack


def trust_flavor(crates: list[tuple[str, str]], markers: dict[str, bool]) -> str | None:
    """Where server-cert trust comes from: 'native-certs', 'webpki-roots', or None.

    rustls-native-certs wins over webpki-roots when both are present: it is the
    actionable answer (system CA install works) and native-certs apps typically
    keep webpki-roots as a fallback set. None means custom verifier / unknown —
    worth manual inspection, possibly app-level pinning (SPEC: out of scope for
    auto-defeat, detect + document).
    """
    names = {n for n, _ in crates}
    if "rustls-native-certs" in names:
        return "native-certs"
    if markers.get("mozilla_root_anchors") or "webpki-roots" in names:
        return "webpki-roots"
    return None


def http3_capable(crates: list[tuple[str, str]]) -> bool:
    """True if quinn/h3 code is compiled in (direct-h3 egress could bypass a proxy)."""
    return bool({n for n, _ in crates} & _HTTP3_CRATES)


def analyze(report: dict) -> dict:
    """Add derived interpretation fields to a :func:`fingerprint_bytes` result.

    Adds (in order): ``tls_stack``, ``trust_flavor``, ``http3``, ``env_proxy``,
    ``relevance`` ("primary" = networking core worth intercepting,
    "informational" = Rust lib without TLS/proxy markers), ``notes``.
    """
    derived = {
        "tls_stack": tls_stack(report["crates"], report["markers"]),
        "trust_flavor": trust_flavor(report["crates"], report["markers"]),
        "http3": http3_capable(report["crates"]),
        "env_proxy": report["markers"]["env_proxy_support"],
    }
    derived["relevance"] = (
        "primary" if (derived["tls_stack"] or derived["env_proxy"]) else "informational"
    )
    out = {**report, **derived}
    out["notes"] = _notes(out)
    return out


def classify(report: dict) -> list[str]:
    """Human-readable interpretation — heuristics, printed for the analyst.

    Accepts a raw :func:`fingerprint_bytes` result (analyzes it first) or an
    already-analyzed one.
    """
    if "relevance" not in report:
        report = analyze(report)
    return list(report["notes"])


def _notes(a: dict) -> list[str]:
    m = a["markers"]
    notes = []
    tls = a["tls_stack"]
    if tls is None:
        pass
    elif tls.startswith("rustls"):
        notes.append(f"TLS: {tls} (in-process, platform store ignored)")
    elif tls == "native-tls":
        notes.append("TLS: native-tls (platform trust store — system CA install may work)")
    elif tls == "rquest":
        notes.append("TLS: rquest (browser-impersonating reqwest fork, own TLS stack)")
    else:
        notes.append(f"TLS: {tls} (in-process)")
    if a["trust_flavor"] == "native-certs":
        notes.append("trust: rustls-native-certs → system CA install works, no binary patch needed")
    elif a["trust_flavor"] == "webpki-roots":
        notes.append("trust: compiled-in webpki-roots → binary patch required (T1 verify-branch or T2 anchor-swap)")
    elif tls is not None and tls.startswith("rustls"):
        notes.append("trust: no rustls-native-certs, no compiled-in Mozilla anchor set → custom verifier or non-standard roots; inspect manually (app-level pinning possible)")
    if a["relevance"] == "informational":
        # No networking evidence at all — interception advice would be noise.
        notes.append("no TLS/proxy markers — not a networking core (informational)")
        return notes
    if a["env_proxy"]:
        notes.append("proxy: env-var plumbing present → M1 shim (setenv) works; no root needed")
    elif m["connect_tunnel"] or m["socks_support"]:
        notes.append("proxy: tunnel support present but no env detection → M2 frida or M3 redirect")
    else:
        notes.append("proxy: no proxy plumbing detected → M3 transparent redirect")
    if a["http3"]:
        notes.append("HTTP/3: quinn/h3 present — watch for direct-h3 bypassing the proxy; block UDP/443 if seen")
    return notes
