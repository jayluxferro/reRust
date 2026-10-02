# reRust — SPEC v0.2

> reFlutter for Rust-based mobile apps: make apps whose networking lives in a
> statically-linked Rust core (reqwest / hyper / rustls and friends) proxy-able and
> TLS-transparent for Burp / mitmproxy — without root, without source, without Frida.

## Why this exists

reFlutter solves Flutter apps by swapping `libflutter.so` with a patched engine. Rust-core
apps have no swappable engine: every app embeds its own Rust build (`librhttp.so`,
`librust_lib_*.so`, embedded runtimes, ...). The classic mobile MITM toolkit dies three
ways at once:

1. **No Java-layer trust surface.** TLS happens inside the Rust `.so` (rustls + ring /
   aws-lc); the platform trust store is never consulted.
2. **Compiled-in trust anchors** (`webpki-roots`): even a system-level CA install on a
   rooted device does nothing.
3. **No proxy awareness.** reqwest/hyper-util *does* read `HTTP(S)_PROXY`/`ALL_PROXY`
   env vars — but Android never sets them, and Wi-Fi proxy settings are ignored.

Points 2 and 3 are both verifiable in the target binary, which is why a binary-level
tool is the right shape — the same conclusion reFlutter reached for Flutter.

## Architecture

Two orthogonal problems, independent mechanisms:

### P1 — Traffic redirection
- **M1 shim (flagship, no root):** tiny `librerust.so` injected into the APK and added to
  each Rust lib's `DT_NEEDED` (patchelf). Its constructor does
  `setenv("HTTP_PROXY"|"HTTPS_PROXY"|"ALL_PROXY", <proxy>)` reading a baked-in value or
  a config file. Every reqwest/hyper-util `Client` built afterwards picks up the proxy
  with proper CONNECT semantics. Version-tolerant; requires the env plumbing compiled in
  (`rerust inspect` reports it).
- **M1.5 connect-hook:** a `connect()` interposer in the same shim for cores with NO
  env plumbing (embedded JS runtimes, hand-rolled hyper stacks). Rewrites matching TCP
  dials to the proxy and speaks the CONNECT preamble on the app's behalf. UDP is left
  untouched on purpose: QUIC flows fail to tunnel and the stack falls back to TCP.
- **M2 frida (runtime, rooted/emulator):** `rerust frida` emits a self-contained agent —
  getenv hook, live trust patch, dial observer — for workflows that prefer no repack.
- **M3 transparent redirect (fallback):** socket-level or DNAT redirection.

### P2 — Trust defeat
- **T1 verify-entry patch (flagship):** byte-pattern patch forcing the verifier's
  `verify_server_cert` to return Ok. Patterns keyed by `crate@version + provider + arch`
  in `patterns/` — the direct analog of reFlutter's engine-version table, keyed by the
  crate fingerprint `rerust inspect` extracts from stripped binaries. The compiled Ok
  tag is **codegen-selected, not a constant** — re-derived per fingerprint
  (see docs/pattern-derivation.md).
- **T2 anchor swap (data-only alternative):** overwrite one compiled-in `TrustAnchor`'s
  subject + SPKI with the proxy CA's. Pinned to the pki-types struct layout of the build.
- **T3 native-certs apps (easy case):** roots read from the filesystem → plain system-CA
  install; no patch. `rerust inspect` detects and says so.
- Out of scope: app-level pinning (SPKI compares in app code) — detected and reported,
  not auto-defeated.

### CLI surface

```
rerust inspect app.apk        # fingerprint: rust libs, crates@versions, TLS stack, modes
rerust patch app.apk --proxy http://127.0.0.1:9999 [--redirect all --hook-connect]
rerust frida <apk|lib> --proxy URL   # emit the runtime agent
```

## Pattern DB rules

- One yaml per fingerprint; selection gates on crate+version+arch+extras (provider).
- A pattern must match at exactly one offset in its source binary, or the repack refuses.
- Every entry records source-binary sha256 + derivation method.
- Sites are chosen by runtime evidence or caller-xref census — never by shape alone
  (real binaries carried four verifier impls; region/shape filtering hid the live one).

## Success criteria

- A real-world Flutter+Rust app's rustls core decrypts through Burp on an unrooted
  production-image emulator, with the patched APK installing and running normally —
  both the reqwest half and the embedded-runtime half.
- Status: **achieved and shipped as [v0.1.0](https://github.com/jayluxferro/reRust/releases/tag/v0.1.0)**.

## Risks / honest limits

- Stripped + LTO Rust can inline/merge verification code; anchors drift between builds.
  Mitigation: harness-first derivation, D4 discipline, parked-with-evidence entries.
- Ok tags differ per (version, provider, target) triple — always re-derive.
- HTTP/3: QUIC over UDP bypasses TCP-only hooks (by design — forces TCP fallback).
- The proxy's TLS fingerprint is not the app's; CDN-side bot defenses may challenge.
- Lab networks that sinkhole ad domains will trip in-app "adblock detection" gates —
  that is the network, not the tool.
- iOS: same design via Mach-O patch + dylib injection + codesign. Planned.

## Decisions

- **D1** v1 flagship = repack patcher (M1 + T1): reFlutter-identical UX, no root needed.
- **D2** Python CLI (uv project), stdlib + pyyaml only, published to PyPI; `uv sync`
  works from a fresh clone.
- **D3** Pattern DB yaml-per-fingerprint, sha256-pinned, falsifications recorded.
- **D4** One site or refuse; experimental → stable on a second binary of the same
  fingerprint (self-built pinned targets make this trivial — docs/corpus-farming.md).
