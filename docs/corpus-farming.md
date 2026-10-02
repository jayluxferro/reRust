# Corpus farming — growing the pattern DB with self-built targets

The DB is keyed by **library build**, not by app: off-the-shelf Rust cores ship as
prebuilt `.so` artifacts, so one pattern entry per (crate-version, crypto-provider,
target) triple unlocks every app built on that release. That means entries can be
farmed proactively against pinned throwaway builds — no real-world target needed.

## Ecosystem map (what to farm)

| Target class | Built with | Library signature in an APK |
|---|---|---|
| rhttp apps | `rhttp` pub package (reqwest+rustls via FRB) | `librhttp.so` — env-proxy plumbing present |
| FRB custom crates | `flutter_rust_bridge` v2 `integrate` | `librust_lib_<app>_.so` |
| rinf apps | `rinf` (FRB alternative) | `librust_<crate>.so` |
| rust_in_flutter | `rust_in_flutter` | `librust_lib_*.so`-ish |
| Tauri v2 mobile | reqwest in the Rust core | `lib<app>.so` |
| UniFFI SDKs | `uniffi` (Kotlin/Swift) | `libuniffi_*.so` / `lib<crate>.so` |
| Plain JNI | `jni` crate | arbitrary |

`rerust inspect` fingerprints all of the above (crate paths + markers work on any
Rust ELF).

## Quickstart (rhttp pattern)

```bash
flutter create farm_rhttp && cd farm_rhttp
cargo install flutter_rust_bridge_codegen
flutter_rust_bridge integrate
flutter pub add rhttp
# pin the versions you want DB entries for in Cargo.toml, e.g.:
#   rustls = "=0.23.38"
#   reqwest = { version = "=0.12.28", default-features = false, features = ["rustls-tls"] }
cargo ndk -t arm64-v8a -p 24 -o android/app/src/main/jniLibs build --release
flutter build apk --release
rerust inspect build/app/outputs/flutter-apk/app-release.apk
```

Variants to pin alongside the default: `rustls-tls-native-roots` (should need NO
patch — a good negative test), the `aws-lc-rs` provider, `x86_64`, and each rustls
point release in circulation.

## The farming loop

1. Build, inspect, record the fingerprint.
2. Derive per [pattern-derivation.md](pattern-derivation.md) — including the
   per-binary Ok-tag re-derivation.
3. Validate in the reference harness first; prove pattern uniqueness.
4. Ship the yaml + a regression test pinning the offset against the source binary.

## Contributions

A contribution is a yaml entry + derivation notes + the pinned target recipe
(or the source-binary sha256). Reviewers re-run the uniqueness check and the
harness validation. Entries graduate experimental → stable on a second binary of
the same fingerprint.
