# reRust

**Traffic interception for Rust-based mobile apps — the reFlutter playbook, applied to
rustls/reqwest cores.**

Mobile apps increasingly move their networking into a statically-linked Rust library.
That kills every classic interception technique at once: TLS terminates inside the `.so`
with compiled-in Mozilla roots (`webpki-roots`), the platform CA store is never consulted,
and the Wi-Fi proxy settings are ignored because reqwest only speaks `HTTP(S)_PROXY` env
vars that Android never sets.

reRust makes those apps transparent again:

- `rerust inspect app.apk` — fingerprint the Rust core (exact crate versions, TLS stack,
  trust store flavor) straight from a stripped binary. `.ipa` and bare Mach-O images work
  too.
- `rerust patch app.apk|.ipa --proxy http://127.0.0.1:9999` — repack with an env-proxy shim +
  fingerprint-gated trust patch (+ optional `connect()` hook for cores without env
  plumbing); debug-signed APK output that runs on **unrooted** devices, ad-hoc re-signed
  ipa output for the iOS pipeline (simulator-validated; see the iOS section of
  [docs/lab-setup.md](docs/lab-setup.md)).
- `rerust frida <apk|lib> --proxy URL` — the same interception at runtime, no repack
  (Android-validated; the generated agent is platform-neutral JS but untested on iOS).

```bash
# pip / uv
pip install rerust
uv tool install rerust        # or from a clone: uv sync && uv run rerust --help

# end-to-end lab recipe (validated on production-image emulators, no root):
rerust patch app.apk --proxy http://127.0.0.1:9999 --out app.rerust.apk
adb reverse tcp:9999 tcp:8080   # tunnel to Burp/mitmproxy — never rely on 10.0.2.2
adb install -r app.rerust.apk
# decrypted HTTP/2 lands in your proxy within seconds of launch
```

**No CA installation is needed for the Rust core** — the trust patch makes the client
accept the proxy's certificate, which is why patched apps run unrooted. Platform-store
consumers (Java/WebView/Dart) are covered separately in [docs/lab-setup.md](docs/lab-setup.md),
including the modern-Android apex-store recipe.

The pattern DB is keyed by **library build**, not app: off-the-shelf cores (`rhttp`,
Tauri v2's reqwest, …) ship identical `.so` files across apps, so each entry unlocks
every app on that release — and entries can be farmed proactively against self-built
pinned targets ([docs/corpus-farming.md](docs/corpus-farming.md)).

Docs: [SPEC.md](SPEC.md) · [lab setup](docs/lab-setup.md) ·
[pattern derivation](docs/pattern-derivation.md) · [corpus farming](docs/corpus-farming.md) ·
[iOS Mach-O walkthrough](docs/research/ios-macho-walkthrough.md)

Lineage: from the maintainer of [reFlutter](https://github.com/Impact-I/reFlutter).

License: [MIT](LICENSE)
