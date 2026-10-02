# Lab setup — intercepting a Rust-core app with reRust

## Build the patched app

```bash
rerust patch app.apk --proxy http://127.0.0.1:9999 --out app.rerust.apk
# add --redirect all --hook-connect for cores without env-proxy plumbing
# (e.g. embedded runtimes that dial sockets directly)
```

`rerust patch` dispatches on the input: an `.ipa` (or a bare Mach-O for
`inspect`) takes the iOS pipeline — same flag surface, iOS mechanics
(see the iOS section at the bottom).

## Point the device at your proxy

On an emulator, do NOT bake the host's `10.0.2.2` alias into the shim — on several
emulator builds it is unreachable and every dial dies in the network stack. The robust
pattern is a reverse tunnel and an on-device loopback proxy URL:

```bash
adb reverse tcp:9999 tcp:8080        # device 127.0.0.1:9999 -> host proxy :8080
adb install -r app.rerust.apk
```

The reverse rule survives app restarts but not emulator reboots — re-run it after reboot.
`rerust inspect` first tells you which libs will be shimmed and which patterns apply.

## Proxy endpoints

Any explicit-proxy HTTP(S) interceptor works: Burp, mitmproxy (`mitmdump --verbose`),
etc. For cores routed by the connect-hook, the shim speaks CONNECT on the app's behalf.

## Certificate notes

- The **Rust core needs no CA installation anywhere** — the trust patch makes the
  client accept the proxy's certificate. This is the whole point of reRust, and it is
  why patched apps run on unrooted devices with zero CA setup.
- Stacks that consult the **platform trust store** (Java, WebView, cronet,
  Dart/BoringSSL) still need the proxy CA trusted. On modern Android (14+) the
  effective store lives under `/apex/com.android.conscrypt/cacerts`, NOT
  `/system/etc/security/cacerts` — a classic `/system` install is invisible there.
  On a rooted lab device, shadow the apex store from zygote's mount namespace
  (children inherit it; no per-app racing):

  ```bash
  adb root
  adb shell nsenter -t $(pidof zygote64) -m -- sh -c '
    mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts &&
    cp /system/etc/security/cacerts/* /apex/com.android.conscrypt/cacerts/ &&
    cp /data/local/tmp/your-proxy-ca.0 /apex/com.android.conscrypt/cacerts/ &&
    chown 0:0 /apex/com.android.conscrypt/cacerts/* &&
    chmod 644 /apex/com.android.conscrypt/cacerts/*'
  ```

  Copy cert files through `/data/local/tmp` — a namespace may hold a different
  (verity-verified) view of `/system` than your shell.
  User-store installs alone do not work for `targetSdk >= 24` apps without a
  `networkSecurityConfig` opt-in.

## Watching what happens

- `adb logcat | grep -E 'reRust|reqwest'` — shim bootstrap, proxy interception,
  connect-hook flows.
- The proxy's own log is the ground truth for decrypted traffic.

## Known lab quirks

- Ad-blocked lab networks: if your resolver sinkholes ad domains, apps with
  "adblock detection" (any ad-call failure => block the user) will gate themselves
  on your own network, with or without interception.
- QUIC/HTTP3: the connect-hook covers TCP only by design — UDP/443 QUIC flows fail
  to tunnel and the stack falls back to TCP, which is intercepted.

## Hybrid Flutter+Rust apps

reRust covers the Rust core. Flows that leave via Dart's own `dart:io` sockets
(catalog code that doesn't route through the Rust client, WebView plumbing,
some SDK traffic) terminate TLS inside `libflutter.so` with the engine's
compiled-in roots — that half needs **[reFlutter](https://github.com/Impact-I/reFlutter)**
(engine patch) on top. The two tools compose: reFlutter the app first, then
reRust-patch the same build (or vice versa) — each owns a different half of the
network stack. `rerust inspect` tells you which libs carry which half.

## iOS (.ipa)

The same CLI drives the iOS pipeline; it dispatches on the `.ipa` extension.
The trust move is byte-identical in spirit (one pattern entry per arch, in
`patterns/rustls-*-arm64_ios.yaml`), the loader mechanics differ:

```bash
# 1. package the built app as an .ipa — note the Payload/ wrapper: ditto
#    archives the CONTENTS of its source dir, so wrap the app in Payload/
#    and keep that dir name with --keepParent
mkdir -p stage/Payload && ditto build/ios/iphonesimulator/Runner.app stage/Payload/Runner.app
ditto -c -k --keepParent stage/Payload app.ipa

# 2. patch (builds the shim via xcrun; re-signs ad-hoc)
rerust patch app.ipa --proxy http://<lan-ip>:9999 --out app.rerust.ipa

# 3. run it against the proxy
xcrun simctl boot "iPhone 17 Pro"
xcrun simctl install booted app.rerust.ipa
mitmdump --listen-host <lan-ip> -p 9999 &
xcrun simctl launch --console-pty booted <bundle-id>
```

Simulator notes:

- **The simulator shares the host network.** There is no `10.0.2.2` alias and
  no need for reverse tunnels: bake the host's LAN IP (or `127.0.0.1`) into
  the shim and point mitmdump at the same address.
- **Simulator builds are debug-flavored only** (`flutter build ios
  --simulator`; Apple does not ship a release sim SDK). Modern Xcode emits a
  stub main executable that `LC_LOAD_DYLIB`s a `Runner.debug.dylib`, which in
  turn loads frameworks through `@rpath/...`. Plain `simctl launch` resolves
  those fine — no Xcode environment needed (verified: the frameworks load and
  the injected shim's `@rpath/librerust.dylib` resolves through the same
  mechanism).
- **Code signing**: byte surgery invalidates embedded signatures, and even
  the simulator refuses to launch code whose signature doesn't match its
  content. The pipeline re-signs ad-hoc (`codesign -f -s -`), in the order
  the format demands: shim dylib and every patched nested binary first, the
  bundle itself last (bundle signing regenerates the main executable's
  CodeDirectory — the reason a modified macOS/iOS app needs exactly one
  re-sign command, not per-binary passes). `--no-sign` skips this for tests;
  the output will not launch anywhere.
- **What is in scope**: self-built or otherwise directly-signed apps
  (development/ad-hoc/distribution-signed ipas that run on your machine).
  **App Store ipas are FairPlay-encrypted** — the binary on disk is a cipher
  blob until the loader decrypts it, so no static patch pipeline can reach
  it; that requires a decrypted dump (out of scope). A physical device
  additionally needs development signing + a provisioned device and will
  likely need a device-arch pattern derived separately (simulator codegen is
  debug-flavored and the byte windows will not match a device build).
- **Shim injection needs header padding.** LC_LOAD_DYLIB is written into the
  zero-padding after the load commands — real ld leaves little. The pipeline
  tries a 48-byte `@rpath/librerust.dylib` command first and a 72-byte
  `@executable_path/Frameworks/...` command second, and refuses loudly
  (no silent header rewrite) if neither fits.

### Toolchain quirks hit while building an FRB app for the simulator

Lab-machine archaeology, kept here because every one of them cost real time:

- **rustup home skew**: if `rustc` in `PATH` is a non-rustup (e.g. Homebrew)
  toolchain, toolchain cargo spawns it and dies with `E0463: can't find crate
  for core` for `-target aarch64-apple-ios-sim` (no ios-sim std there). The
  working `PATH` puts `~/.cargo/bin` FIRST so the rustup proxy resolves the
  rustup toolchain.
- **backtrace vs libc bit-rot on ios-sim**: libc ≥ 0.2.174 dropped the
  `_dyld_image_count` family that backtrace ≤ 0.3.76 still declares via
  `libc::`, and pinning libc is impossible (tokio-adjacent crates floor it
  higher). flutter_rust_bridge hardcodes allo-isolate's `backtrace` feature,
  so you cannot sever it from the app either. Workaround: vendor a backtrace
  fork that declares the four `dyld` functions directly (a `dyld` extern
  module in `symbolize/gimli/libs_macos.rs`).
- **Xcode 27 `lipo -verify_arch` accepts exactly ONE arch**: the two-arch
  invocation misparses the extra arch as an input file and fails, which
  breaks flutter_tools' thinFramework step for simulator builds (script
  phases also get Xcode's toolchain dir prepended to PATH, so a PATH shim of
  `lipo` does not reach them). Local flutter_tools patch: verify per-arch
  with AND semantics. Remember flutter_tools caches its snapshot — deleting
  `bin/cache/flutter_tools.snapshot` (+ `.stamp`) is required after editing
  its Dart sources.

### Recipe proven end-to-end

Flutter + flutter_rust_bridge app, reqwest/rustls 0.23.45 (webpki-roots)
core: patched ipa installs on a booted simulator, the shim's constructor
bakes the proxy, and the app displays the **decrypted** response served by
mitmdump (`200 OK server=cloudflare ...`), while the same build with
`--no-trust` fails the handshake with a rustls connect error — the 20-byte
trust patch is load-bearing. Pattern derivation walkthrough:
`docs/research/ios-macho-walkthrough.md`.
