# Lab setup — intercepting a Rust-core app with reRust

## Build the patched app

```bash
rerust patch app.apk --proxy http://127.0.0.1:9999 --out app.rerust.apk
# add --redirect all --hook-connect for cores without env-proxy plumbing
# (e.g. embedded runtimes that dial sockets directly)
```

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
