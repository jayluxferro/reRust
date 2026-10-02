# Mach-O pattern derivation — rustls 0.23.45 / arm64-ios

How the first iOS entry (`patterns/rustls-0.23.45_arm64_ios.yaml`) was derived,
from a simulator build of the farm corpus app (Flutter + flutter_rust_bridge,
reqwest/rustls 0.23.45, webpki-roots trust flavor). This is the Mach-O variant
of the chain in [../pattern-derivation.md](../pattern-derivation.md) — same
destination, different loader-format mechanics. Every tool used here ships
with Xcode (`xcrun dyld_info`, `objdump`) or is Python stdlib; no hex-decompiler
was involved, and the binary's mangled Rust symbols survived the simulator
build pipeline (device builds will not be so kind — the shipped byte window is
deliberately symbol-independent so the entry still applies after a strip).

## 0. Fingerprint and address world

`rerust inspect app.ipa` (or on the bare framework dylib) reports the crate set
— rustls 0.23.45, rustls-webpki 0.103.15, rustls-pki-types 1.15.1, ring +
aws-lc-rs, hyper 1.6.0 / hyper-util 0.1.17 — and the arch. iOS arch strings get
an `-ios` suffix at slice classification (`arm64-ios`, `x86_64-ios`) so DB
entries can never cross-fire between an Android aarch64 ELF and an iOS arm64
Mach-O even though both are AArch64 code.

Address-world facts that make the Mach-O chain simpler than ELF:

- `__TEXT` has **file offset == vmaddr** (base 0 in this dylib), so function
  addresses read straight off the disassembly are simultaneously file offsets.
- `__DATA_CONST` shares that property here — panic-Location structs can be read
  in place, no bias arithmetic (the ELF chain's `.data.rel.ro` LOAD2 bias trap
  has no equivalent here).
- Rebase info lives in **chained fixups**, listed by `xcrun dyld_info -fixups`
  — no `.rela.dyn` addend walking.

## 1. Panic-Location strings are the map

Rust panic locations are `#[track_caller]` breadcrumbs: every `?` operator
compiles to code carrying a `&Location` — a 24-byte struct
`{ ptr: *const u8, len: usize, line: u32, col: u32 }` pointing at the source
path string. The strings dedupe per path, so one string serves many sites;
the STRUCTS are per-site and carry the line/col.

Steps:

```bash
# one deduped copy of the rustls server_verifier source path (108-byte tail)
strings -a the_dylib | grep 'rustls-0.23.45/src/webpki/server_verifier.rs'

# every rebase target — the pointer fields of those Location structs appear here
xcrun dyld_info -fixups the_dylib | grep <string-offset-hex>
```

For each candidate struct address, scan `__DATA_CONST` for the 24-byte pattern
`<ptr=string-start><len=108><line><col>` and read line/col. **False start worth
recording**: the first scan matched rebase targets against the offset of the
*grep hit* — the middle of the path — and found nothing. Locations point at the
string's first byte; walk back from any match position to the preceding NUL.

The lines that fall out for rustls 0.23.45's `webpki/server_verifier.rs`:

| line | col | source (`?` sites of `verify_server_cert`) |
|------|-----|---------------------------------------------|
| 121  | 13  | `build()` — `NoRootAnchors` error            |
| 127  | 10  | `build()` — the `Ok(...)` return             |
| 211  | c26 | `ParsedCertificate::try_from` call chain     |
| 240  | 20  | `end_entity.try_into()?`                     |
| 253  | 22  | the revocation-options `?`                   |
| 263  | 9   | `verify_server_cert_signed_by_trust_anchor_impl(...)?` |
| 276  | 9   | `verify_server_name(&cert, server_name)?`    |

(Two extra Location structs point at a *merged* string — the linker merged two
identical string tails; ignore structs whose line/col don't map to source.)

## 2. From Locations to the function

`verify_server_cert` is the function whose `?`-propagation paths reference the
L263/L276 Locations. Two routes to its address, and the honest record of both:

- **Route A (abandoned mid-way)**: a pure-Python scanner pairing ADRP/ADD
  immediates against the Location addresses. The pairing itself worked, but its
  LC_FUNCTION_STARTS bookkeeping was garbage — the `__text` size decoded as
  34 GB and every xref was attributed to "function starting at 0x38". ULEB128
  delta lists are easy to get subtly wrong, and wrong bounds are worse than no
  bounds (they misattribute xrefs *plausibly*).
- **Route B (shipped)**: `xcrun objdump -d --macho` over the whole file once
  (147 MB of text in seconds), then plain `grep`. The simulator build kept
  mangled Rust symbols, so `verify_server_cert` is *named*:

  ```
  __RNvXs0_...6rustls6webpki15server_verifier...18ServerCertVerifier18verify_server_cert:
    2aaa98:  fc 6f be a9   stp x28, x27, [sp, #-0x20]!
  ```

  Function range `[0x2aaa98, 0x2ab06c)` (ends at the epilogue `ret`). Three
  independent confirmations, per the caller-xref rule from
  pattern-derivation.md: the function's Err paths feed `from_residual` with
  exactly the L263 (`0x2aae0c`) and L276 (`0x2ab024`) Locations; the L263 path
  directly follows the call to
  `...webpki6verify46verify_server_cert_signed_by_trust_anchor_impl`; and the
  *other* two `verify_server_cert` impls in the binary (reqwest's `NoVerifier`
  and `IgnoreHostname`) sit at their own addresses doing their own thing —
  the census says the WebPkiServerVerifier impl is the live verifier for this
  trust flavor.

## 3. Ok-tag derivation (per-binary, always)

Rust returns `Result<ServerCertVerified, Error>` through the sret register
`x8` (`ServerCertVerified::assertion()` is a ZST — the Ok payload is nothing,
only the discriminant byte matters). In THIS binary:

- **Producer** (Ok path, just before the epilogue):
  `ldr x9,[sp,#0xe0] ; mov w8,#0xff ; strb w8,[x9]` at `0x2ab03c` — the sret
  pointer spilled at entry is reloaded and the tag byte `0xFF` stored.
- **Dispatchers** (both `?` sites in-function):
  `ldrb w8,[sp,#X] ; uxtb w8,w8 ; subs w8,w8,#0xff ; cset x8,ne ; tbnz` —
  `0xFF` falls through to the Ok path, anything else propagates the error.

So tag = `0xFF` — same as the 0.23.37/0.23.38/0.23.40 Android binaries (4/4 so
far). That consistency is an observation, not an invariant: pattern-derivation.md
documents a build whose tag was `0x16`. Re-derive every time; the stub's
`movz` re-encodes as `word = 0x52800000 | (tag << 5) | Rd`.

## 4. The window

32 instructions from the entry, nibble-masked. Design rules that survived:

- **Keep what the ABI fixes**: the sret spill (`str x8,[sp,#imm]` — x8 is the
  indirect-result register), the `mov x8,x0` / `mov x0,x1` / `mov x1,x0` pivot
  (self saved, end_entity becomes try_from's arg0), the frame-record
  `stp x29,x30` shape.
- **Mask what codegen owns**: frame size, spill offsets, call targets (a `bl`
  encoding shifts with any code change), the callee-save pair in the prologue's
  first `stp`.
- **Class-keep instruction forms**: the ordered `x2..x7` spill run followed by
  the `x1..x6` re-spill run — this build's two-phase arg handling — is the
  signature shape of the window.
- **Trap**: `ldr xzr,[sp]` early in the prologue is a stack-probe idiom, NOT an
  Ok-value preinit (the Android 0.23.38 entry flagged the same trap).

Validation: whole-slice scan finds exactly ONE site (the entry); the 20-byte
stub has zero pre-existing occurrences (idempotence precondition); the three
Android windows score zero on this slice byte-wise, and the `-ios` arch gate
keeps the families mutually unselectable regardless.

## 5. The stub, assembler-verified

```
movz w9, #0xff        e9 1f 80 52
strb w9, [x8]         09 01 00 39     ; sret tag = Ok
str  xzr, [x8, #8]    1f 05 00 f9     ; defensive payload zeroing (and: the
str  xzr, [x8, #0x10] 1f 09 00 f9     ; 20-byte length the pipeline standardizes on)
ret                   c0 03 5f d6
```

Assembled with Apple clang for `arm64-apple-ios` and read back via objdump —
after the 0.23.37 entry's lesson that hand-encoded bytes have silently mismatched
a real assembler before. `x8` still holds the sret at entry (the function's own
first data move spills it), and returning without touching `sp`/`x29`/`x30`
leaves the frame intact for the caller's dispatcher.

## 6. What the live run proved (and didn't)

On the simulator (recipe in lab-setup.md §iOS): patched ipa → shim constructor
bakes the proxy → mitmdump sees the CONNECT, completes a TLS handshake with its
untrusted certificate, and the app displays the decrypted 200. `--no-trust`
negative control on the same proxy: rustls connect error in the UI. The patch
is load-bearing; webpki-roots is compiled in, so no keychain trust could
explain the handshake away.

Not yet proven:

- **Device builds** — release-mode codegen, FairPlay considerations, and
  provisioning are all untested; expect a separate `arm64-ios` entry derived
  from a device binary (the window will not survive the optimizer differences).
- **x86_64-ios** — the same derivation chain applies (x86 RIP-relative lea
  instead of ADRP/ADD); today the pipeline loudly skips the x86_64 slice.
- **A stripped device-grade binary** — the window is symbol-independent by
  construction, but the Location-based *derivation* route assumed readable
  symbols; on a stripped binary, fall back to the panic-string walk (step 1)
  and function-starts, which is exactly why the derivation chain — not the
  symbols — is what this document records.
