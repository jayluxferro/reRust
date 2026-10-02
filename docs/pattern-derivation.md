# Pattern derivation — adding a trust-defeat entry to the DB

The DB (`patterns/*.yaml`) is keyed by library build: a pattern targets one
`(crate-version, crypto-provider, target)` triple of the verifier code compiled into
a specific `.so`. Off-the-shelf cores ship identical binaries across apps, so each
entry unlocks every app on that release.

## Rules (enforced by tests)

- One yaml per fingerprint; `select_pattern` gates on the target block including
  `extras` (provider pins like `crypto: ring` / `crypto: aws-lc`).
- A pattern must match at exactly ONE offset in its source binary — zero or several
  both refuse loudly.
- Every entry records `binary_sha256` provenance and the derivation method.
- The **Ok tag is codegen-selected, not a constant**: the compiled `Result`
  discriminant for the same trait differs across (version, provider, target)
  triples — e.g. one build's dispatcher tests tag byte `0x16` for Ok while another
  uses `0xff`. Re-derive per binary; never copy a tag between fingerprints.

## Method (the chain that survived contact with real apps)

**Shortcut:** a disassembler with dataflow tracing (e.g. IDA via `idalib`) reproduces
steps 2-4 in one pass — trace backward from a panic-`Location` struct and you get the
struct typed with line/column, its single ADRP/ADD xref, and the containing function
byte-exact. Prefer that when available; the manual chain below is the dependency-free
fallback and the cross-check. Caveat: inferred function bounds may include trailing
unwind pads past the epilogue `ret` — record both the tool's bounds and the
ret-terminated range when deriving.

1. **Fingerprint** the target with `rerust inspect` — crate versions, provider,
   arch. No pattern without a fingerprint match.
2. **Locate verifier candidates** from the crate set's structure. For rustls-based
   cores: find the `webpki-roots` TrustAnchor table ( Borrowed-tag pointers with a
   fixed stride in `.data.rel.ro`), follow `R_AARCH64_RELATIVE` relocations to the
   vtables, read the `verify_server_cert` slot.
3. **Census by caller-xref, not by shape.** Region-scoping vtables or filtering
   slots by strict shape both produced false negatives on real binaries — a fourth
   verifier impl (a custom `ServerCertVerifier`) was missed twice and only found by
   xrefing the shared TLS1.2/1.3-signature helpers and accounting for every wrapper
   pair. Patch sites must be chosen by runtime evidence or a caller-xref census —
   never by "the impl that should be live".
4. **Validate in a reference harness first.** Build a small client with the exact
   pinned crate versions (same provider feature), reproduce the
   `invalid peer certificate: UnknownIssuer` failure through your proxy, then
   confirm your patch flips it to a completed request. Harness cycles are seconds;
   device cycles are minutes.
5. **Prove uniqueness** of the wildcarded pattern over the whole binary; write the
   yaml with the patch bytes, the Ok-tag evidence (the dispatcher's compare), and a
   regression test pinning the offset against the source binary.
6. **On-device arbitration**: deploy, watch the proxy log. `tlsv1 alert unknown ca`
  means a live verifier is unpatched (the alert mapping in rustls 0.23.4x:
  `UnknownIssuer -> UnknownCA`). Iterate — candidates that deploy clean but do not
  change runtime behavior are parked in the yaml with their bench falsification
  recorded.

## Anchor-swap alternative (data-only)

Instead of patching code, overwrite one compiled-in `TrustAnchor`'s subject + SPKI
DER with your proxy CA's (length-constrained swap inside the packed roots table).
The table is live and correct on real targets; the exact swap payload rules
(headerless subject DER, SPKI length words) are documented in the yaml's
`anchor_swap` sections. This path needs no tag derivation but is pinned to the
`rustls-pki-types` struct layout of the target build.

## Farming entries proactively

See [corpus-farming.md](corpus-farming.md) — pin crate versions in a throwaway app
and derive entries without waiting for real-world targets.
