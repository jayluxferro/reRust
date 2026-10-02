# Pattern DB

One yaml per `crate-version_arch` — the direct analog of reFlutter's engine-version
table, keyed by the crate fingerprint `rerust inspect` extracts from panic-location
strings (which survive stripping; see docs/research/librhttp-notes.md).

## Schema

```yaml
target:
  crate: rustls
  version: 0.23.37
  arch: aarch64
  extras:            # anything that changes codegen enough to move the patch
    webpki: 0.103.10
    crypto: ring
derived_from:
  binary_sha256: "..."   # the exact binary this was researched on
  method: "ghidra xref from string anchor `invalid peer certificate: `"
patches:
  - name: server-cert-verify-force-ok
    match: "d1 00 00 ?? ..."   # wildcarded byte pattern, unique in file
    patch_offset: 12           # bytes from match start to patch site
    patch_bytes: "..."
    validation:
      before: "cbz w0, ..."
      after: "mov w0, #1 ; ret"
anchor_swap:                    # optional, data-only alternative
  array_vaddr: 0x0
  struct_layout: "(subject_ptr, subject_len, spki_ptr, spki_len, name_constraints_ptr, name_constraints_len) x N"
  relocation: R_AARCH64_RELATIVE
  candidate_anchor: "DigiCert Global Root CA (RSA-2048, no name_constraints)"
  recipe: |
    file-offset steps to swap subject+spki with user CA DER
```

## Rules (D4 in SPEC)

- Every entry must record the source-binary sha256 and the derivation method.
- A pattern that matches at != 1 offset in its source binary is invalid — weaken/strengthen
  it, don't ship it.
- Entries are contributions: reproduce on a second binary of the same fingerprint before
  promoting from `experimental:` to `stable:`.
