"""Trust-defeat application from the version-keyed pattern DB (SPEC T1, D4).

Selection is fingerprint-gated: a pattern applies only when the target lib's
own crate fingerprint (crate@version + arch + extras) matches the yaml's
``target`` block — the same discipline reFlutter uses for engine versions.
A selected pattern MUST match at exactly one offset: zero or several hits both
abort the repack loudly (D4: one site or refuse). Re-applying to an
already-patched lib is detected and reported as a no-op (idempotent re-repacks,
matching the DT_NEEDED idempotence in repack.py).

The matcher understands nibble-level wildcards (``f?``, ``?9``, ``??``) and is
compiled to a bytes regex so scans run in C even over multi-MB libs; matches
are found with a lookahead so overlapping candidates are all counted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

# ABI (as it appears in lib/<abi>/) -> arch naming used in pattern yaml targets.
ABI_ARCH = {"arm64-v8a": "aarch64", "x86_64": "x86_64", "armeabi-v7a": "armv7"}


# --- pattern DB ---------------------------------------------------------------


@dataclass(frozen=True)
class PatternEntry:
    """One applicable patch from patterns/<crate>-<version>_<arch>.yaml."""

    db_file: str
    crate: str
    version: str
    arch: str
    extras: dict  # codegen-pinning facts: crate versions, crypto provider, ...
    name: str
    match_text: str  # space-separated tokens, nibble wildcards allowed
    patch_offset: int  # bytes from match start to the patch site
    patch_bytes: bytes
    source_sha256: str  # binary this was derived on (D4 provenance)


class TrustError(RuntimeError):
    """Loud failure base — a repack with a trust error must not ship."""


class PatternNotFound(TrustError):
    pass


class PatternAmbiguous(TrustError):
    pass


def load_patterns(db_dir: str | Path) -> list[PatternEntry]:
    """Load all patches/*.yaml entries under db_dir (fragments tolerated)."""
    entries: list[PatternEntry] = []
    for f in sorted(Path(db_dir).glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
        if not isinstance(doc, dict):
            continue
        target = doc.get("target") or {}
        derived = doc.get("derived_from") or {}
        for p in doc.get("patches") or []:
            if "match" not in p or "patch_bytes" not in p:
                continue
            entries.append(
                PatternEntry(
                    db_file=f.name,
                    crate=target.get("crate", ""),
                    version=str(target.get("version", "")),
                    arch=target.get("arch", ""),
                    extras=dict(target.get("extras") or {}),
                    name=p.get("name", f.name),
                    match_text=re.sub(r"\s+", " ", str(p["match"])).strip(),
                    patch_offset=int(p.get("patch_offset", 0)),
                    patch_bytes=bytes.fromhex(re.sub(r"\s+", "", str(p["patch_bytes"]))),
                    source_sha256=str(derived.get("binary_sha256", "")),
                )
            )
    return entries


def select_pattern(
    entries: list[PatternEntry],
    crates: list[tuple[str, str]],
    arch: str,
    tls_stack: str | None,
) -> PatternEntry | None:
    """The DB entry whose target block matches this lib's fingerprint.

    extras keys that name crates must match the fingerprint's crate versions;
    the special key ``crypto`` must appear in the classified tls_stack string
    (e.g. 'rustls+ring'). Any mismatch disqualifies the entry — the DB, not
    the caller, decides applicability.
    """
    crate_map = dict(crates)
    for e in entries:
        if crate_map.get(e.crate) != e.version or e.arch != arch:
            continue
        ok = True
        for k, v in e.extras.items():
            if k == "crypto":
                if not tls_stack or str(v) not in tls_stack:
                    ok = False
                    break
            elif crate_map.get(k) != str(v):
                ok = False
                break
        if ok:
            return e
    return None


# --- wildcard matcher ---------------------------------------------------------


def _nibble_class(hi: str, lo: str) -> str:
    """Regex character class for one pattern token (ASCII-escaped)."""
    if hi == "?" and lo == "?":
        return "[\\x00-\\xff]"
    if hi == "?":
        return "[" + "".join(f"\\x{h}{lo}" for h in "0123456789abcdef") + "]"
    if lo == "?":
        return f"[\\x{hi}0-\\x{hi}f]"
    return "\\x" + hi + lo


def pattern_regex(match_text: str) -> re.Pattern[bytes]:
    """Compile a token pattern to a bytes regex (overlapping-safe: lookahead)."""
    parts = []
    for tok in match_text.split():
        tok = tok.lower()
        if len(tok) != 2 or any(c not in "0123456789abcdef?" for c in tok):
            raise ValueError(f"bad pattern token {tok!r} in {match_text!r}")
        parts.append(_nibble_class(tok[0], tok[1]))
    return re.compile(("(?=" + "".join(parts) + ")").encode("ascii"), re.DOTALL)


def find_sites(data: bytes, match_text: str) -> list[int]:
    return [m.start() for m in pattern_regex(match_text).finditer(data)]


def apply_trust(data: bytes, entry: PatternEntry) -> tuple[bytes, int, bool]:
    """Apply one pattern entry; returns (new_data, match_offset, already_applied).

    Raises PatternNotFound / PatternAmbiguous per D4 (exactly one site or
    refuse). Idempotence: patterns with patch_offset 0 overwrite their own
    match bytes, so a re-repack cannot re-match — instead, zero hits combined
    with exactly one occurrence of the patch bytes in the lib is reported as
    already-applied (12 arbitrary instruction bytes colliding anywhere else
    in a stripped lib is astronomically unlikely; anything else stays an error).
    """
    sites = find_sites(data, entry.match_text)
    if not sites:
        if data.count(entry.patch_bytes) == 1:
            return data, data.find(entry.patch_bytes), True
        raise PatternNotFound(
            f"{entry.name}: 0 hits in {len(data)}-byte lib "
            f"(pattern from {entry.db_file}, derived on sha256 {entry.source_sha256[:16]}… "
            f"— fingerprint matched but codegen drifted; re-derive the pattern)"
        )
    if len(sites) > 1:
        shown = ", ".join(hex(s) for s in sites[:4])
        raise PatternAmbiguous(
            f"{entry.name}: {len(sites)} hits ({shown}…) — refusing to patch (D4: one site or refuse)"
        )
    off = sites[0]
    lo = off + entry.patch_offset
    if data[lo : lo + len(entry.patch_bytes)] == entry.patch_bytes:
        return data, off, True
    patched = data[:lo] + entry.patch_bytes + data[lo + len(entry.patch_bytes) :]
    return patched, off, False
