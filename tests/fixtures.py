"""Synthetic binary builders for the reRust tests.

Minimal stand-ins for stripped Rust libraries: an ELF-ish header plus
NUL-separated string fragments. Only the string content matters to the
fingerprinter — everything else is decoration to keep the fixtures honest
(i.e. they are *not* plain-text files).
"""

from __future__ import annotations

import zipfile

# The well-known crates.io sparse-registry hash (16 hex chars; the regex
# requires >= 8).
CRATES_IO = "index.crates.io-6f17d22bba15001f"


def cargo_path(crate: str, version: str, style: str = "posix", sub: str = "src/lib.rs") -> bytes:
    """A panic-location registry path, POSIX or Windows builder style."""
    if style == "posix":
        return f"/home/runner/.cargo/registry/src/{CRATES_IO}/{crate}-{version}/{sub}".encode()
    if style == "windows":
        return f"C:\\Users\\builder\\.cargo\\registry\\src\\{CRATES_IO}\\{crate}-{version}\\{sub}".encode()
    raise ValueError(f"unknown style: {style}")


def make_lib(*fragments: bytes, rustc_marker: bool = False) -> bytes:
    """Concatenate fragments into a fake stripped ELF (NUL-separated blob)."""
    parts: list[bytes] = [b"\x7fELF", b"\x00" * 32]
    if rustc_marker:
        parts.append(b"/rustc/" + b"a" * 40 + b"/library/std/src/panicking.rs")
    parts.extend(fragments)
    return b"\x00".join(parts) + b"\x00"


def librhttp_like() -> bytes:
    """Synthetic stand-in for the real target lib: rustls+ring reqwest core."""
    return make_lib(
        cargo_path("rustls", "0.23.37", "posix"),
        cargo_path("ring", "0.17.14", "posix"),
        cargo_path("reqwest", "0.12.28", "windows"),
        cargo_path("hyper-rustls", "0.27.7", "posix"),
        b"invalid peer certificate: ",
        b"ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy",
        b"tunneling HTTPS over proxy",
        b"DigiCert Global Root CA",
        b"ISRG Root X1",
        rustc_marker=True,
    )


def rust_glue_like() -> bytes:
    """Rust lib with no networking (e.g. app glue / storage) — informational."""
    return make_lib(
        cargo_path("flutter_rust_bridge", "2.12.0", "posix"),
        cargo_path("tokio", "1.34.0", "posix"),
        rustc_marker=True,
    )


def make_apk(path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)


# --- frida emitter fixtures ----------------------------------------------------

# Concrete bytes for the synthetic wildcard pattern below ("fd 7b ?? a9 …").
FRIDA_MATCH = bytes.fromhex("fd7bbda912345678")

PATTERN_YAML = """\
target:
  crate: rustls
  version: "0.23.37"
  arch: aarch64
  extras:
    crypto: ring
derived_from:
  binary_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
patches:
  - name: test-force-ok
    match: "fd 7b ?? a9 12 34 56 78"
    patch_offset: 4
    patch_bytes: "aa bb cc dd"
"""


def make_pattern_db(db_dir, text: str = PATTERN_YAML, fname: str = "test_aarch64.yaml"):
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / fname).write_text(text)
    return db_dir


def lib_with_match(lib: bytes | None = None) -> bytes:
    """librhttp_like() plus the synthetic pattern bytes at a findable offset."""
    return (lib if lib is not None else librhttp_like()) + b"\x00" + FRIDA_MATCH + b"\x00"
