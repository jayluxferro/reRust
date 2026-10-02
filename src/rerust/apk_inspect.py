"""APK-level inspection: walk the archive, select native libs, compose the report.

:func:`inspect_apk` builds the document printed by ``rerust inspect --json``.
Accepts an APK/zip (walks ``lib/<abi>/*.so`` entries) or a bare native-library
file (handy when analyzing an extracted ``.so``, as in docs/research/).

## ``--json`` document schema (stable within 0.x)

New keys may be added; existing keys never change shape or meaning.

.. code-block:: json

    {
      "apk": "some_app_v8a.apk",
      "libs": {
        "lib/arm64-v8a/librhttp.so": {
          "is_rust": true,
          "crates": [["rustls", "0.23.37"]],
          "markers": {
            "rustls_error_strings": true,
            "env_proxy_support": true,
            "connect_tunnel": true,
            "socks_support": true,
            "reqwest": true,
            "hyper_util": true,
            "mozilla_root_anchors": true
          },
          "tls_stack": "rustls+ring",
          "trust_flavor": "webpki-roots",
          "http3": true,
          "env_proxy": true,
          "relevance": "primary",
          "notes": ["..."]
        }
      }
    }

- ``apk``: basename of the inspected file.
- ``crates``: sorted, de-duplicated ``[name, version]`` pairs extracted from
  panic-location registry paths (exact versions, survive stripping).
- ``markers``: whole-binary string evidence; every key always present (booleans).
- ``tls_stack``: ``"rustls"`` / ``"rustls+ring"`` / ``"rustls+aws-lc"`` /
  ``"native-tls"`` / ``"openssl"`` / ``"boring"`` / ``"rquest"`` / null.
- ``trust_flavor``: ``"native-certs"`` (system CA install works),
  ``"webpki-roots"`` (compiled-in anchors, binary patch required), null
  (custom verifier / unknown).
- ``relevance``: ``"primary"`` = networking core (TLS stack or env-proxy
  markers present) — the interception target; ``"informational"`` = Rust lib
  without networking evidence (app glue, storage, media).
- Non-Rust libs are omitted *unless* they carry the Mozilla anchor set — such a
  lib is likely a Rust TLS core whose panic paths were fully optimized out
  (``is_rust`` stays false, honestly). Only libs with any evidence are listed.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .fingerprint import analyze, fingerprint_bytes

# v0 semantics kept: exactly lib/<abi>/<name>.so — no deeper nesting, no
# non-lib paths (assets/, META-INF/, directory entries all fail the match).
NATIVE_LIB = re.compile(r"lib/[^/]+/[^/]+\.so\Z")


def iter_native_libs(names) -> list[str]:
    """Zip-entry names that are native libraries (``lib/<abi>/<name>.so``)."""
    return [n for n in names if NATIVE_LIB.fullmatch(n)]


# Magics that mark a file as a native lib we can fingerprint single-file.
# ELF is the Android case; Mach-O is here for the iOS successor (SPEC: v2).
NATIVE_MAGICS = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xc3\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def _is_native_lib(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(4) in {m[:4] for m in NATIVE_MAGICS}


def read_native_libs(path: str | Path) -> dict[str, bytes]:
    """Every native lib candidate as {zip_entry_name: bytes}.

    Zip/APK input walks ``lib/<abi>/*.so``; a bare native lib maps its file
    name to its bytes. Raises ValueError for anything else.
    """
    path = Path(path)
    if path.is_file() and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            return {n: z.read(n) for n in iter_native_libs(z.namelist())}
    if path.is_file() and _is_native_lib(path):
        return {path.name: path.read_bytes()}
    raise ValueError(f"{path} is neither a zip/APK nor a native library")


def inspect_apk(path: str | Path) -> dict:
    """Fingerprint every relevant native lib; see module docstring for schema.

    Raises ValueError for input that is neither a zip/APK nor a native lib.
    """
    libs = {}
    for name, data in read_native_libs(path).items():
        report = analyze(fingerprint_bytes(data))
        if _reportable(report):
            libs[name] = report
    return {"apk": Path(path).name, "libs": libs}


def _reportable(report: dict) -> bool:
    # A lib with Mozilla anchors but no rustc/crate paths is likely a Rust TLS
    # core with panic paths optimized out — keep it, with is_rust honestly false.
    return report["is_rust"] or report["markers"]["mozilla_root_anchors"]
