"""Frida agent emitter (SPEC M2) — `rerust frida` generates the runtime script.

v1 is an emitter only: fingerprint the target (apk_inspect), select trust
patches (trust.py — the same fingerprint gating as the repack pipeline), and
render a self-contained Frida JS agent doing three jobs:

1. **ENV-PROXY (redirection).** Hooks libc ``getenv`` and answers the proxy
   variables (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY, upper+lowercase) with the
   configured proxy and clears NO_PROXY/no_proxy (Android never sets them; a
   stale value would silently exclude hosts). hyper-util reads these when a
   connector is built and CACHES the result — the hook must land before the
   app's first Client build, i.e. SPAWN MODE (`frida -f <pkg> -l agent.js`).
   A late attach still patches + observes, but redirection may be a no-op.

2. **TRUST PATCH (T1).** For every lib where the pattern DB matched at
   EXACTLY ONE site, embed that site. The offset is found here by scanning the
   shipped lib bytes with trust.find_sites — NOT read from the yaml (the
   recorded offset is valid only for the DB's own source binary; re-scanning
   keeps the D4 "one site or refuse" invariant per build). Address world: on
   the target class (Android arm64 .so, LOAD1 vaddr == file offset, bias 0 —
   see the patterns yaml header) file offsets double as runtime vaddrs, so
   ``module_base + offset`` is the patch site. The agent's seatbelt is the
   same tri-state trust.py uses on re-repacks: read the site first; equal to
   the PATCH bytes → already applied; equal to the ORIGINAL bytes → apply;
   anything else → log loudly and refuse (wrong-world offsets fail safe).

3. **OBSERVATION.** Hooks libc ``connect`` and logs outbound IPv4/IPv6
   destinations (deduped, capped) tagged ``reRust``. Logging only — traffic
   rewriting is the native shim's job (M1).

The emitted script uses only stable Frida core (Interceptor, Memory, Process,
Module) so it runs under frida-server attach and gadget alike.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from . import trust
from .fingerprint import analyze, fingerprint_bytes
from .trust import PatternEntry, find_sites, select_pattern

# yaml arch (trust.ABI_ARCH values) -> Frida's Process.arch naming.
FRIDA_ARCH = {"aarch64": "arm64", "armv7": "arm", "x86_64": "x64"}

PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}


@dataclass(frozen=True)
class PatchSpec:
    """One runtime patch embedded into the agent script."""

    module: str  # module basename as Frida sees it at runtime
    lib_path: str  # zip entry the bytes came from (provenance)
    frida_arch: str  # Process.arch gate for the patch
    pattern_name: str
    db_file: str
    source_sha256: str
    offset: int  # match site + patch_offset, as a file offset (== vaddr, bias 0)
    orig_bytes: bytes  # pre-patch bytes — the runtime seatbelt reads these
    patch_bytes: bytes


def validate_proxy(url: str) -> str:
    """Reject obviously-broken --proxy values early (scheme + host required)."""
    parsed = urlparse(url)
    if parsed.scheme not in PROXY_SCHEMES or not parsed.netloc:
        raise ValueError(f"proxy must be a URL like http://host:port (got {url!r})")
    return url


def build_patches(
    libs: dict[str, bytes], entries: list[PatternEntry]
) -> tuple[list[PatchSpec], list[str], bool]:
    """Select + verify trust patches against the actual shipped lib bytes.

    Returns (specs, warnings, saw_rust). Selection is per-lib: fingerprint ->
    select_pattern -> find_sites must yield exactly one site, else the lib is
    skipped with a warning (the agent stays env+observe for it). Non-Rust libs
    are skipped silently — but a rustls core with no DB entry is called out.
    """
    specs: list[PatchSpec] = []
    warnings: list[str] = []
    saw_rust = False
    for lib_path, data in sorted(libs.items()):
        fp = fingerprint_bytes(data)
        if not fp["is_rust"]:
            continue
        saw_rust = True
        abi = lib_path.split("/")[1] if "/" in lib_path else ""
        arch = trust.ABI_ARCH.get(abi)
        if arch is None:
            # Bare .so input: no ABI in the path, so the arch-gated DB cannot
            # be consulted honestly — say so rather than guess.
            warnings.append(f"{lib_path}: bare lib, ABI unknown — trust patching skipped")
            continue
        analyzed = analyze(fp)
        entry = select_pattern(entries, fp["crates"], arch, analyzed["tls_stack"])
        if entry is None:
            if analyzed["tls_stack"] and "rustls" in analyzed["tls_stack"]:
                warnings.append(
                    f"{lib_path}: rustls core, no pattern DB entry for this fingerprint — trust patch skipped"
                )
            continue
        sites = find_sites(data, entry.match_text)
        if len(sites) != 1:
            warnings.append(
                f"{lib_path}: pattern {entry.name} matched {len(sites)} sites ({entry.db_file}) — "
                "refusing to embed (D4: one site or refuse)"
            )
            continue
        site = sites[0] + entry.patch_offset
        orig = data[site : site + len(entry.patch_bytes)]
        if len(orig) != len(entry.patch_bytes):
            warnings.append(f"{lib_path}: patch site at {hex(site)} runs past end of lib — skipped")
            continue
        specs.append(
            PatchSpec(
                module=lib_path.rsplit("/", 1)[-1],
                lib_path=lib_path,
                frida_arch=FRIDA_ARCH.get(arch, arch),
                pattern_name=entry.name,
                db_file=entry.db_file,
                source_sha256=entry.source_sha256,
                offset=site,
                orig_bytes=orig,
                patch_bytes=entry.patch_bytes,
            )
        )
    return specs, warnings, saw_rust


# --- JS rendering -------------------------------------------------------------
#
# The agent body is a fixed template; only the __TOKEN__ holes are filled.
# Bytes go in as JSON int arrays (JSON cannot express 0x literals; offsets are
# rendered as JS hex literals by hand below). String values pass through
# json.dumps so a hostile proxy string cannot break out of a JS literal.


def _js_patch(p: PatchSpec) -> str:
    return (
        '  { module: %s, name: %s, arch: "%s",\n'
        "    offset: 0x%x,                    // file offset == vaddr (LOAD1 bias 0)\n"
        "    orig: %s,\n"
        "    patch: %s,\n"
        "    from: %s }"
        % (
            json.dumps(p.module),
            json.dumps(p.pattern_name),
            p.frida_arch,
            p.offset,
            json.dumps(list(p.orig_bytes)),
            json.dumps(list(p.patch_bytes)),
            json.dumps(f"{p.db_file}, derived on sha256 {p.source_sha256}"),
        )
    )


def emit_script(target: str, proxy: str, patches: list[PatchSpec], warnings: list[str]) -> str:
    """Render the agent. `warnings` are surfaced both as a header note and as
    runtime console.warn lines (the no-pattern case warns in-script too)."""
    summary = (
        f"{len(patches)} patch(es)"
        + (f": {', '.join(p.pattern_name for p in patches)}" if patches else " — env+observe only")
    )
    header = (
        "/**\n"
        " * reRust runtime agent (SPEC M2) — generated by `rerust frida`; do not edit by hand.\n"
        " *\n"
        f" * target  : {target}\n"
        f" * proxy   : {proxy}\n"
        f" * patches : {summary}\n"
        " *\n"
        " * SPAWN MODE REQUIRED: hyper-util caches proxy env when the first Client is\n"
        " * built — run `frida -f <package> -l this.js` so the getenv hook lands first.\n"
        " * Late attach keeps the trust patch + connect observer, but redirection may\n"
        " * be a no-op for Clients already built.\n"
    )
    for w in warnings:
        header += f" *\n * ! {w}\n"
    header += " */\n\n"

    body = _AGENT_TEMPLATE
    body = body.replace("__PROXY__", json.dumps(proxy))
    body = body.replace("__WARNINGS__", json.dumps(warnings, indent=2))
    body = body.replace("__PATCHES__", "\n".join(_js_patch(p) for p in patches) or "")
    return header + body


_AGENT_TEMPLATE = r"""
'use strict';

// --- configuration (filled by rerust frida) ----------------------------------

var PROXY = __PROXY__;

// Setup problems found at generation time — also printed at runtime.
var SETUP_WARNINGS = __WARNINGS__;

// Each entry: module to find, Process.arch gate, patch site (base + offset),
// orig bytes (what must be there NOW) and patch bytes (what to write).
var PATCHES = [
__PATCHES__
];

// --- plumbing ----------------------------------------------------------------

function log(msg)  { console.log("[reRust] " + msg); }
function warn(msg) { console.warn("[reRust] " + msg); }

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// --- 1. env-proxy redirection (getenv hook) ----------------------------------
// hyper-util builds the proxy config from these variables when a Client's
// connector is constructed and caches it — hence the spawn-mode requirement
// in the header. NO_PROXY is cleared so nothing can silently exclude hosts.

function installEnvProxyHook() {
  var getenvAddr = Module.findExportByName(null, "getenv");
  if (getenvAddr === null) { warn("getenv not found — env-proxy hook NOT installed"); return; }

  var overrides = {};
  ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"].forEach(function (k) {
    overrides[k] = Memory.allocUtf8String(PROXY);
    overrides[k.toLowerCase()] = Memory.allocUtf8String(PROXY);
  });
  overrides["NO_PROXY"] = null;
  overrides["no_proxy"] = null;
  var NULLP = ptr("0");

  var announced = {};
  Interceptor.attach(getenvAddr, {
    onEnter: function (args) {
      this.key = args[0].isNull() ? null : args[0].readUtf8String();
    },
    onLeave: function (retval) {
      if (this.key === null || !(this.key in overrides)) return;
      var v = overrides[this.key];
      retval.replace(v === null ? NULLP : v);
      if (!announced[this.key]) {
        announced[this.key] = true;
        log("env override: " + this.key + " -> " + (v === null ? "<cleared>" : PROXY));
      }
    }
  });
  log("env-proxy hook installed on getenv (spawn mode required — see header)");
}

// --- 2. trust patch (T1) ------------------------------------------------------
// Same tri-state as the repack pipeline's idempotence check: write only over
// the recorded ORIGINAL bytes; PATCH bytes already present -> done; anything
// else -> refuse loudly. Modules may load after spawn, so retries are driven
// by the dynamic loader hooks.

function applyPatch(p, base) {
  var site = base.add(p.offset);
  var cur;
  try {
    cur = new Uint8Array(site.readByteArray(p.patch.length));
  } catch (e) {
    p._state = "unreadable";
    warn(p.name + ": site unreadable at " + p.module + "+0x" + p.offset.toString(16) + ": " + e);
    return;
  }
  if (bytesEqual(cur, p.patch)) {
    p._state = "applied";
    log(p.name + ": already applied at " + p.module + "+0x" + p.offset.toString(16));
    return;
  }
  if (!bytesEqual(cur, p.orig)) {
    p._state = "mismatch";
    warn(p.name + ": bytes at " + p.module + "+0x" + p.offset.toString(16) +
         " differ from the recorded original — build drift? NOT patching");
    return;
  }
  Memory.patchCode(site, p.patch.length, function (code) { code.writeByteArray(p.patch); });
  p._state = "applied";
  log(p.name + ": patched " + p.module + "+0x" + p.offset.toString(16));
}

function tryApplyPatches() {
  var anyPending = false;
  PATCHES.forEach(function (p) {
    if (p._state !== "pending") return;
    if (Process.arch !== p.arch) {
      p._state = "skipped-arch";
      warn(p.name + ": skipped — process arch " + Process.arch + " != " + p.arch);
      return;
    }
    var m = Process.findModuleByName(p.module);
    if (m === null) { anyPending = true; return; }
    applyPatch(p, m.base);
  });
  return anyPending;
}

function installTrustPatches() {
  if (PATCHES.length === 0) {
    warn("no trust patch embedded for this build — env+observe only (no pattern DB match)");
    return;
  }
  tryApplyPatches();
  ["android_dlopen_ext", "dlopen"].forEach(function (fn) {
    var addr = Module.findExportByName(null, fn);
    if (addr === null) return;
    Interceptor.attach(addr, {
      onLeave: function () {
        // Retry after the loader returns; coalesce via the timer.
        if (installTrustPatches._t) return;
        installTrustPatches._t = setTimeout(function () {
          installTrustPatches._t = null;
          tryApplyPatches();
        }, 0);
      }
    });
  });
}

// --- 3. connect() observer -----------------------------------------------------
// LOGGING ONLY — showing what the app dials; rewriting is the native shim's job.

function installConnectObserver() {
  var addr = Module.findExportByName(null, "connect");
  if (addr === null) { warn("connect not found — observer NOT installed"); return; }
  var seen = {};
  var seenCount = 0;
  var CAP = 1024;
  var capAnnounced = false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      var sa = args[1];
      var len = args[2].toInt32();
      if (sa.isNull() || len < 8) return;
      var family = sa.readU16();          // Linux: sa_family_t at offset 0, host order
      var host = null, port = 0;
      if (family === 2) {                 // AF_INET: port BE at +2, addr at +4
        port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        host = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." + sa.add(6).readU8() + "." + sa.add(7).readU8();
      } else if (family === 10) {         // AF_INET6: port BE at +2, 16B addr at +8
        port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        var g = [];
        for (var i = 0; i < 16; i += 2) g.push(sa.add(8 + i).readU8().toString(16));
        host = g.join(":");
      } else {
        return;
      }
      var key = host + ":" + port;
      if (seen[key] || capAnnounced) return;
      if (seenCount >= CAP) {
        capAnnounced = true;
        warn("destination cap (" + CAP + ") reached — new destinations will not be logged");
        return;
      }
      seen[key] = true;
      seenCount++;
      log("connect -> " + key);
    }
  });
  log("connect observer installed (logging only, deduped, cap " + CAP + ")");
}

// --- bootstrap ----------------------------------------------------------------

log("agent up — arch=" + Process.arch + ", proxy=" + PROXY);
SETUP_WARNINGS.forEach(function (w) { warn("setup: " + w); });
installEnvProxyHook();
installConnectObserver();
installTrustPatches();
"""
