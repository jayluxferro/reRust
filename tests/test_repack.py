"""Tests for rerust.repack — zip surgery only, no patchelf/NDK needed.

patchelf is mocked (monkeypatching _add_needed): what we're testing here is
marker detection, target selection, zip rebuild semantics (STORED .so, entry
preservation, signature stripping) and report shape — not patchelf itself,
which the emulator smoke test covers against the real target.
"""

import zipfile
from pathlib import Path

import pytest

from rerust.repack import (
    CONNECT_HOOK_MARKER,
    SHIM_NAME,
    has_env_proxy,
    repack_apk,
    shim_is_hook,
)

HYPER_UTIL_SO = b"\x7fELF" + b"A" * 64 + b"ALL_PROXY all_proxy HTTP_PROXY" + b"B" * 32
PLAIN_RUST_SO = b"\x7fELF" + b"C" * 128
FLUTTER_LIKE_SO = b"\x7fELF" + b"D" * 16 + b"HTTPS_PROXY" + b"E" * 16  # must NOT match
# libfjs profile (the embedded-runtime lib): full rustls stack, NO env-proxy plumbing. The
# rustls_error_strings marker string is what fingerprint_bytes keys on.
RUSTLS_NO_ENV_SO = b"\x7fELF" + b"F" * 32 + b"invalid peer certificate: UnknownIssuer" + b"G" * 32
HOOK_SHIM = b"\x7fELF-shim-hook" + CONNECT_HOOK_MARKER + b"bytes"
PLAIN_SHIM = b"\x7fELF-shim-bytes"


@pytest.fixture()
def fake_patchelf(monkeypatch):
    """Record --add-needed calls; no ELF parsing happens in tests."""
    calls = []

    def fake_add(path, tool, lib):
        calls.append(path.name)

    monkeypatch.setattr("rerust.repack._add_needed", fake_add)
    return calls


def make_apk(tmp_path, name="in.apk"):
    apk = tmp_path / name
    with zipfile.ZipFile(apk, "w") as z:
        # one env-proxy lib, one plain lib, one HTTPS_PROXY-only decoy,
        # and the libfjs profile: rustls without env plumbing
        z.writestr("lib/arm64-v8a/librhttp.so", HYPER_UTIL_SO)
        z.writestr("lib/arm64-v8a/libfjs.so", RUSTLS_NO_ENV_SO)
        z.writestr("lib/arm64-v8a/librust_other.so", PLAIN_RUST_SO)
        z.writestr("lib/arm64-v8a/libflutter.so", FLUTTER_LIKE_SO)
        # assets must survive byte-identical with their compression type
        z.writestr("assets/data.json", b'{"x": 1}', compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("resources.arsc", b"\x00" * 32, compress_type=zipfile.ZIP_STORED)
        # stale v1 signature material — must be stripped
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        z.writestr("META-INF/CERT.SF", b"stale")
        z.writestr("META-INF/CERT.RSA", b"stale")
        # non-signature META-INF — must be kept
        z.writestr("META-INF/services/foo.Bar", b"impl")
    return apk


def make_shim(tmp_path, data=PLAIN_SHIM, name="librerust.so"):
    shim = tmp_path / name
    shim.write_bytes(data)
    return shim


def test_has_env_proxy_requires_all_proxy():
    assert has_env_proxy(HYPER_UTIL_SO)
    assert not has_env_proxy(FLUTTER_LIKE_SO)  # HTTPS_PROXY alone is a decoy
    assert not has_env_proxy(PLAIN_RUST_SO)


def test_repack_injects_and_preserves(tmp_path, fake_patchelf):
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path), tmp_path / "out.apk"
    report = repack_apk(apk, shim, out)

    # only the marker-carrying lib is patched; the HTTPS_PROXY decoy is not
    assert report.patched == ["lib/arm64-v8a/librhttp.so"]
    assert fake_patchelf == ["librhttp.so"]
    assert report.shims_added == ["lib/arm64-v8a/" + SHIM_NAME]

    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        # shim shipped next to the patched lib, stored uncompressed
        assert z.getinfo("lib/arm64-v8a/" + SHIM_NAME).compress_type == zipfile.ZIP_STORED
        assert z.read("lib/arm64-v8a/" + SHIM_NAME).startswith(b"\x7fELF-shim")
        assert z.getinfo("lib/arm64-v8a/librhttp.so").compress_type == zipfile.ZIP_STORED
        # patched lib content is what patchelf left on disk (we fake-patched: unchanged)
        assert z.read("lib/arm64-v8a/librhttp.so") == HYPER_UTIL_SO
        # untouched entries: same bytes, same compression method
        assert z.read("assets/data.json") == b'{"x": 1}'
        assert z.getinfo("assets/data.json").compress_type == zipfile.ZIP_DEFLATED
        assert z.getinfo("resources.arsc").compress_type == zipfile.ZIP_STORED
        assert z.read("lib/arm64-v8a/libflutter.so") == FLUTTER_LIKE_SO
        # signatures stripped, other META-INF kept
        assert "META-INF/MANIFEST.MF" not in names
        assert "META-INF/CERT.SF" not in names
        assert "META-INF/CERT.RSA" not in names
        assert "META-INF/services/foo.Bar" in names


def test_also_patch_forces_false_negative(tmp_path, fake_patchelf):
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path), tmp_path / "out.apk"
    report = repack_apk(apk, shim, out, also_patch=["libflutter.so"])
    assert sorted(report.patched) == [
        "lib/arm64-v8a/libflutter.so",
        "lib/arm64-v8a/librhttp.so",
    ]
    with zipfile.ZipFile(out) as z:
        assert "lib/arm64-v8a/" + SHIM_NAME in z.namelist()


def test_repack_is_idempotent(tmp_path, fake_patchelf):
    """Repacking an already-shimmed APK must not duplicate the shim entry, and
    the real _add_needed (patchelf level, verified in the emulator smoke test)
    skips libs whose DT_NEEDED already carries the shim."""
    apk, shim = make_apk(tmp_path), make_shim(tmp_path)
    out1 = tmp_path / "one.apk"
    repack_apk(apk, shim, out1)
    repack_apk(out1, shim, tmp_path / "two.apk")

    with zipfile.ZipFile(tmp_path / "two.apk") as z:
        shim_entries = [n for n in z.namelist() if n.endswith(SHIM_NAME)]
        assert shim_entries == ["lib/arm64-v8a/" + SHIM_NAME]
        assert z.read("lib/arm64-v8a/librhttp.so") == HYPER_UTIL_SO


# ---- M2.5: redirect=all / connect-hook shim ----


class _FakeElf:
    """State + mutation log of the fake patchelf. Paths are keyed per repack
    run's staging dir, so find entries by basename suffix."""

    def __init__(self):
        self.state: dict[str, list[str]] = {}
        self.by_content: dict[bytes, list[str]] = {}
        self.ops: list[tuple[str, str, str]] = []  # (op, lib-basename, dt-lib)

    def by_suffix(self, suffix):
        return next(v for k, v in self.state.items() if k.endswith(suffix))

    def has_suffix(self, suffix):
        return any(k.endswith(suffix) for k in self.state)


@pytest.fixture()
def stateful_patchelf(monkeypatch):
    """In-memory fake of all three patchelf ops, tracking DT_NEEDED per file
    and logging real mutations, so the hook-build ordering fix (shim before
    libc.so) is testable without patchelf.

    State is keyed by file content, not just path: the real patchelf writes
    the new DT_NEEDED into the .so and a second repack pass over its output
    re-reads those bytes, while each pass stages files under a fresh temp dir.
    Content keying reproduces that "already-patched input" semantics, which
    is exactly what the idempotence guard exercises. Files start seeded like
    a real arm64 Rust lib's NEEDED list. The real tool validated on-device
    PREPENDS --add-needed entries; prepend=False models an appending one so
    both repair strategies stay covered."""
    fake = _FakeElf()
    fake.prepend = True
    SEED = ["libdl.so", "libc.so", "libm.so"]

    def needed_for(path):
        data = Path(path).read_bytes()
        if data in fake.by_content:
            return list(fake.by_content[data])
        return list(SEED)

    def dt_needed(path, tool):
        if str(path) in fake.state:
            return list(fake.state[str(path)])
        return needed_for(path)

    def add_needed(path, tool, lib):
        n = fake.state.setdefault(str(path), needed_for(path))
        if lib not in n:
            if fake.prepend:
                n.insert(0, lib)
            else:
                n.append(lib)
            fake.by_content[Path(path).read_bytes()] = list(n)
            fake.ops.append(("add", Path(path).name, lib))

    def remove_needed(path, tool, lib):
        n = fake.state.setdefault(str(path), needed_for(path))
        changed = False
        while lib in n:
            n.remove(lib)
            changed = True
        if changed:
            fake.by_content[Path(path).read_bytes()] = list(n)
            fake.ops.append(("remove", Path(path).name, lib))

    monkeypatch.setattr("rerust.repack._dt_needed", dt_needed)
    monkeypatch.setattr("rerust.repack._add_needed", add_needed)
    monkeypatch.setattr("rerust.repack._remove_needed", remove_needed)
    return fake


def test_shim_is_hook():
    assert shim_is_hook(HOOK_SHIM)
    assert not shim_is_hook(PLAIN_SHIM)


def test_redirect_all_hooks_rustls_without_env(tmp_path, stateful_patchelf):
    """--redirect=all: the libfjs profile (rustls, no ALL_PROXY) gets the hook
    shim; the env-marker lib still reports under `patched`; the Dart decoy is
    still untouched."""
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path, HOOK_SHIM), tmp_path / "out.apk"
    report = repack_apk(apk, shim, out, redirect="all")

    assert report.redirect == "all"
    assert report.patched == ["lib/arm64-v8a/librhttp.so"]
    assert report.hook_patched == ["lib/arm64-v8a/libfjs.so"]
    # both classes got DT_NEEDED; in both, the shim sits before libc.so
    for lib in ("librhttp.so", "libfjs.so"):
        needed = stateful_patchelf.by_suffix(lib)
        assert needed.index(SHIM_NAME) < needed.index("libc.so")
    with zipfile.ZipFile(out) as z:
        assert "lib/arm64-v8a/" + SHIM_NAME in z.namelist()


def test_redirect_env_default_leaves_rustls_no_env_unshimmed(tmp_path, fake_patchelf):
    """Default M1 behavior is unchanged: a rustls lib without the env marker
    gets no shim (trust-patch-only), exactly the pre-M2.5 semantics."""
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path), tmp_path / "out.apk"
    report = repack_apk(apk, shim, out)
    assert report.patched == ["lib/arm64-v8a/librhttp.so"]
    assert report.hook_patched == []


def test_redirect_all_requires_hook_shim(tmp_path, fake_patchelf):
    """A plain shim injected in redirect=all mode would add DT_NEEDED that
    redirects nothing for the hook-target libs — refuse instead."""
    with pytest.raises(ValueError, match="hook"):
        repack_apk(make_apk(tmp_path), make_shim(tmp_path), tmp_path / "o.apk",
                   redirect="all")


def test_hook_shim_lands_before_libc_prepend_patchelf(tmp_path, stateful_patchelf):
    """The load-bearing correctness detail: bionic resolves symbols BFS over
    DT_NEEDED order — if libc.so resolves connect first, the hook silently
    never fires. The patchelf validated on-device PREPENDS --add-needed
    entries, so the plain add already yields the required order with no
    repair churn."""
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path, HOOK_SHIM), tmp_path / "out.apk"
    report = repack_apk(apk, shim, out, redirect="all")

    needed = stateful_patchelf.by_suffix("libfjs.so")
    assert needed.index(SHIM_NAME) < needed.index("libc.so")
    assert needed[0] == SHIM_NAME
    assert report.hook_patched == ["lib/arm64-v8a/libfjs.so"]
    # both shimmed libs get exactly one add each — no repair churn
    assert sorted(stateful_patchelf.ops) == [
        ("add", "libfjs.so", SHIM_NAME),
        ("add", "librhttp.so", SHIM_NAME),
    ]


def test_hook_shim_repaired_when_patchelf_appends(tmp_path, stateful_patchelf):
    """An appending patchelf would bury the shim behind libc.so; the repair
    (remove + re-add libc.so) must push libc behind the shim and verify."""
    stateful_patchelf.prepend = False
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path, HOOK_SHIM), tmp_path / "out.apk"
    report = repack_apk(apk, shim, out, redirect="all")

    needed = stateful_patchelf.by_suffix("libfjs.so")
    assert needed.index(SHIM_NAME) < needed.index("libc.so")
    assert needed[-1] == "libc.so"
    assert report.hook_patched == ["lib/arm64-v8a/libfjs.so"]
    assert ("remove", "libfjs.so", "libc.so") in stateful_patchelf.ops
    assert ("add", "libfjs.so", "libc.so") in stateful_patchelf.ops


def test_hook_reorder_is_idempotent(tmp_path, stateful_patchelf):
    """Second pass over an already-ordered lib: the shim is already present
    and in front, so no repair ops run at all."""
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path, HOOK_SHIM), tmp_path / "out.apk"
    repack_apk(apk, shim, out, redirect="all")
    stateful_patchelf.ops.clear()
    repack_apk(out, shim, tmp_path / "two.apk", redirect="all")
    assert stateful_patchelf.ops == []


def test_hook_shim_in_env_mode_still_ordered(tmp_path, stateful_patchelf):
    """Auto-detection: a hook shim injected via plain env mode still gets the
    order enforcement (it exports connect regardless of the redirect flag)."""
    apk, shim, out = make_apk(tmp_path), make_shim(tmp_path, HOOK_SHIM), tmp_path / "out.apk"
    repack_apk(apk, shim, out)  # redirect defaults to env
    # libfjs was NOT shimmed (env mode) — never staged for patchelf at all
    assert not stateful_patchelf.has_suffix("libfjs.so")
    rhttp = stateful_patchelf.by_suffix("librhttp.so")
    assert rhttp.index(SHIM_NAME) < rhttp.index("libc.so")


def test_bad_redirect_value_rejected(tmp_path, fake_patchelf):
    with pytest.raises(ValueError, match="redirect"):
        repack_apk(make_apk(tmp_path), make_shim(tmp_path), tmp_path / "o.apk",
                   redirect="everything")
