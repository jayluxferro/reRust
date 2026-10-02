"""Synthetic Mach-O builders for the iOS-side tests.

Hand-packed headers (stdlib struct) mirroring what ld produces closely
enough for the surgery code to be exercised honestly: real header field
layout, a __TEXT LC_SEGMENT_64 with one section placed at a page boundary
(the padding window LC insertion writes into), optional load-dylib
commands, and a fat container wrapping thin images at aligned offsets.

Everything the fingerprinter needs (panic paths, markers) rides INSIDE the
section content, same as rodata does in a real slice.
"""

from __future__ import annotations

import struct

from rerust.macho import (
    DYLIB_CMD_FIXED,
    HEADER64_SIZE,
    LC_LOAD_DYLIB,
    LC_SEGMENT_64,
    MH_EXECUTE,
    SECTION64_SIZE,
    SEGMENT64_SIZE,
    THIN64_LE,
)

PAGE = 0x4000  # arm64 ld alignment — also the realistic padding budget

CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_ARM64 = 12 | CPU_ARCH_ABI64
CPU_TYPE_X86_64 = 7 | CPU_ARCH_ABI64


def make_dylib_cmd(install_name: str) -> bytes:
    name = install_name.encode()
    cmdsize = (DYLIB_CMD_FIXED + len(name) + 1 + 7) & ~7
    return (
        struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, DYLIB_CMD_FIXED, 0, 0, 0)
        + name
        + b"\x00" * (cmdsize - DYLIB_CMD_FIXED - len(name))
    )


def make_thin(
    content: bytes = b"\x00" * 16,
    *,
    filetype: int = MH_EXECUTE,
    cputype: int = CPU_TYPE_ARM64,
    cpusubtype: int = 0,
    dylibs: tuple[str, ...] = (),
    section: bool = True,
    section_offset: int = PAGE,
) -> bytes:
    """A thin arm64 image: header + __TEXT segment (+ one section at
    `section_offset`) + optional LC_LOAD_DYLIBs, content after the first page.

    `section=False` or a tight `section_offset` shrinks the padding window —
    that is how the no-budget refusal is tested.
    """
    cmds = []
    nsects = 1 if section else 0
    seg = bytearray(struct.pack("<II", LC_SEGMENT_64, SEGMENT64_SIZE + nsects * SECTION64_SIZE))
    seg += b"__TEXT".ljust(16, b"\x00")
    total = section_offset + max(len(content), 1)
    seg += struct.pack("<QQQQ", 0, total, 0, total)  # vmaddr/vmsize/fileoff/filesize
    seg += struct.pack("<ii", 5, 5)  # maxprot/initprot r-x
    seg += struct.pack("<II", nsects, 0)  # nsects, flags
    if section:
        s = bytearray()
        s += b"__text".ljust(16, b"\x00")
        s += b"__TEXT".ljust(16, b"\x00")
        s += struct.pack("<QQ", section_offset, len(content))  # addr, size
        # offset, align, reloff, nreloc, flags, reserved1..3 — all 8 u32s
        s += struct.pack("<IIIIIIII", section_offset, 2, 0, 0, 0, 0, 0, 0)
        seg += s
    cmds.append(bytes(seg))
    for d in dylibs:
        cmds.append(make_dylib_cmd(d))

    ncmds = len(cmds)
    sizeofcmds = sum(len(c) for c in cmds)
    hdr = bytearray(
        struct.pack(
            "<IIIIIIII",
            0xFEEDFACF,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            0x00200085,  # MH_PIE | NOUNDEFS-ish, value irrelevant here
            0,
        )
    )
    assert len(hdr) == HEADER64_SIZE
    blob = bytes(hdr) + b"".join(cmds)
    pad = b"\x00" * (section_offset - len(blob)) if section_offset > len(blob) else b""
    return blob + pad + content


def make_fat(images: list[bytes], *, fat64: bool = False) -> bytes:
    """Wrap thin images in a big-endian fat header at page-aligned offsets."""
    offs = []
    body = b""
    body_off = 8 + len(images) * (32 if fat64 else 20)  # where body starts in the file
    cursor = body_off
    for img in images:
        cursor = (cursor + PAGE - 1) & ~(PAGE - 1)
        offs.append((cursor, len(img)))
        body += b"\x00" * (cursor - body_off - len(body)) + img
        cursor += len(img)
    magic = 0xCAFEBABF if fat64 else 0xCAFEBABE
    hdr = struct.pack(">II", magic, len(images))
    for (off, size), img in zip(offs, images):
        cputype = struct.unpack_from("<I", img, 4)[0]
        cpusubtype = struct.unpack_from("<I", img, 8)[0]
        if fat64:
            hdr += struct.pack(">IIQQII", cputype, cpusubtype, off, size, 12, 0)
        else:
            hdr += struct.pack(">IIIII", cputype, cpusubtype, off, size, 12)
    return hdr + body


def rustls_slice_strings(
    rustls: str = "0.23.45",
    *,
    webpki_roots: bool = True,
    env_proxy: bool = True,
) -> bytes:
    """Section content carrying the fingerprint families the pattern flow keys on."""
    reg = "index.crates.io-6f17d22bba15001f"
    parts = [
        f"/home/builder/.cargo/registry/src/{reg}/rustls-{rustls}/src/verify.rs".encode(),
        f"/home/builder/.cargo/registry/src/{reg}/reqwest-0.12.28/src/async_impl/client.rs".encode(),
        b"invalid peer certificate: ",
    ]
    if env_proxy:
        parts.append(b"ALL_PROXY all_proxy HTTPS_PROXY https_proxy")
    if webpki_roots:
        parts += [b"DigiCert Global Root CA", b"ISRG Root X1"]
    return b"\x00".join(parts) + b"\x00"
