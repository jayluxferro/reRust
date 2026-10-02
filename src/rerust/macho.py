"""Minimal Mach-O reader/injector for iOS repacking — stdlib struct only.

The iOS analog of what patchelf does for Android: locate the slices of a
Mach-O (thin or fat), read load commands, and add one ``LC_LOAD_DYLIB`` so
dyld loads the reRust shim next to the app's Rust core. No LIEF, no optool
dependency — the surgery is small enough that its correctness is checkable
against hand-built headers in the test suite.

## Why insertion is padding-only

Every load command lives in the header area: ``mach_header_64`` (32 bytes)
followed by ``ncmds`` variable-size commands, followed by the first
section's file data. Xcode's ld page-aligns that first section (``__text``
starts at 0x4000 on arm64), leaving kilobytes of zero padding after the
last command. An LC command can be written into that padding WITHOUT moving
any other byte of the file: only the header's ``ncmds``/``sizeofcmds``
change, so every section offset, symbol table offset and the
code-signature blob offset stay valid. This is the same behavior as
optool/insert_dylib on a healthy image; when the padding is too small we
refuse loudly instead of shifting file offsets (a full offset rewrite
touches every load command and is where silent corruption lives — out of
scope on purpose).

The stale code signature that results is expected and handled by the
caller: the blob is rebuilt by ``codesign -f -s -`` after the rewrite (see
repack_ipa.py). The LC_CODE_SIGNATURE command itself keeps its dataoff —
codesign re-uses the slot.

## Fat binaries

A fat (universal) file is a big-endian ``fat_header`` + ``fat_arch``
entries pointing at embedded thin images. Everything here works per-slice:
:func:`slices` enumerates the embedded thin images (with their file
offsets), surgery runs on extracted slice bytes, and :func:`patch_slice`
splices equal-size results back. LC insertion is padding-only, so slice
size never changes — no fat-header relocation is ever needed.

## What is deliberately NOT supported

- 32-bit thin images as *surgery* targets (fingerprinting in
  apk_inspect.py is magic-agnostic and string-scans anything; injection
  refuses non-64 slices — iOS targets are arm64/arm64e/x86_64 in practice).
- Byte-swapped (``MH_CIGAM_*``) images: never produced on-disk by Apple
  toolchains; refused rather than half-supported.
- Header rewrites: if the padding budget is too small, refuse (above).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# --- magics -------------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF  # on disk (little-endian slices): CF FA ED FE
FAT_MAGIC = 0xCAFEBABE  # big-endian on disk: CA FE BA BE
FAT_MAGIC_64 = 0xCAFEBABF

THIN64_LE = b"\xcf\xfa\xed\xfe"  # every arm64/x86_64 slice Apple toolchains emit
THIN32_LE = b"\xce\xfa\xed\xfe"
FAT_BE = b"\xca\xfe\xba\xbe"
FAT64_BE = b"\xca\xfe\xba\xbf"

MACHO_MAGICS = (THIN64_LE, THIN32_LE, FAT_BE, FAT64_BE)

CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_ARM = 12
CPU_TYPE_X86 = 7
CPU_SUBTYPE_ARM64E = 0x02000000

# --- load commands / filetypes --------------------------------------------------

LC_REQ_DYLIB = 0x80000000
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLIB
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLIB

DYLIB_CMDS = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB)

MH_EXECUTE = 0x2
MH_DYLIB = 0x6

HEADER64_SIZE = 32  # mach_header_64
SEGMENT64_SIZE = 72  # segment_command_64, sections follow
SECTION64_SIZE = 80  # section_64; file offset field at +48
DYLIB_CMD_FIXED = 24  # dylib_command fixed part; install-name string follows
LINKEDIT_CMD_SIZE = 16  # linkedit_data_command (code signature etc.)

LC_SIZE = 8  # cmd + cmdsize, common to every load command


class MachOError(RuntimeError):
    """Loud failure — a refused surgery must never half-apply."""


def is_macho(data: bytes) -> bool:
    return data[:4] in MACHO_MAGICS


# --- containers ---------------------------------------------------------------


@dataclass(frozen=True)
class Slice:
    """One thin image inside a Mach-O file (offset 0 for a thin file)."""

    arch: str  # "arm64", "x86_64", ... — the `lipo -info` spelling
    cputype: int
    offset: int  # file offset of the mach_header_64
    size: int
    filetype: int


@dataclass(frozen=True)
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


def arch_name(cputype: int, cpusubtype: int) -> str:
    if cputype == (CPU_TYPE_ARM | CPU_ARCH_ABI64):
        return "arm64e" if (cpusubtype & 0xFF000000) == CPU_SUBTYPE_ARM64E else "arm64"
    if cputype == (CPU_TYPE_X86 | CPU_ARCH_ABI64):
        return "x86_64"
    if cputype == CPU_TYPE_ARM:
        return {9: "armv7", 11: "armv7s"}.get(cpusubtype & 0x00FFFFFF, "arm")
    if cputype == CPU_TYPE_X86:
        return "i386"
    return f"cputype-0x{cputype:x}"


def slices(data: bytes) -> list[Slice]:
    """Every thin image in `data` (one entry for a thin file, N for a fat).

    Raises MachOError for byte-swapped or otherwise unhandleable containers —
    fingerprint callers can still string-scan such blobs, but surgery must
    not guess.
    """
    magic = data[:4]
    if magic in (FAT_BE, FAT64_BE):
        out = []
        nfat = struct.unpack_from(">I", data, 4)[0]
        for i in range(nfat):
            base = 8 + i * (32 if magic == FAT64_BE else 20)
            if magic == FAT64_BE:
                cputype, cpusubtype, off, size = struct.unpack_from(">IIQQ", data, base)
            else:
                cputype, cpusubtype, off, size = struct.unpack_from(">IIII", data, base)
            out.append(
                Slice(
                    _slice_arch(data, off),
                    cputype,
                    off,
                    size,
                    _filetype(data, off),
                )
            )
        return out
    if magic == THIN64_LE:
        cputype, cpusubtype, filetype = struct.unpack_from("<III", data, 4)
        return [Slice(arch_name(cputype, cpusubtype), cputype, 0, len(data), filetype)]
    raise MachOError(
        f"unsupported Mach-O container magic {magic!r} — only little-endian "
        f"64-bit thin images and big-endian fat containers are handled"
    )


def _slice_arch(data: bytes, off: int) -> str:
    if data[off : off + 4] != THIN64_LE:
        raise MachOError(f"fat slice at 0x{off:x} is not a little-endian 64-bit image")
    cputype, cpusubtype = struct.unpack_from("<II", data, off + 4)
    return arch_name(cputype, cpusubtype)


def _filetype(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off + 12)[0]


# --- per-slice parsing ---------------------------------------------------------


def header(data: bytes, off: int = 0) -> tuple[int, int, int]:
    """(ncmds, sizeofcmds, filetype) of the thin image at `off`."""
    _ft = struct.unpack_from("<I", data, off + 12)[0]
    ncmds, sizeofcmds = struct.unpack_from("<II", data, off + 16)
    return ncmds, sizeofcmds, _ft


def load_commands(data: bytes, off: int = 0):
    """Yield (cmd, cmdsize, cmd_offset) for the image at `off`."""
    ncmds, sizeofcmds, _ft = header(data, off)
    p = off + HEADER64_SIZE
    end = p + sizeofcmds
    if end > len(data):
        raise MachOError(f"load commands at 0x{off:x} claim {sizeofcmds} bytes past EOF")
    for _ in range(ncmds):
        if p + LC_SIZE > end:
            raise MachOError(f"truncated load command at 0x{p:x}")
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmdsize < LC_SIZE or p + cmdsize > end:
            raise MachOError(f"bad cmdsize {cmdsize} at 0x{p:x}")
        yield cmd, cmdsize, p
        p += cmdsize


def segments(data: bytes, off: int = 0) -> dict[str, Segment]:
    """LC_SEGMENT_64 commands by segname (first wins — names are unique here)."""
    out: dict[str, Segment] = {}
    for cmd, cmdsize, p in load_commands(data, off):
        if cmd != LC_SEGMENT_64 or cmdsize < SEGMENT64_SIZE:
            continue
        segname = data[p + 8 : p + 24].split(b"\x00", 1)[0].decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, p + 24)
        out.setdefault(segname, Segment(segname, vmaddr, vmsize, fileoff, filesize))
    return out


def dylib_paths(data: bytes, off: int = 0, cmds: tuple[int, ...] = DYLIB_CMDS) -> list[str]:
    """Install names of the LC_*DYLIB commands (load order preserved)."""
    out = []
    for cmd, cmdsize, p in load_commands(data, off):
        if cmd not in cmds or cmdsize < DYLIB_CMD_FIXED:
            continue
        name_off = struct.unpack_from("<I", data, p + 8)[0]
        if not DYLIB_CMD_FIXED <= name_off <= cmdsize:
            raise MachOError(f"dylib name offset {name_off} outside cmdsize {cmdsize} at 0x{p:x}")
        raw = data[p + name_off : p + cmdsize].split(b"\x00", 1)[0]
        out.append(raw.decode("utf-8", "replace"))
    return out


def has_dylib(data: bytes, off: int, name: str) -> bool:
    return name in dylib_paths(data, off)


def vaddr_to_file(data: bytes, off: int, vaddr: int) -> int | None:
    """File offset for a vmaddr via the LC_SEGMENT_64 table.

    The Android pattern DB could assume vaddr == file offset on its loads;
    Mach-O never grants that (``__TEXT`` happens to map vmaddr 0/fileoff 0,
    but ``__DATA``/``__LINKEDIT`` drift immediately). Patterns derived for
    ELF entries must re-derive their addresses here — one more reason iOS
    entries live in their own yaml despite the codegen overlap. Returns
    None for unmapped addresses and zero-fill tails (no file bytes exist).
    """
    for seg in segments(data, off).values():
        if seg.vmaddr <= vaddr < seg.vmaddr + seg.vmsize:
            delta = vaddr - seg.vmaddr
            if delta >= seg.filesize:
                return None
            return seg.fileoff + delta
    return None


# --- surgery -------------------------------------------------------------------


def content_start(data: bytes, off: int = 0) -> int:
    """First SLICE-RELATIVE offset at/after the header that holds referenced data.

    The injection budget is everything between header end and this offset —
    ld leaves that window zeroed as alignment padding. Computed from
    sections' own file offsets (NOT segment vmaddrs — see vaddr_to_file for
    why the two must not be conflated) plus linkedit blob offsets.

    Frame contract: section/dataoff fields inside a Mach-O are relative to
    the START OF THE SLICE (they are only file-absolute in a thin file,
    where the slice starts at 0) — so this returns slice-relative offsets
    too, and callers must not mix them with absolute fat-file offsets.
    """
    starts = []
    hdr_end = HEADER64_SIZE + header(data, off)[1]
    for cmd, cmdsize, p in load_commands(data, off):
        if cmd == LC_SEGMENT_64 and cmdsize >= SEGMENT64_SIZE:
            nsects = struct.unpack_from("<I", data, p + 64)[0]
            for i in range(nsects):
                s = p + SEGMENT64_SIZE + i * SECTION64_SIZE  # absolute: for READS
                if s + SECTION64_SIZE > p + cmdsize:
                    break  # malformed nsects — the load_command walk will not
                sect_off = struct.unpack_from("<I", data, s + 48)[0]  # VALUE is slice-relative
                if sect_off:
                    starts.append(sect_off)
        elif cmd == LC_CODE_SIGNATURE and cmdsize >= LINKEDIT_CMD_SIZE:
            dataoff = struct.unpack_from("<I", data, p + 8)[0]
            if dataoff:
                starts.append(dataoff)
    if not starts:
        return len(data) - off
    first = min(starts)
    if first < hdr_end:
        raise MachOError(
            f"a section/linkedit offset (0x{first:x}) lands inside the load-command "
            f"area (ends 0x{hdr_end:x}) — parse is wrong or the image is hostile; refusing"
        )
    return first


def make_load_dylib(install_name: str, *, weak: bool = False) -> bytes:
    """An LC_LOAD_DYLIB (or weak) command for `install_name`, 8-byte aligned."""
    if not install_name or "\x00" in install_name:
        raise MachOError(f"bad install name {install_name!r}")
    name = install_name.encode()
    cmdsize = (DYLIB_CMD_FIXED + len(name) + 1 + 7) & ~7
    cmd = LC_LOAD_WEAK_DYLIB if weak else LC_LOAD_DYLIB
    # name.offset = 24 (string starts right after the fixed part); timestamps
    # and versions are 0 — dyld ignores them for injected shims.
    return (
        struct.pack("<IIIIII", cmd, cmdsize, DYLIB_CMD_FIXED, 0, 0, 0)
        + name
        + b"\x00" * (cmdsize - DYLIB_CMD_FIXED - len(name))
    )


def insert_load_dylib(data: bytes, off: int, install_name: str, *, weak: bool = False) -> bytes:
    """The image at `off` with one more LC_*DYLIB; all other bytes unchanged.

    Writes the new command into the header padding and bumps ncmds/sizeofcmds
    — see the module docstring for why nothing else may move. Idempotence is
    the caller's concern (repack_ipa checks has_dylib first, mirroring the
    DT_NEEDED duplicate guard in repack.py).
    """
    if data[off : off + 4] != THIN64_LE:
        raise MachOError("insert_load_dylib: only little-endian 64-bit images")
    ncmds, sizeofcmds, filetype = header(data, off)
    if filetype not in (MH_EXECUTE, MH_DYLIB):
        raise MachOError(
            f"filetype 0x{filetype:x} is neither an executable nor a dylib — refusing injection"
        )
    new_cmd = make_load_dylib(install_name, weak=weak)
    hdr_end = HEADER64_SIZE + sizeofcmds  # slice-relative
    budget = content_start(data, off) - hdr_end
    if len(new_cmd) > budget:
        raise MachOError(
            f"no header padding for a {len(new_cmd)}-byte LC_LOAD_DYLIB "
            f"(budget {budget} B before the first section) — this image needs "
            f"a header rewrite, which this injector refuses by design"
        )
    write_at = off + hdr_end
    window = data[write_at : write_at + len(new_cmd)]
    if set(window) != {0}:
        raise MachOError(
            f"the {len(new_cmd)}-byte window after the load commands is not zero "
            f"padding — writing would corrupt unknown data; refusing"
        )
    out = bytearray(data)
    # mach_header_64: magic@0 cputype@4 cpusubtype@8 filetype@12 ncmds@16
    # sizeofcmds@20 flags@24 reserved@28. Only ncmds/sizeofcmds ever change;
    # everything else in the file is offset-addressed and stays put.
    struct.pack_into("<II", out, off + 16, ncmds + 1, sizeofcmds + len(new_cmd))
    out[write_at : write_at + len(new_cmd)] = new_cmd
    return bytes(out)


def patch_slice(data: bytes, slice_: Slice, new_slice_bytes: bytes) -> bytes:
    """Splice equal-size slice content back into a (thin or fat) file."""
    if len(new_slice_bytes) != slice_.size:
        raise MachOError(
            f"slice {slice_.arch} changed size ({slice_.size} -> {len(new_slice_bytes)}); "
            f"fat headers would dangle — size-preserving surgery only"
        )
    return data[: slice_.offset] + new_slice_bytes + data[slice_.offset + slice_.size :]


def map_slices(data: bytes, fn) -> bytes:
    """Rebuild `data` with fn applied to every slice's bytes; fn may RESIZE.

    The growth-capable counterpart to patch_slice: a thin image is rewritten
    directly; a fat container gets its header rebuilt — offsets recomputed
    from each entry's original align field, slice order kept. This exists
    because the LC_LOAD_DYLIB injector grows a slice by its command size and
    a fat file has no free-space bookkeeping to absorb that in place.
    """
    sls = slices(data)
    if len(sls) == 1 and sls[0].offset == 0:
        return fn(data, sls[0])
    fat64 = data[:4] == FAT64_BE
    entsz = 32 if fat64 else 20
    n = len(sls)
    hdr = bytearray((FAT64_BE if fat64 else FAT_BE) + struct.pack(">I", n))
    body = bytearray()
    cursor = 8 + n * entsz
    for i, sl in enumerate(sls):
        base = 8 + i * entsz
        _, cpusubtype = struct.unpack_from(">II", data, base)
        align = struct.unpack_from(">I", data, base + (24 if fat64 else 16))[0]
        new = fn(data[sl.offset : sl.offset + sl.size], sl)
        step = 1 << align
        cursor = (cursor + step - 1) & ~(step - 1)
        body += b"\x00" * (cursor - (8 + n * entsz) - len(body)) + new
        if fat64:
            hdr += struct.pack(">IIQQII", sl.cputype, cpusubtype, cursor, len(new), align, 0)
        else:
            hdr += struct.pack(">IIIII", sl.cputype, cpusubtype, cursor, len(new), align)
        cursor += len(new)
    return bytes(hdr + body)
