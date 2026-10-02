"""Mach-O parsing + LC_LOAD_DYLIB surgery against hand-built headers."""

import struct

import pytest

from macho_fixtures import (
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    PAGE,
    make_fat,
    make_thin,
    rustls_slice_strings,
)

from rerust import macho
from rerust.macho import (
    HEADER64_SIZE,
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    MachOError,
    SECTION64_SIZE,
    SEGMENT64_SIZE,
    THIN64_LE,
    is_macho,
    slices,
)


class TestContainers:
    def test_thin_slice(self):
        img = make_thin()
        assert is_macho(img)
        [s] = slices(img)
        assert s.arch == "arm64"
        assert s.offset == 0
        assert s.size == len(img)
        assert s.filetype == macho.MH_EXECUTE

    def test_fat_slices(self):
        arm = make_thin(cputype=CPU_TYPE_ARM64)
        x86 = make_thin(cputype=CPU_TYPE_X86_64, section_offset=0x2000)
        fat = make_fat([arm, x86])
        assert is_macho(fat)
        [a, x] = slices(fat)
        assert a.arch == "arm64" and x.arch == "x86_64"
        assert a.offset != 0 and x.offset > a.offset
        assert fat[a.offset : a.offset + 4] == THIN64_LE

    def test_fat64_container(self):
        arm = make_thin()
        fat = make_fat([arm], fat64=True)
        [s] = slices(fat)
        assert s.arch == "arm64"
        assert fat[s.offset : s.offset + len(arm)] == arm

    def test_refuses_thin32_and_garbage(self):
        thin32 = b"\xce\xfa\xed\xfe" + b"\x00" * 64
        with pytest.raises(MachOError):
            slices(thin32)
        with pytest.raises(MachOError):
            slices(b"\x00" * 64)


class TestLoadCommands:
    def test_dylib_paths_read_back(self):
        img = make_thin(dylibs=("/usr/lib/libSystem.B.dylib", "@rpath/Flutter.framework/Flutter"))
        assert macho.dylib_paths(img) == [
            "/usr/lib/libSystem.B.dylib",
            "@rpath/Flutter.framework/Flutter",
        ]
        assert not macho.has_dylib(img, 0, "@executable_path/Frameworks/librerust.dylib")

    def test_segments_and_vaddr_mapping(self):
        img = make_thin()
        seg = macho.segments(img)["__TEXT"]
        assert seg.vmaddr == 0 and seg.fileoff == 0
        # __TEXT maps 1:1; the section content sits at PAGE.
        assert macho.vaddr_to_file(img, 0, PAGE) == PAGE
        assert macho.vaddr_to_file(img, 0, PAGE + 4) == PAGE + 4
        # past vmsize -> unmapped; inside vmsize but past filesize -> zero-fill
        assert macho.vaddr_to_file(img, 0, seg.vmsize + 1) is None

    def test_vaddr_drifts_from_file_offset(self):
        """The reason iOS entries cannot reuse ELF offset assumptions: a
        segment whose vmaddr != fileoff must map through the table."""
        img = bytearray(make_thin())
        # Rewrite __TEXT vmaddr to 0x100000000 (typical PIE slide base).
        struct.pack_into("<Q", img, HEADER64_SIZE + 24, 0x100000000)
        assert macho.vaddr_to_file(bytes(img), 0, 0x100000000 + PAGE) == PAGE
        assert macho.vaddr_to_file(bytes(img), 0, PAGE) is None


class TestInsertLoadDylib:
    NAME = "@executable_path/Frameworks/librerust.dylib"

    def test_insert_roundtrip(self):
        img = make_thin(dylibs=("/usr/lib/libSystem.B.dylib",))
        out = macho.insert_load_dylib(img, 0, self.NAME)
        assert macho.has_dylib(out, 0, self.NAME)
        assert macho.dylib_paths(out)[0] == "/usr/lib/libSystem.B.dylib"  # order kept
        assert len(out) == len(img)  # padding-only: no byte is added or moved

    def test_nothing_but_header_and_padding_changes(self):
        img = make_thin(content=rustls_slice_strings())
        _, sizeofcmds, _ = macho.header(img)
        hdr_end = HEADER64_SIZE + sizeofcmds
        out = macho.insert_load_dylib(img, 0, self.NAME)
        new_cmd = macho.make_load_dylib(self.NAME)
        assert out[:16] == img[:16]  # through filetype
        # the command was written into what was zero padding — nothing moved
        assert set(img[hdr_end : hdr_end + len(new_cmd)]) == {0}
        assert out[hdr_end : hdr_end + len(new_cmd)] == new_cmd
        assert out[hdr_end + len(new_cmd) :] == img[hdr_end + len(new_cmd) :]
        ncmds, new_sizeof, _ = macho.header(out)
        assert ncmds == 2 and new_sizeof == sizeofcmds + len(new_cmd)

    def test_weak_variant(self):
        out = macho.insert_load_dylib(make_thin(), 0, self.NAME, weak=True)
        # make_thin's segment command comes first — find OUR command, not cmd #0.
        cmds = list(macho.load_commands(out))
        assert any(c == LC_LOAD_WEAK_DYLIB for c, _s, _p in cmds)
        assert not any(c == LC_LOAD_DYLIB for c, _s, _p in cmds)

    def test_idempotence_guard_is_callers_job(self):
        img = make_thin()
        once = macho.insert_load_dylib(img, 0, self.NAME)
        # repack_ipa must check has_dylib first — a blind second insert dupes.
        assert macho.has_dylib(img, 0, self.NAME) is False
        assert macho.has_dylib(once, 0, self.NAME) is True

    def test_refuses_without_padding_budget(self):
        # Section lands immediately after the load commands: budget 0.
        tight = make_thin(section_offset=HEADER64_SIZE + SEGMENT64_SIZE + SECTION64_SIZE)
        with pytest.raises(MachOError, match="no header padding"):
            macho.insert_load_dylib(tight, 0, self.NAME)

    def test_refuses_non_64bit_and_wrong_filetype(self):
        with pytest.raises(MachOError):
            macho.insert_load_dylib(b"\xce\xfa\xed\xfe" + b"\x00" * 256, 0, self.NAME)
        # MH_BUNDLE (0x8) etc. are not executable/dylib — refuse rather than
        # inject into something dyld will not load our way.
        bundle = bytearray(make_thin())
        struct.pack_into("<I", bundle, 12, 0x8)
        with pytest.raises(MachOError, match="filetype"):
            macho.insert_load_dylib(bytes(bundle), 0, self.NAME)

    def test_fat_slices_patch_in_place(self):
        arm = make_thin(content=rustls_slice_strings())
        x86 = make_thin(cputype=CPU_TYPE_X86_64, section_offset=0x2000)
        fat = make_fat([arm, x86])
        s_arm = slices(fat)[0]
        patched_slice = macho.insert_load_dylib(fat[s_arm.offset : s_arm.offset + s_arm.size], 0, self.NAME)
        out = macho.patch_slice(fat, s_arm, patched_slice)
        assert len(out) == len(fat)
        assert macho.has_dylib(out, s_arm.offset, self.NAME)
        # the x86 slice bytes survived untouched
        s_x86 = slices(out)[1]
        assert out[s_x86.offset : s_x86.offset + s_x86.size] == x86
