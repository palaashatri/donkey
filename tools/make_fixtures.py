#!/usr/bin/env python3
"""Generate Donkey's redistributable binary fixtures.

Every byte is produced here; no proprietary or third-party binary is copied.
The output is deterministic, so regenerating on any host yields identical
files and hashes. Run from the repository root:

    python3 tools/make_fixtures.py
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "binaries"
MANIFESTS = ROOT / "tests" / "fixtures" / "manifests"

X86_64_TEXT = bytes(
    [
        0x55,                    # push rbp
        0x48, 0x89, 0xE5,        # mov rbp, rsp
        0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0
        0x90,                    # nop
        0x5D,                    # pop rbp
        0xC3,                    # ret
    ]
)
ARM64_TEXT = bytes(
    [
        0xFD, 0x7B, 0xBF, 0xA9,  # stp x29, x30, [sp, #-16]!
        0xFD, 0x03, 0x00, 0x91,  # mov x29, sp
        0x00, 0x00, 0x80, 0xD2,  # mov x0, #0
        0xFD, 0x7B, 0xC1, 0xA8,  # ldp x29, x30, [sp], #16
        0xC0, 0x03, 0x5F, 0xD6,  # ret
    ]
)
X86_32_TEXT = bytes(
    [
        0x55,                    # push ebp
        0x89, 0xE5,              # mov ebp, esp
        0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0
        0x90,                    # nop
        0x5D,                    # pop ebp
        0xC3,                    # ret
    ]
)


def u16(buf, offset, value):
    struct.pack_into("<H", buf, offset, value)


def u32(buf, offset, value):
    struct.pack_into("<I", buf, offset, value)


def u64(buf, offset, value):
    struct.pack_into("<Q", buf, offset, value)


def i32(buf, offset, value):
    struct.pack_into("<i", buf, offset, value)


def build_elf() -> bytes:
    text = (X86_64_TEXT + b"\x90" * 16)[:16]
    rodata = b"hello world\x00"

    shstrtab = b"\x00.text\x00.rodata\x00.shstrtab\x00.symtab\x00.strtab\x00"
    strtab = b"\x00_start\x00puts\x00message\x00"
    names = {
        ".text": 1,
        ".rodata": 7,
        ".shstrtab": 15,
        ".symtab": 25,
        ".strtab": 33,
    }
    strings = {
        "_start": 1,
        "puts": 8,
        "message": 13,
    }

    shoff = 0x300
    buf = bytearray(shoff + 6 * 64)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2  # ELFCLASS64
    buf[5] = 1  # ELFDATA2LSB
    buf[6] = 1  # EV_CURRENT
    buf[7] = 0  # ELFOSABI_SYSV

    u16(buf, 16, 2)  # ET_EXEC
    u16(buf, 18, 62)  # EM_X86_64
    u32(buf, 20, 1)
    u64(buf, 24, 0x400100)  # entry
    u64(buf, 32, 64)  # phoff
    u64(buf, 40, shoff)
    u32(buf, 48, 0)
    u16(buf, 52, 64)
    u16(buf, 54, 56)
    u16(buf, 56, 1)
    u16(buf, 58, 64)
    u16(buf, 60, 6)
    u16(buf, 62, 3)

    # Program header: one read/execute PT_LOAD covering the headers.
    u32(buf, 64, 1)
    u32(buf, 68, 5)
    u64(buf, 72, 0)
    u64(buf, 80, 0x400000)
    u64(buf, 88, 0x400000)
    u64(buf, 96, shoff)
    u64(buf, 104, shoff)
    u64(buf, 112, 0x1000)

    buf[0x100 : 0x100 + len(text)] = text
    buf[0x180 : 0x180 + len(rodata)] = rodata
    buf[0x200 : 0x200 + len(shstrtab)] = shstrtab

    symbols = [
        (0, 0, 0, 0, 0),
        (strings["_start"], 0x12, 1, 0x400100, 16),
        (strings["puts"], 0x12, 0, 0, 0),
        (strings["message"], 0x11, 2, 0x400180, 12),
    ]
    for index, (name, info, shndx, value, size) in enumerate(symbols):
        base = 0x240 + index * 24
        u32(buf, base, name)
        buf[base + 4] = info
        buf[base + 5] = 0
        u16(buf, base + 6, shndx)
        u64(buf, base + 8, value)
        u64(buf, base + 16, size)
    buf[0x2A0 : 0x2A0 + len(strtab)] = strtab

    def section(index, name, sh_type, flags, addr, offset, size, link=0, info=0,
                align=1, entsize=0):
        base = shoff + index * 64
        u32(buf, base, names.get(name, 0) if name else 0)
        u32(buf, base + 4, sh_type)
        u64(buf, base + 8, flags)
        u64(buf, base + 16, addr)
        u64(buf, base + 24, offset)
        u64(buf, base + 32, size)
        u32(buf, base + 40, link)
        u32(buf, base + 44, info)
        u64(buf, base + 48, align)
        u64(buf, base + 56, entsize)

    section(0, "", 0, 0, 0, 0, 0)
    section(1, ".text", 1, 0x6, 0x400100, 0x100, 16, align=16)
    section(2, ".rodata", 1, 0x2, 0x400180, 0x180, len(rodata), align=4)
    section(3, ".shstrtab", 3, 0, 0, 0x200, len(shstrtab))
    section(4, ".symtab", 2, 0, 0, 0x240, len(symbols) * 24, link=5, info=1,
            align=8, entsize=24)
    section(5, ".strtab", 3, 0, 0, 0x2A0, len(strtab))
    return bytes(buf)


def build_elf_i386() -> bytes:
    """A 32-bit ET_EXEC x86 ELF with the same shape as build_elf()."""
    text = (X86_32_TEXT + b"\x90" * 16)[:16]
    rodata = b"hello world\x00"

    shstrtab = b"\x00.text\x00.rodata\x00.shstrtab\x00.symtab\x00.strtab\x00"
    strtab = b"\x00_start\x00puts\x00message\x00"
    names = {
        ".text": 1,
        ".rodata": 7,
        ".shstrtab": 15,
        ".symtab": 25,
        ".strtab": 33,
    }
    strings = {
        "_start": 1,
        "puts": 8,
        "message": 13,
    }

    shoff = 0x300
    buf = bytearray(shoff + 6 * 40)
    buf[0:4] = b"\x7fELF"
    buf[4] = 1  # ELFCLASS32
    buf[5] = 1  # ELFDATA2LSB
    buf[6] = 1  # EV_CURRENT
    buf[7] = 0  # ELFOSABI_SYSV

    u16(buf, 16, 2)  # ET_EXEC
    u16(buf, 18, 3)  # EM_386
    u32(buf, 20, 1)
    u32(buf, 24, 0x08048100)  # entry
    u32(buf, 28, 52)  # phoff, immediately after the 52-byte header
    u32(buf, 32, shoff)
    u32(buf, 36, 0)
    u16(buf, 40, 52)  # ehsize
    u16(buf, 42, 32)  # phentsize
    u16(buf, 44, 1)  # phnum
    u16(buf, 46, 40)  # shentsize
    u16(buf, 48, 6)  # shnum
    u16(buf, 50, 3)  # shstrndx

    # Program header (Elf32_Phdr): type, offset, vaddr, paddr, filesz, memsz,
    # flags, align. One read/execute PT_LOAD covering the headers and content.
    ph = 52
    u32(buf, ph + 0, 1)
    u32(buf, ph + 4, 0)
    u32(buf, ph + 8, 0x08048000)
    u32(buf, ph + 12, 0x08048000)
    u32(buf, ph + 16, shoff)
    u32(buf, ph + 20, shoff)
    u32(buf, ph + 24, 5)  # R|X
    u32(buf, ph + 28, 0x1000)

    buf[0x100 : 0x100 + len(text)] = text
    buf[0x180 : 0x180 + len(rodata)] = rodata
    buf[0x200 : 0x200 + len(shstrtab)] = shstrtab

    # Elf32_Sym: name, value, size, info, other, shndx.
    symbols = [
        (0, 0, 0, 0, 0),
        (strings["_start"], 0x12, 1, 0x08048100, 16),
        (strings["puts"], 0x12, 0, 0, 0),
        (strings["message"], 0x11, 2, 0x08048180, 12),
    ]
    for index, (name, info, shndx, value, size) in enumerate(symbols):
        base = 0x240 + index * 16
        u32(buf, base, name)
        u32(buf, base + 4, value)
        u32(buf, base + 8, size)
        buf[base + 12] = info
        buf[base + 13] = 0
        u16(buf, base + 14, shndx)
    buf[0x2A0 : 0x2A0 + len(strtab)] = strtab

    def section(index, name, sh_type, flags, addr, offset, size, link=0, info=0,
                align=1, entsize=0):
        base = shoff + index * 40
        u32(buf, base, names.get(name, 0) if name else 0)
        u32(buf, base + 4, sh_type)
        u32(buf, base + 8, flags)
        u32(buf, base + 12, addr)
        u32(buf, base + 16, offset)
        u32(buf, base + 20, size)
        u32(buf, base + 24, link)
        u32(buf, base + 28, info)
        u32(buf, base + 32, align)
        u32(buf, base + 36, entsize)

    section(0, "", 0, 0, 0, 0, 0)
    section(1, ".text", 1, 0x6, 0x08048100, 0x100, 16, align=16)
    section(2, ".rodata", 1, 0x2, 0x08048180, 0x180, len(rodata), align=4)
    section(3, ".shstrtab", 3, 0, 0, 0x200, len(shstrtab))
    section(4, ".symtab", 2, 0, 0, 0x240, len(symbols) * 16, link=5, info=1,
            align=4, entsize=16)
    section(5, ".strtab", 3, 0, 0, 0x2A0, len(strtab))
    return bytes(buf)


def build_pe() -> bytes:
    text = (X86_64_TEXT + b"\xcc" * 0x200)[:0x200]
    buf = bytearray(0x600)

    buf[0:2] = b"MZ"
    u16(buf, 0x02, 0x90)
    u16(buf, 0x04, 0x03)
    u16(buf, 0x18, 0x40)
    u32(buf, 0x3C, 0x80)

    pe = 0x80
    buf[pe : pe + 4] = b"PE\x00\x00"
    coff = pe + 4
    u16(buf, coff, 0x8664)  # x86-64
    u16(buf, coff + 2, 2)
    u32(buf, coff + 4, 0x5F5E1000)
    u32(buf, coff + 8, 0)
    u32(buf, coff + 12, 0)
    u16(buf, coff + 16, 0xF0)
    u16(buf, coff + 18, 0x0022)

    opt = coff + 20
    u16(buf, opt, 0x20B)
    buf[opt + 2] = 1
    u32(buf, opt + 4, 0x200)
    u32(buf, opt + 8, 0x200)
    u32(buf, opt + 16, 0x1000)  # entry RVA
    u32(buf, opt + 20, 0x1000)  # base of code
    u64(buf, opt + 24, 0x140000000)  # image base
    u32(buf, opt + 32, 0x1000)
    u32(buf, opt + 36, 0x200)
    u16(buf, opt + 40, 6)
    u16(buf, opt + 48, 6)
    u32(buf, opt + 56, 0x3000)  # size of image
    u32(buf, opt + 60, 0x200)   # size of headers
    u32(buf, opt + 64, 0)
    u16(buf, opt + 68, 3)  # console subsystem
    u16(buf, opt + 70, 0x8160)
    u64(buf, opt + 72, 0x100000)
    u64(buf, opt + 80, 0x1000)
    u64(buf, opt + 88, 0x100000)
    u64(buf, opt + 96, 0x1000)
    u32(buf, opt + 104, 0)
    u32(buf, opt + 108, 16)
    dirs = opt + 112
    u32(buf, dirs + 0 * 8, 0x2000)
    u32(buf, dirs + 0 * 8 + 4, 0x100)
    u32(buf, dirs + 1 * 8, 0x2100)
    u32(buf, dirs + 1 * 8 + 4, 0x100)

    sections = opt + 0xF0
    def section(index, name, vsize, vaddr, raw_size, raw_ptr, characteristics):
        base = sections + index * 40
        encoded = name.encode("ascii")
        buf[base : base + 8] = encoded + b"\x00" * (8 - len(encoded))
        u32(buf, base + 8, vsize)
        u32(buf, base + 12, vaddr)
        u32(buf, base + 16, raw_size)
        u32(buf, base + 20, raw_ptr)
        u32(buf, base + 24, 0)
        u32(buf, base + 28, 0)
        u16(buf, base + 32, 0)
        u16(buf, base + 34, 0)
        u32(buf, base + 36, characteristics)

    section(0, ".text", 0x100, 0x1000, 0x200, 0x200, 0x60000020)
    section(1, ".rdata", 0x200, 0x2000, 0x200, 0x400, 0x40000040)

    buf[0x200 : 0x200 + len(text)] = text

    rdata = 0x400
    export = rdata
    u32(buf, export + 0, 0)
    u32(buf, export + 4, 0x5F5E1000)
    u16(buf, export + 8, 0)
    u16(buf, export + 10, 0)
    u32(buf, export + 12, 0x2080)  # dll name RVA
    u32(buf, export + 16, 1)       # ordinal base
    u32(buf, export + 20, 1)       # number of functions
    u32(buf, export + 24, 1)       # number of names
    u32(buf, export + 28, 0x2040)
    u32(buf, export + 32, 0x2044)
    u32(buf, export + 36, 0x2048)
    u32(buf, rdata + 0x40, 0x1000)
    u32(buf, rdata + 0x44, 0x2060)
    u16(buf, rdata + 0x48, 0)
    buf[rdata + 0x60 : rdata + 0x60 + 12] = b"tiny_export\x00"
    buf[rdata + 0x80 : rdata + 0x80 + 9] = b"tiny.dll\x00"

    imp = rdata + 0x100
    u32(buf, imp + 0, 0x2140)
    u32(buf, imp + 4, 0)
    u32(buf, imp + 8, 0)
    u32(buf, imp + 12, 0x2180)
    u32(buf, imp + 16, 0x2160)
    u32(buf, rdata + 0x140, 0x21A0)
    u64(buf, rdata + 0x160, 0x21A0)
    u16(buf, rdata + 0x1A0, 0)
    buf[rdata + 0x1A2 : rdata + 0x1AE] = b"ExitProcess\x00"
    buf[rdata + 0x180 : rdata + 0x180 + 13] = b"KERNEL32.dll\x00"
    return bytes(buf)


def build_macho() -> bytes:
    text = ARM64_TEXT
    command_bytes = 152 + 72 + 24 + 24
    buf = bytearray(0x1040)

    u32(buf, 0, 0xFEEDFACF)
    u32(buf, 4, 0x0100000C)  # CPU_TYPE_ARM64
    u32(buf, 8, 0)
    u32(buf, 12, 2)  # MH_EXECUTE
    u32(buf, 16, 4)  # ncmds
    u32(buf, 20, command_bytes)
    u32(buf, 24, 0)
    u32(buf, 28, 0)

    command = 32
    # __TEXT
    u32(buf, command, 0x19)
    u32(buf, command + 4, 152)
    buf[command + 8 : command + 24] = b"__TEXT\x00" + b"\x00" * 9
    u64(buf, command + 24, 0x100000000)
    u64(buf, command + 32, 0x1000)
    u64(buf, command + 40, 0)
    u64(buf, command + 48, 0x1000)
    i32(buf, command + 56, 7)
    i32(buf, command + 60, 5)
    u32(buf, command + 64, 1)
    u32(buf, command + 68, 0)
    section = command + 72
    buf[section : section + 16] = b"__text\x00" + b"\x00" * 9
    buf[section + 16 : section + 32] = b"__TEXT\x00" + b"\x00" * 9
    u64(buf, section + 32, 0x100000F00)
    u64(buf, section + 40, len(text))
    u32(buf, section + 48, 0xF00)
    u32(buf, section + 52, 4)
    u32(buf, section + 56, 0)
    u32(buf, section + 60, 0)
    u32(buf, section + 64, 0x80000400)
    u32(buf, section + 68, 0)
    u32(buf, section + 72, 0)
    u32(buf, section + 76, 0)

    command += 152
    # __LINKEDIT
    u32(buf, command, 0x19)
    u32(buf, command + 4, 72)
    buf[command + 8 : command + 24] = b"__LINKEDIT\x00" + b"\x00" * 5
    u64(buf, command + 24, 0x100001000)
    u64(buf, command + 32, 0x1000)
    u64(buf, command + 40, 0x1000)
    u64(buf, command + 48, 0x40)
    i32(buf, command + 56, 7)
    i32(buf, command + 60, 1)
    u32(buf, command + 64, 0)
    u32(buf, command + 68, 0)

    command += 72
    # LC_MAIN
    u32(buf, command, 0x80000028)
    u32(buf, command + 4, 24)
    u64(buf, command + 8, 0xF00)
    u64(buf, command + 16, 0)

    command += 24
    # LC_SYMTAB
    u32(buf, command, 2)
    u32(buf, command + 4, 24)
    u32(buf, command + 8, 0x1000)
    u32(buf, command + 12, 2)
    u32(buf, command + 16, 0x1020)
    u32(buf, command + 20, 0x10)

    buf[0xF00 : 0xF00 + len(text)] = text

    def nlist(offset, strx, n_type, sect, value):
        u32(buf, offset, strx)
        buf[offset + 4] = n_type
        buf[offset + 5] = sect
        u16(buf, offset + 6, 0)
        u64(buf, offset + 8, value)

    nlist(0x1000, 1, 0x0F, 1, 0x100000F00)  # _main
    nlist(0x1010, 7, 0x01, 0, 0)            # _puts (undefined)
    buf[0x1020 : 0x102D] = b"\x00_main\x00_puts\x00"
    return bytes(buf)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    fixtures = {
        "tiny-elf-x86_64": build_elf(),
        "tiny-elf-i386": build_elf_i386(),
        "tiny-pe-x86_64.exe": build_pe(),
        "tiny-macho-arm64": build_macho(),
    }
    manifest = {"generator": "tools/make_fixtures.py", "fixtures": []}
    for name, data in fixtures.items():
        path = OUT / name
        path.write_bytes(data)
        entry = {
            "name": name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "provenance": "generated from first principles by tools/make_fixtures.py",
        }
        manifest["fixtures"].append(entry)
        print(f"{name}: {len(data)} bytes sha256={entry['sha256']}")
    (MANIFESTS / "generated.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
