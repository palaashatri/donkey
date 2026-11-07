#!/usr/bin/env python3
"""Writes sample.dmp, a Windows minidump for the minidump reader tests (G15-T3).

The layout is the one Microsoft documents for MINIDUMP_HEADER, MINIDUMP_DIRECTORY and the
streams used here (SystemInfo, ThreadList, ModuleList, Memory64List and Exception). The values
are the constants below, and tests/unit/minidump_test.cpp checks the same values. No Windows
host produced this file, so it does not test Windows output; it tests the reader against the
documented structure.

Run: python3 make_sample_minidump.py   (writes sample.dmp next to this script)
"""

import pathlib
import struct

SIGNATURE = 0x504D444D  # "MDMP"
VERSION = 0xA793
HEADER_SIZE = 32
DIRECTORY_ENTRY_SIZE = 12

STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_EXCEPTION = 6
STREAM_SYSTEM_INFO = 7
STREAM_MEMORY64_LIST = 9

ARCH_AMD64 = 9
CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL = 0x1
CONTEXT_INTEGER = 0x2
CONTEXT_SIZE = 0x4D0
REGISTER_OFFSETS = {
    "rax": 0x78, "rcx": 0x80, "rdx": 0x88, "rbx": 0x90, "rsp": 0x98, "rbp": 0xA0,
    "rsi": 0xA8, "rdi": 0xB0, "r8": 0xB8, "r9": 0xC0, "r10": 0xC8, "r11": 0xD0,
    "r12": 0xD8, "r13": 0xE0, "r14": 0xE8, "r15": 0xF0, "rip": 0xF8,
}
EFLAGS_OFFSET = 0x44

# id, stack start, stack size, registers the context holds
THREADS = [
    (0x1234, 0x7FFE00000000, 0x1000,
     {"rip": 0x140001000, "rsp": 0x7FFE00000F00, "rbp": 0x7FFE00000F40, "rax": 0x1111,
      "rcx": 0x2222, "r15": 0xFEDCBA9876543210}),
    (0x1235, 0x7FFE00010000, 0x2000,
     {"rip": 0x7FF800012340, "rsp": 0x7FFE00011FF0, "rbp": 0, "rax": 0x42}),
]
# base, size, timestamp, checksum, name (non-ASCII, to exercise the UTF-16 conversion)
MODULES = [
    (0x140000000, 0x4000, 0x65000000, 0x1A2B, "C:\\build\\sample.exe"),
    (0x7FF800000000, 0x200000, 0x64000000, 0x3C4D, "\u00dcnicode.dll"),
]
# address, bytes
MEMORY = [
    (0x140001000, bytes(range(256))),
    (0x7FFE00000F00, bytes([0xAB] * 0x40)),
]
# thread id, exception code, exception address
EXCEPTION = (0x1234, 0xC0000005, 0x140001010)


def align4(value):
    return (value + 3) & ~3


def utf16_string(text):
    encoded = text.encode("utf-16-le")
    return struct.pack("<I", len(encoded)) + encoded


def amd64_context(registers, eflags=0x246):
    data = bytearray(CONTEXT_SIZE)
    struct.pack_into("<I", data, 0x30, CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER)
    struct.pack_into("<I", data, EFLAGS_OFFSET, eflags)
    for name, value in registers.items():
        struct.pack_into("<Q", data, REGISTER_OFFSETS[name], value)
    return bytes(data)


def build():
    # The streams' fixed-size bodies. The variable parts (contexts, names, memory bytes) are
    # appended after the streams, and the streams point at them by RVA.
    system = struct.pack("<HHHBBIIII", ARCH_AMD64, 0, 0, 8, 1, 10, 0, 22621, 2)
    system += b"\0" * (56 - len(system))

    contexts = [amd64_context(regs) for (_, _, _, regs) in THREADS]
    thread_body = bytearray(struct.pack("<I", len(THREADS)))
    for index, (thread_id, stack_start, stack_size, _) in enumerate(THREADS):
        thread_body += struct.pack("<IIIIQ", thread_id, 0, 0, 0, 0)  # id, suspend, class, prio, teb
        thread_body += struct.pack("<QII", stack_start, stack_size, 0)  # stack: start, size, rva
        thread_body += struct.pack("<II", len(contexts[index]), 0)  # context: size, rva (patched)

    module_body = bytearray(struct.pack("<I", len(MODULES)))
    for base, size, timestamp, checksum, _ in MODULES:
        # base, size, checksum, timestamp, name rva (patched), then 84 bytes of version info
        # and locations this reader does not need.
        module_body += struct.pack("<QIIII", base, size, checksum, timestamp, 0)
        module_body += b"\0" * 84

    memory_blob = b"".join(data for (_, data) in MEMORY)
    memory_body = bytearray(struct.pack("<QQ", len(MEMORY), 0))  # count, base rva (patched)
    for address, data in MEMORY:
        memory_body += struct.pack("<QQ", address, len(data))

    thread_id, code, address = EXCEPTION
    exception = struct.pack("<IIIIQQI", thread_id, 0, code, 0, 0, address, 0)
    exception += b"\0" * (168 - len(exception))

    streams = [
        (STREAM_SYSTEM_INFO, bytearray(system)),
        (STREAM_THREAD_LIST, thread_body),
        (STREAM_MODULE_LIST, module_body),
        (STREAM_MEMORY64_LIST, memory_body),
        (STREAM_EXCEPTION, bytearray(exception)),
    ]

    # Layout: the header, the directory, the streams, then the variable blobs.
    cursor = HEADER_SIZE + DIRECTORY_ENTRY_SIZE * len(streams)
    stream_rvas = []
    for _, body in streams:
        cursor = align4(cursor)
        stream_rvas.append(cursor)
        cursor += len(body)

    blobs = []  # (rva, bytes)

    def place(blob):
        nonlocal cursor
        cursor = align4(cursor)
        rva = cursor
        blobs.append((rva, blob))
        cursor += len(blob)
        return rva

    context_rvas = [place(c) for c in contexts]
    name_rvas = [place(utf16_string(name)) for (_, _, _, _, name) in MODULES]
    memory_base = place(memory_blob)

    # Patch the RVAs the streams name.
    for index, rva in enumerate(context_rvas):
        struct.pack_into("<II", thread_body, 4 + index * 48 + 40, len(contexts[index]), rva)
    for index, rva in enumerate(name_rvas):
        struct.pack_into("<I", module_body, 4 + index * 108 + 20, rva)
    struct.pack_into("<Q", memory_body, 8, memory_base)

    image = bytearray(cursor)
    directory = bytearray()
    for (stream_type, body), rva in zip(streams, stream_rvas):
        directory += struct.pack("<III", stream_type, len(body), rva)
        image[rva:rva + len(body)] = body
    for rva, blob in blobs:
        image[rva:rva + len(blob)] = blob
    header = struct.pack("<IIIIIIQ", SIGNATURE, VERSION, len(streams), HEADER_SIZE, 0,
                         0x65000000, 0)
    image[0:HEADER_SIZE] = header
    image[HEADER_SIZE:HEADER_SIZE + len(directory)] = directory
    return bytes(image)


def main():
    out = pathlib.Path(__file__).resolve().parent / "sample.dmp"
    data = build()
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
