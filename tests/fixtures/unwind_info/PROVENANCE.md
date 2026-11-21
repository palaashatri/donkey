# Compact unwind fixtures (G23-T3)

`unwind.c` is written for this repository. Its functions have different frame shapes (a leaf, a
fixed frame, saved registers, a variable-length array), so their compact unwind encodings differ
and the linker cannot fold them all into one entry. The leaf and the variable-length-array
function are reached only through a pointer table in data. The images are linked without
LC_FUNCTION_STARTS and stripped, so only `__TEXT,__unwind_info` names those functions.

Built on Linux with LLVM 18 (Ubuntu clang 18.1.3, LLD 18.1.3), for each `ARCH` in `x86_64` and `arm64`:

    clang-18 --target=ARCH-apple-macos13 -O1 -fno-stack-protector -c unwind.c -o unwind-ARCH.o
    ld64.lld-18 -arch ARCH -platform_version macos 13.0.0 13.0.0 -no_uuid -no_adhoc_codesign \
        -no_function_starts -e _main -o unwind-ARCH-full unwind-ARCH.o
    llvm-strip-18 -o unwind_ARCH unwind-ARCH-full

(`-fno-stack-protector` because the images link no libSystem; they do not run on macOS and exist
to be read.)

The oracle is `llvm-objdump --macho --unwind-info`. Both images have one compressed second-level
page.

| File | SHA-256 | Entries (address: encoding) | End |
|---|---|---|---|
| `unwind_x86_64` | `a96c74bd9046733a0029d73a8abf7d3e7b916304703996c0a52b45dbfec82833` | 0x1000003a0: 0x01000000, 0x100000410: 0x01010001, 0x100000450: 0x01030161, 0x1000004d0: 0x01010001 | 0x1000004fa |
| `unwind_arm64` | `90d5387f192c5cd6467b52f48f09a8c99a96706dd4e22f8a12d5d25a0b732573` | 0x100000350: 0x02000000, 0x100000358: 0x02011010, 0x1000003b4: 0x04000001, 0x100000400: 0x04000003, 0x100000494: 0x04000001 | 0x1000004c8 |

The unstripped builds' functions (`llvm-nm -n`), in address order:

- x86-64: `_leaf`, `_sum_to`, `_variable`, `_run`, `_keeps`, `_main`, at 0x1000003a0, 0x1000003b0,
  0x100000410, 0x100000450, 0x100000490 and 0x1000004d0.
- arm64: the same functions, at 0x100000350, 0x100000358, 0x1000003b4, 0x100000400, 0x100000454
  and 0x100000494.

`_sum_to` (x86-64) and `_keeps` (both) share their predecessor's encoding, so they have no entry
of their own; calls reach them.
