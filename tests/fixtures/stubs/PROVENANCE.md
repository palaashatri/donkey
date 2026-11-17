# Import stub fixtures (G24-T4)

`stubs.c` is written for this repository (MIT, like the rest of Donkey). It calls two imports,
`abort` (no-return) and `puts`. The three binaries are built from it, stripped, with GCC 13.3.0
(Ubuntu 13.3.0-6ubuntu2~24.04.1) on x86-64 Linux, and the matching AArch64 cross compiler:

    gcc -O1 -fno-inline -s -o stubs_x86_64 stubs.c
    gcc -O1 -fno-inline -fno-plt -s -o stubs_noplt_x86_64 stubs.c
    aarch64-linux-gnu-gcc -O1 -fno-inline -s -Wl,-z,max-page-size=4096 -o stubs_aarch64 stubs.c
    gcc -O1 -fPIC -shared -s -o libifunc.so ifunc.c
    gcc -w -O1 -fno-inline -fno-builtin-exit -fPIC -shared -s -Wl,-soname,libmyexit.so.1 -o libmyexit.so.1 myexit.c
    gcc -O1 -fno-inline -fno-builtin -s -o exit_consumer exit_consumer.c ./libmyexit.so.1
    x86_64-w64-mingw32-gcc -O1 -fno-inline -s -Wl,--no-insert-timestamp -o stubs_x86_64.exe stubs.c
    # (GCC 13-win32, MinGW-w64; built twice, the bytes are the same)

`bti.c` (also written here, MIT) is built with Ubuntu clang 18.1.3 and LLD 18.1.3 against the same
AArch64 cross sysroot. lld starts a PLT entry with `bti c` when the entry's address escapes, as it
does for `puts` here (built twice, the bytes are the same):

    clang --target=aarch64-linux-gnu --gcc-toolchain=/usr -O1 -fno-pic -no-pie -s \
      -mbranch-protection=standard -fuse-ld=lld -Wl,-z,force-bti -Wl,-z,max-page-size=4096 \
      -Wl,--build-id=none -o bti_aarch64 bti.c

| File | SHA-256 | What it holds |
|---|---|---|
| `stubs_x86_64` | `3148bb3c0ffe68172d2def4e5a764f6ffc9a2cc55ca2cc953f584a80365ca005` | PIE with IBT: `abort@plt` and `puts@plt` in `.plt.sec`, `__cxa_finalize@plt` in `.plt.got` |
| `stubs_noplt_x86_64` | `09634211210b70f44227c11115115efd55ab7baaade360d22dc14ccd8962c8ee` | `-fno-plt`: `call *slot(%rip)` through the GLOB_DAT slots of `abort` and `puts` |
| `stubs_x86_64.exe` | `3695ff7a81ff78768e392a7a64c96c123a28b8195a28e7e760f98735da4a4780` | PE32+ (MinGW): `call *slot(%rip)` through KERNEL32's IAT, and 8-byte `jmp *slot(%rip)` thunks for msvcrt imports |
| `libifunc.so` | `cbc05ca0aea5d21bc7eb6ac2284a5328aec871a9219b284059d3299b9453a2fe` | from `ifunc.c`: the protected ifunc `pick`, called through `1050 <*ABS*+0x1121@plt>`, whose slot an IRELATIVE relocation with addend 0x1121 (the IFUNC symbol `pick`) fills |
| `libmyexit.so.1` | `76e666f442af3d61c8cc15d71bcf95e6cb8c1dfe3bda769ef0c7c8ac1e844ad6` | from `myexit.c`: exports an `exit` that returns (G24-T3) |
| `exit_consumer` | `d1d796951bbbd2d1e4349b5723455cd4ee396a65a1f0bf8472da4e0efad3eb85` | from `exit_consumer.c`: needs `libmyexit.so.1` before `libc.so.6`, imports an unversioned `exit` (bound to libmyexit at run time), `1150: call 1050 <exit@plt>` |
| `stubs_aarch64` | `d9d9941aba6761ad230ccd1526238bd5e8f0d7dc509d2161ce6ca0609996b8b8` | AArch64 PIE: `abort@plt` and `puts@plt` in `.plt` |
| `bti_aarch64` | `ac2c4602baa858a2f7da9b29d627abc69958e634cb69eca17a2c4628af28672a` | AArch64 non-PIE, BTI: `2018f8 <puts@plt>` is `bti c; adrp; ldr; add; br`, `2018b0 <abort@plt>` has no BTI |

The ELF binaries link glibc dynamically; only its small startup objects (`crt1.o`, `crti.o`,
`crtn.o`, under the LGPL's exception for them) and GCC's `crtbegin`/`crtend` (GCC Runtime Library
Exception; `bti_aarch64` takes them from the same cross toolchain through clang) are in the files, as in any GCC-built program. The PE links the MinGW-w64 startup code
statically (ZPL-2.1 for most of `mingw-w64-crt`, per Debian's copyright file for
`mingw-w64-x86-64-dev`) and libgcc pieces (GCC Runtime Library Exception), as
`tests/fixtures/pdata/pdata-pe-x86_64.dll` does, and imports msvcrt.dll and KERNEL32.dll.
The oracle for the stub names is `objdump -d` (x86-64 ELF), `llvm-objdump -d` (AArch64) and
`llvm-objdump -d -p` (PE: the disassembly and the import tables).
