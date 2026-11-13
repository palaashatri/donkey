# Signature generator fixtures (G09-T2)

`sigfuncs.c`, `sig_main.c` and this note were written for this repository. The binaries were built
on x86-64 Linux with Clang 18.1.3 and GNU `ar` and `ranlib`, with no C library:

    clang-18 -c -O1 -fno-pic -ffunction-sections -o sigfuncs.o sigfuncs.c
    ar rcs libsigfuncs.a sigfuncs.o && ranlib libsigfuncs.a
    clang-18 -static -nostdlib -fno-pic -O1 -ffunction-sections -fuse-ld=lld \
      -o sig_static sig_main.c libsigfuncs.a

- `sigfuncs.o` and `libsigfuncs.a` are the library the generator reads. Its global functions are
  `sig_add`, `sig_mul`, `sig_lookup` and `sig_call_external`. `sig_local` is static and `sig_table`
  is data, so the generator must not name either.
- `sig_lookup` has two relocations: a call to `sig_local` (`R_X86_64_PLT32` at offset 7) and the
  address of `sig_table` in `.rodata` (`R_X86_64_32S` at offset 14). `sig_call_external` has one,
  a call to `sig_external` at offset 2. These are the offsets the tests check.
- `sig_static` is an ELF executable that links the archive. The linker has filled in the
  relocations, so its bytes differ from the object's where the relocations are. It is the program a
  generated set is matched against. `sig_main.c` exits by syscall, so it needs no C library.

Inspect the relocations with `readelf -rW sigfuncs.o` and the symbols with `readelf -sW sigfuncs.o`.
