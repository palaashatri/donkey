# Object fixtures

`reloc-x86_64.o` is an x86-64 ELF relocatable object built from `reloc.c` in this
directory with GCC (`cc -c -O0 -fno-pic -fno-stack-protector -fcf-protection=none`).
Both sources were written for this repository. The object has a data pointer that is
initialised with an absolute address (`R_X86_64_64`), a call to a global function
defined in the same object (`R_X86_64_PLT32`), and a call to an undefined function
(`R_X86_64_PLT32` against an external symbol). The relocation tests are in
`tests/unit/relocate_test.cpp`.

`reloc-forms-aarch64.o` is an AArch64 ELF relocatable object built from `reloc-forms.c` in
this directory with Clang 18.1.3 (`clang --target=aarch64-linux-gnu -O2 -c reloc-forms.c`).
The source was written for this repository. The object carries the page and low-12-bit
data forms: `R_AARCH64_ADR_PREL_PG_HI21` with `R_AARCH64_LDST8/16/32/64_ABS_LO12_NC`, and
`R_AARCH64_ADD_ABS_LO12_NC` for the address of a static table. The test is
`RelocateAArch64.PageAndLowBitRelocationsReachTheirData` in `tests/unit/relocate_aarch64_test.cpp`.
