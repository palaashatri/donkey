# Object fixtures

`reloc-x86_64.o` is an x86-64 ELF relocatable object built from `reloc.c` in this
directory with GCC (`cc -c -O0 -fno-pic -fno-stack-protector -fcf-protection=none`).
Both sources were written for this repository. The object has a data pointer that is
initialised with an absolute address (`R_X86_64_64`), a call to a global function
defined in the same object (`R_X86_64_PLT32`), and a call to an undefined function
(`R_X86_64_PLT32` against an external symbol). The relocation tests are in
`tests/unit/relocate_test.cpp`.
