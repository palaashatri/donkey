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

`reloc-got-x86_64.o` and `reloc-got-aarch64.o` are built from `reloc-got.c` with Clang 18.1.3
(`clang -fPIC -O2 -c`, and `--target=aarch64-linux-gnu` for the AArch64 object). The source
was written for this repository. The x86-64 object carries `R_X86_64_REX_GOTPCRELX`; the
AArch64 object carries `R_AARCH64_ADR_GOT_PAGE` and `R_AARCH64_LD64_GOT_LO12_NC`. The tests
are in `tests/unit/relocate_got_test.cpp`.

`reloc-common-x86_64.o` and `reloc-common-aarch64.o` are built from `reloc-common.c` with Clang
18.1.3 (`clang -fcommon -O2 -c`, with `--target=aarch64-linux-gnu` for the AArch64 object). The
source was written for this repository. The objects hold three COMMON symbols (`shared_counter`,
`shared_buffer`, `shared_wide`) that the linker must place. The tests are in
`tests/unit/relocate_common_test.cpp`.

## TLS relocation forms (G15-T1)

- `tls.c`: written for this repository. Three thread-local variables (`tls_counter` and
  `tls_byte` in `.tdata`, `tls_pair` in `.tbss`) and `read_tls`, which reads them.
- `tls-local-exec-x86_64.o`: `gcc -c -O0 -fno-pic -ftls-model=local-exec tls.c` (GCC 13.3,
  Ubuntu 24.04). Its relocations are R_X86_64_TPOFF32.
  The expected bytes of `read_tls` are the ones `ld -static -nostdlib -e read_tls` puts in the
  executable (GNU ld 2.42), read with `readelf`/`objdump`: 45 bytes, the thread-pointer offsets
  -0x20 (tls_counter), -0x1c (tls_byte) and -0x8 (tls_pair+8).
- `tls-initial-exec.s`: written for this repository, the same variables and `read_tls` in
  assembly, using `movq sym@gottpoff(%rip), %reg` (R_X86_64_GOTTPOFF). GCC does not emit
  GOTTPOFF for variables it defines itself, and `ld` relaxes the form in a static link, so the
  object is assembled with `as` and its expected slot values are the linker's layout of the
  same TLS block: -0x20, -0x1c and -0x10 (tls_pair at offset 0x10).
- `tls-global-dynamic-x86_64.o`: `gcc -c -O0 -fPIC -ftls-model=global-dynamic tls.c` (GCC 13.3.0).
  Its R_X86_64_TLSGD sequences are relaxed by a static link, as `ld` relaxes them. The expected
  bytes of `read_tls` are the 85 bytes that `ld -static -nostdlib -e read_tls` (GNU ld 2.42)
  writes for this object: `mov %fs:0,%rax; lea tpoff(%rax),%rax` in place of each call sequence.
- `tls-local-dynamic-x86_64.o`: `gcc -c -O0 -fPIC -ftls-model=local-dynamic tls-local-dynamic.c`
  (GCC 13.3.0; the source is written for this repository). The expected bytes of `read_ld` are
  the 65 bytes that `ld -static -nostdlib -e read_ld` (GNU ld 2.42) writes: the 12-byte call
  sequence becomes `data16 data16 data16 mov %fs:0,%rax`, and each DTPOFF32 becomes the
  variable's thread-pointer offset.
- `tls-global-dynamic-extern-x86_64.o`: `gcc -c -O0 -fPIC -ftls-model=global-dynamic
  tls-extern.c` (GCC 13.3.0; written for this repository). It accesses a thread-local variable
  the object does not define, so the access cannot be relaxed and the image stays partial.
- `tls-local-exec-aarch64.o`, `tls-initial-exec-aarch64.o`, `tls-global-dynamic-aarch64.o`:
  `aarch64-linux-gnu-gcc -c -O0 -fPIC -ftls-model=<model> tls.c` (GCC 13.3.0), from the same
  source as the x86-64 objects. The AArch64 default for the global-dynamic model is TLSDESC, so
  the global-dynamic object carries R_AARCH64_TLSDESC_* relocations. The expected bytes of
  `read_tls` in the local-exec object (64 bytes) and the global-dynamic object (112 bytes) are
  the bytes `aarch64-linux-gnu-ld -static -nostdlib -e read_tls` (GNU ld 2.42) writes. The
  initial-exec object's slots are checked against the variant I offsets 0x10, 0x14 and 0x18
  (tls_counter, tls_byte, tls_pair); `ld` relaxes that model to movz/movk instead, and the
  slot form used here is equally valid.
