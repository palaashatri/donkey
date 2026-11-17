/* G24-T4 fixture: an AArch64 executable whose PLT entry for puts starts with BTI.
 * lld adds `bti c` to a PLT entry whose address escapes; a non-PIE executable that takes
 * the address of puts gives its entry a canonical address, so the entry is
 * `bti c; adrp; ldr; add; br`. abort's entry is the plain four-instruction form. */
#include <stdio.h>
#include <stdlib.h>

int (*volatile print)(const char *);

int main(int argc, char **argv) {
  (void)argv;
  if (argc > 5) {
    abort();
  }
  print = puts; /* adrp/add of puts in code: its PLT entry is its address */
  return print("bti");
}
