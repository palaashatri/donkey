/* Entry point for the MIPS32 and PowerPC32 ISA fixtures (G13-T3). The call crosses translation
 * units, so the relocation names the global isa_branches symbol. `_start` ends in a self-jump, so
 * the image has a direct branch to its own address. */
extern int isa_branches(int count, int limit);

void _start(void) {
  isa_branches(10, 5);
  for (;;) {
  }
}
