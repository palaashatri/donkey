/* GOT relocation fixture (G15-T1). Position-independent code reaches a defined
   global through its GOT slot, so the object carries GOTPCREL (x86-64) and
   ADR_GOT_PAGE / LD64_GOT_LO12_NC (AArch64) relocations. Written for this repository. */
int value = 42;
int *get_value_address(void) { return &value; }
int read_value(void) { return value; }
