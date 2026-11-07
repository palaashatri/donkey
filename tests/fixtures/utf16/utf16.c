/* A freestanding fixture for the UTF-16 data ranges (G12-T2). Both arrays hold UTF-16 code units,
   which little-endian targets store as UTF-16LE in .rodata, each string with a two-byte zero
   terminator. `greeting` is ASCII. `mixed` holds non-ASCII units, which the Data view shows
   escaped (U+00E9 and U+4E2D). No libc is used, so `unsigned short` stands in for char16_t. */
const unsigned short greeting[] = {0x44, 0x6f, 0x6e, 0x6b, 0x65, 0x79, 0x00};
const unsigned short mixed[] = {0x63, 0x61, 0x66, 0x00e9, 0x20, 0x4e2d, 0x00};

void _start(void) {
  for (;;) {
  }
}
