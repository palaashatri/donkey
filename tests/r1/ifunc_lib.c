/* G20-T2 fixture: a shared library with an STT_GNU_IFUNC symbol beside plain STT_FUNC ones, so the
   R1 symbol ground truth is checked against readelf for both types. Built by tests/CMakeLists.txt on
   ELF hosts with GCC or Clang. */
static int implementation(int x) { return x + 1; }
static int (*resolve_entry(void))(int) { return implementation; }
int ifunc_entry(int x) __attribute__((ifunc("resolve_entry")));
int plain(int x) { return x * 2; }
int another(int x, int y) { return plain(x) - y; }
