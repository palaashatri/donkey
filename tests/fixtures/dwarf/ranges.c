/* DWARF fixture for functions described by DW_AT_ranges. Built by the test
 * suite at -O2 -g: GCC moves the unlikely branch of donkey_ranges_split into a
 * separate .cold part, so its DW_TAG_subprogram has DW_AT_ranges instead of
 * DW_AT_low_pc/high_pc. Written for Donkey; no third-party code. */
#if defined(_WIN32)
#define FIXTURE_EXPORT __declspec(dllexport)
#else
#define FIXTURE_EXPORT __attribute__((visibility("default"), used))
#endif

__attribute__((cold, noinline)) void donkey_ranges_slow(int x);

FIXTURE_EXPORT void donkey_ranges_slow(int x) {
  volatile int y = x;
  (void)y;
}

FIXTURE_EXPORT __attribute__((noinline)) int donkey_ranges_split(int x) {
  if (__builtin_expect(x == 12345, 0)) {
    donkey_ranges_slow(x);
    donkey_ranges_slow(x + 1);
  }
  return x * 3 + 1;
}
