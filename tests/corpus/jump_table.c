/* Jump-table fixture (G03-T3). A dense 16-case switch whose cases compute from
 * the second argument. A case that returns a constant lets the compiler turn
 * the switch into a data-table lookup, which is not an indirect jump, so the
 * cases here depend on `y`. At -O2 GCC and Clang lower this switch to a code
 * jump table on AArch64 (a byte-offset table, `adr`, `add ... sxtb|uxtb #2`
 * and `br`) and on x86-64 (a table of absolute or relative offsets).
 *
 * Built by the test suite at -O2 with the host C compiler, separately from
 * corpus.c so that the corpus counts stay as they are. */
#include <stdint.h>

#if defined(_WIN32)
#define CORPUS __declspec(dllexport) __declspec(noinline)
#else
#define CORPUS __attribute__((visibility("default"))) __attribute__((noinline))
#endif

CORPUS int jt_dispatch16(int x, int y) {
  switch (x) {
    case 0:
      return y + 1;
    case 1:
      return y * 3;
    case 2:
      return y - 7;
    case 3:
      return y ^ 5;
    case 4:
      return (int)((uint32_t)y << 2);
    case 5:
      return y >> 1;
    case 6:
      return y | 9;
    case 7:
      return y & 6;
    case 8:
      return y + 25;
    case 9:
      return y * 5;
    case 10:
      return y - 31;
    case 11:
      return y ^ 34;
    case 12:
      return (int)((uint32_t)y << 3);
    case 13:
      return (int)((uint32_t)y >> 4);
    case 14:
      return y | 19;
    case 15:
      return y & 22;
    default:
      return -1;
  }
}
