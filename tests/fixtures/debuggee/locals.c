/* Stack parameters and locals with debug information (G04-T4 stack slots). Built by the test suite at -O0 -g with frame pointers. Written for this repository. */
__attribute__((visibility("default"), used, noinline))
int donkey_locals_sum(int first, int second) {
  int total = first;
  int scaled = second * 3;
  total = total + scaled;
  return total;
}
