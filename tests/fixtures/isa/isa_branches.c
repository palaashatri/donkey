/* A loop with a conditional branch, linked freestanding for MIPS32 and PowerPC32 (G13-T3) with
 * isa_branches_start.c, whose `_start` calls this function from another translation unit. */
int isa_branches(int count, int limit) {
  int sum = 0;
  for (int i = 0; i < count; i++) {
    if (limit > i) {
      sum += i;
    } else {
      sum -= i;
    }
  }
  return sum;
}
