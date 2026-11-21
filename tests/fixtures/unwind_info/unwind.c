/* G23-T3 fixture: functions with different compact unwind encodings, reached only through a
   pointer table in data. Linked without LC_FUNCTION_STARTS and stripped, their starts are known
   only from __TEXT,__unwind_info. */
static int leaf(int x) { return x * 2; }
static int __attribute__((noinline)) sum_to(int n) {
  volatile int buffer[64];
  int total = 0;
  for (int i = 0; i < n && i < 64; ++i) {
    buffer[i] = i;
    total += buffer[i];
  }
  return total;
}
static int __attribute__((noinline)) keeps(int a, int b) {
  int first = sum_to(a);
  int second = sum_to(b);
  return first * second + a - b;
}
static int __attribute__((noinline)) variable(int n) {
  volatile char bytes[n > 0 ? n : 1];
  bytes[0] = (char)n;
  return bytes[0] + keeps(n, n + 1);
}
int (*const table[4])(int) = {leaf, sum_to, variable, leaf};
int run(int which, int x) { return table[which & 3](x) + keeps(x, which); }
int main(void) { return run(1, 2); }
