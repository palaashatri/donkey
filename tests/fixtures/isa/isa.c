/* Small freestanding functions for the A32 and RISC-V decoders (G13). Written for this
   repository: loops, a comparison, a call, and memory access. */
int fib(int n) {
  int a = 0, b = 1;
  while (n-- > 0) {
    int t = a + b;
    a = b;
    b = t;
  }
  return a;
}

int pick(int x, int y) {
  return x > y ? x * 3 : y - 7;
}

int sum(const int *v, int n) {
  int s = 0;
  for (int i = 0; i < n; i++) s += v[i];
  return s;
}

int combine(const int *v, int n, int k) {
  return pick(sum(v, n), fib(k));
}

void _start(void) {
  for (;;) {
  }
}
