/* A callee with seven integer arguments: the seventh is passed on the stack. Written for this
   repository. */
__attribute__((noinline)) long seven(long a, long b, long c, long d, long e, long f, long g) {
  return a + b + c + d + e + f + g * 3;
}

__attribute__((noinline)) long caller(long x) {
  return seven(x, 1, 2, 3, 4, 5, 6) + 1;
}

int main(int argc, char **argv) {
  (void)argv;
  return (int)caller(argc);
}
