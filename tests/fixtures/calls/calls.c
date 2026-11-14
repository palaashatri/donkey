/* A small x86-64 ELF for the G21 CLI test. add2 is a static noinline helper of the same image, so
   the call in caller_add is direct and its signature is recovered from add2's own code. Built with
   gcc -O0 -o calls-x86_64 calls.c (own source). */
__attribute__((noinline, used)) static int add2(int a, int b) {
  return a + b;
}

__attribute__((noinline, used)) int caller_add(int a, int b) {
  return add2(a, b) + 1;
}

int main(void) {
  return caller_add(1, 2);
}
