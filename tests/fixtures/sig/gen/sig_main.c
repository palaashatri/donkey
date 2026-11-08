/* The program the signature tests match against libsigfuncs.a (G09-T2). It has no C library: the
   entry point exits by syscall. Written for this repository. */

int sig_add(int a, int b);
int sig_mul(int a, int b);
int sig_lookup(int i);
int sig_call_external(int x);

int sig_external(int x) { return x - 1; }

void _start(void) {
  long result = sig_add(sig_mul(2, 3), sig_lookup(1)) + sig_call_external(4);
  __asm__ volatile("syscall" : : "a"(60), "D"(result & 0xff) : "rcx", "r11", "memory");
  for (;;) {
  }
}
