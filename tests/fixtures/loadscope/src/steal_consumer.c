/* Imports exit@GLIBC_2.2.5 and needs libsteal.so.1 before libc.so.6. Written for Donkey's tests (MIT). */
#include <stdio.h>
#include <stdlib.h>
int steal_marker(void);
int main(int argc, char **argv) {
  (void)argv;
  if (argc > 5) {
    exit(steal_marker());
  }
  puts("after the call");
  return 0;
}
