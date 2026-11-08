/* A string-literal fixture (G12-T2). Built with Clang 18 for x86-64 Linux, non-PIE, so the string and
 * the code have fixed addresses:
 *   clang-18 -O0 -fno-pie -no-pie -fno-stack-protector -o hello-x86_64 hello.c
 * The string is referenced by a lea and passed to puts. */
#include <stdio.h>

int main(void) {
  puts("hello, donkey");
  return 0;
}
