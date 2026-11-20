/* Needs libextra.so.1 (found by musl's search path) and the C library. Written for Donkey's tests (MIT). */
#include <stdio.h>
int extra_fn(void);
int main(void) { return puts("extra") + extra_fn(); }
