/* A library for the musl fixtures, written for Donkey's tests (MIT): one function, with a symbol
   version, so the scope reaches a library with a version table under musl's loader. */
int extra_fn(void) { return 1; }
