/* A library loaded with dlopen by a musl program: it needs libextra.so.1, which the program does
   not, so musl's search for it from the library's own scope is reached. Written for Donkey's tests (MIT). */
int extra_fn(void);
int plugin_fn(void) { return extra_fn(); }
