/* A stand-in for the C library, written for Donkey's tests (MIT). It defines the names the
   fixtures import, with glibc's version names, so that a test sysroot can hold a "libc.so.6"
   without any glibc code. The bodies are never run. */
void abort(void) { for (;;) { } }
void exit(int status) { (void)status; for (;;) { } }
int puts(const char *s) { (void)s; return 0; }
int __libc_start_main(void) { return 0; }
