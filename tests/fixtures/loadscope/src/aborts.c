/* libaborts.so.1: a shared library that imports abort@GLIBC_2.2.5. Where that call binds depends
   on the program that loads the library. Written for Donkey's tests (MIT). */
void abort(void);
int checked(int value) {
  if (value < 0) {
    abort();
  }
  return value + 1;
}
