/* Shared library loaded at run time by `debuggee load` (dynamic module
 * fixture for the debugger tests). Built by the test suite. */
#if defined(_WIN32)
#define MODULE_EXPORT __declspec(dllexport)
#define MODULE_NOINLINE __declspec(noinline)
#else
#define MODULE_EXPORT __attribute__((visibility("default"), used))
#define MODULE_NOINLINE __attribute__((noinline))
#endif

MODULE_EXPORT volatile int donkey_module_calls = 0;

MODULE_EXPORT MODULE_NOINLINE int donkey_module_answer(int value) {
  donkey_module_calls += 1;
  return value * 2;
}
