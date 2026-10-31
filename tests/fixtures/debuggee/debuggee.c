/* Debuggee for the native debugger tests. Built by the test suite from this
 * source (no prebuilt binary is committed). Exported symbols let the tests
 * find functions and data through the static image on every platform.
 *
 *   debuggee        tick three times; exit 42 when the counter is 3,
 *                   otherwise exit with the counter value
 *   debuggee spin   loop until killed (for pause/attach tests)
 *   debuggee load M load the shared library M after start-up (dlopen /
 *                   LoadLibrary), call donkey_debuggee_module_loaded(), then
 *                   exit with donkey_module_answer(21) (42) -- the dynamic
 *                   module fixture
 */
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#if defined(_WIN32)
#define DEBUGGEE_EXPORT __declspec(dllexport)
#define DEBUGGEE_NOINLINE __declspec(noinline)
#else
#define DEBUGGEE_EXPORT __attribute__((visibility("default"), used))
#define DEBUGGEE_NOINLINE __attribute__((noinline))
#endif

DEBUGGEE_EXPORT volatile int donkey_debuggee_counter = 0;
DEBUGGEE_EXPORT volatile int donkey_debuggee_step = 1;
DEBUGGEE_EXPORT volatile int donkey_debuggee_spinning = 1;

DEBUGGEE_EXPORT DEBUGGEE_NOINLINE void donkey_debuggee_tick(void) {
  donkey_debuggee_counter += donkey_debuggee_step;
}

typedef int (*donkey_answer_fn)(int);

/* Runtime address of donkey_module_answer once the module is loaded. */
DEBUGGEE_EXPORT volatile uint64_t donkey_debuggee_module_function = 0;

/* Breakpoint target: the module is loaded when this runs. */
DEBUGGEE_EXPORT DEBUGGEE_NOINLINE void donkey_debuggee_module_loaded(void) {
  donkey_debuggee_counter += 100;
}

static int run_module(const char* path) {
  donkey_answer_fn answer = 0;
#if defined(_WIN32)
  HMODULE module = LoadLibraryA(path);
  if (module == 0) {
    return 3;
  }
  answer = (donkey_answer_fn)(void (*)(void))GetProcAddress(module, "donkey_module_answer");
#else
  void* module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (module == 0) {
    return 3;
  }
  *(void**)(&answer) = dlsym(module, "donkey_module_answer");
#endif
  if (answer == 0) {
    return 4;
  }
  donkey_debuggee_module_function = (uint64_t)(uintptr_t)answer;
  donkey_debuggee_module_loaded();
  return answer(21);
}

DEBUGGEE_EXPORT int main(int argc, char** argv) {
  if (argc > 2 && strcmp(argv[1], "load") == 0) {
    return run_module(argv[2]);
  }
  if (argc > 1 && strcmp(argv[1], "spin") == 0) {
    while (donkey_debuggee_spinning) {
    }
    return 7;
  }
  for (int i = 0; i < 3; ++i) {
    donkey_debuggee_tick();
  }
  return donkey_debuggee_counter == 3 ? 42 : donkey_debuggee_counter;
}
