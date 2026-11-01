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
 *   debuggee thread a worker thread ticks three times; the main thread
 *                   waits for it and exits 42 when the counter is 3
 */
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
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

#if defined(_WIN32)
static DWORD WINAPI ticker(LPVOID unused) {
  (void)unused;
#else
static void* ticker(void* unused) {
  (void)unused;
#endif
  for (int i = 0; i < 3; ++i) {
    donkey_debuggee_tick();
  }
  return 0;
}

/* Breakpoints on donkey_debuggee_tick hit in a thread the program created. */
static int run_thread(void) {
#if defined(_WIN32)
  HANDLE thread = CreateThread(0, 0, ticker, 0, 0, 0);
  if (thread == 0) {
    return 5;
  }
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
#else
  pthread_t thread;
  if (pthread_create(&thread, 0, ticker, 0) != 0) {
    return 5;
  }
  pthread_join(thread, 0);
#endif
  return donkey_debuggee_counter == 3 ? 42 : donkey_debuggee_counter;
}

DEBUGGEE_EXPORT int main(int argc, char** argv) {
  if (argc > 1 && strcmp(argv[1], "thread") == 0) {
    return run_thread();
  }
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
