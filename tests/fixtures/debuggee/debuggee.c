/* Debuggee for the native debugger tests. Built by the test suite from this
 * source (no prebuilt binary is committed). Exported symbols let the tests
 * find functions and data through the static image on every platform.
 *
 *   debuggee        tick three times; exit 42 when the counter is 3,
 *                   otherwise exit with the counter value
 *   debuggee spin   loop until killed (for pause/attach tests)
 */
#include <string.h>

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

DEBUGGEE_EXPORT int main(int argc, char** argv) {
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
