#include <stddef.h>

#include "donkey/plugin/plugin_abi.h"

#if defined(_WIN32)
#include <windows.h>

/* Loading this DLL into any process ends that process with exit code 86, so
 * a host that loads it in-process instead of failing closed cannot print the
 * diagnostic its test expects. */
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)instance;
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    ExitProcess(86);
  }
  return TRUE;
}
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((constructor)) static void crash_on_load(void) {
  volatile int* p = NULL;
  *p = 99;
}
#endif

static const DonkeyPluginDescriptor kDescriptor = {
    sizeof(DonkeyPluginDescriptor),
    DONKEY_PLUGIN_ABI_VERSION_MAJOR,
    DONKEY_PLUGIN_ABI_VERSION_MINOR,
    "org.donkey.test.ctor_crash",
    "Constructor Crash Plugin",
    "1.0.0",
    "Donkey Team",
    "Crashes in library constructor during load",
    DONKEY_CAP_NONE,
    NULL,
    NULL,
    NULL,
};

DONKEY_PLUGIN_EXPORT const DonkeyPluginDescriptor* donkey_plugin_entry(void) {
  return &kDescriptor;
}
