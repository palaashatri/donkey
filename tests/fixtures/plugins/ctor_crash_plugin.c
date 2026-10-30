#include <stddef.h>

#include "donkey/plugin/plugin_abi.h"

#if defined(__GNUC__) || defined(__clang__)
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

const DonkeyPluginDescriptor* donkey_plugin_entry(void) {
  return &kDescriptor;
}
