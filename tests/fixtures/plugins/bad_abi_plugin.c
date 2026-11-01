#include <stddef.h>

#include "donkey/plugin/plugin_abi.h"

static const DonkeyPluginDescriptor kDescriptor = {
    sizeof(DonkeyPluginDescriptor),
    999,  // Deliberately incompatible ABI major version
    0,
    "org.donkey.test.bad_abi",
    "Bad ABI Plugin",
    "1.0.0",
    "Donkey Team",
    "Incompatible ABI version",
    DONKEY_CAP_NONE,
    NULL,
    NULL,
    NULL,
};

DONKEY_PLUGIN_EXPORT const DonkeyPluginDescriptor* donkey_plugin_entry(void) {
  return &kDescriptor;
}
