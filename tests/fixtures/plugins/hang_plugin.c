#include <stddef.h>

#include "donkey/plugin/plugin_abi.h"

static int hang_execute(const char* input_json, char* output_buf, size_t output_buf_len) {
  (void)input_json;
  (void)output_buf;
  (void)output_buf_len;
  // Deliberately hang indefinitely
  while (1) {
  }
  return 0;
}

static const DonkeyPluginDescriptor kDescriptor = {
    sizeof(DonkeyPluginDescriptor),
    DONKEY_PLUGIN_ABI_VERSION_MAJOR,
    DONKEY_PLUGIN_ABI_VERSION_MINOR,
    "org.donkey.test.hang",
    "Hang Plugin",
    "1.0.0",
    "Donkey Team",
    "Intentionally hangs in execute",
    DONKEY_CAP_NONE,
    NULL,
    NULL,
    hang_execute,
};

const DonkeyPluginDescriptor* donkey_plugin_entry(void) {
  return &kDescriptor;
}
