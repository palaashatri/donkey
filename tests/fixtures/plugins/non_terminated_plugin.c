#include <stddef.h>
#include <string.h>

#include "donkey/plugin/plugin_abi.h"

static int no_null_term_execute(const char* input_json, char* output_buf, size_t output_buf_len) {
  (void)input_json;
  if (output_buf != NULL && output_buf_len > 0) {
    memset(output_buf, 'Z', output_buf_len);
  }
  return 0;
}

static const DonkeyPluginDescriptor kDescriptor = {
    sizeof(DonkeyPluginDescriptor),
    DONKEY_PLUGIN_ABI_VERSION_MAJOR,
    DONKEY_PLUGIN_ABI_VERSION_MINOR,
    "org.donkey.test.no_null_term",
    "Non-Null-Terminated Plugin",
    "1.0.0",
    "Donkey Team",
    "Fills buffer without null terminator",
    DONKEY_CAP_NONE,
    NULL,
    NULL,
    no_null_term_execute,
};

DONKEY_PLUGIN_EXPORT const DonkeyPluginDescriptor* donkey_plugin_entry(void) {
  return &kDescriptor;
}
