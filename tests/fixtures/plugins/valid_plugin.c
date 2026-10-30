#include <string.h>

#include "donkey/plugin/plugin_abi.h"

static int valid_init(void) {
  return 0;
}
static void valid_shutdown(void) {}
static int valid_execute(const char* input_json, char* output_buf, size_t output_buf_len) {
  (void)input_json;
  const char* reply = "{\"status\":\"ok\",\"engine\":\"donkey_plugin_v1\"}";
  if (strlen(reply) < output_buf_len) {
    strcpy(output_buf, reply);
    return 0;
  }
  return -1;
}

static const DonkeyPluginDescriptor kDescriptor = {
    sizeof(DonkeyPluginDescriptor),
    DONKEY_PLUGIN_ABI_VERSION_MAJOR,
    DONKEY_PLUGIN_ABI_VERSION_MINOR,
    "org.donkey.test.valid",
    "Valid Test Plugin",
    "1.0.0",
    "Donkey Team",
    "A valid test plugin for unit testing",
    DONKEY_CAP_ANALYSIS,
    valid_init,
    valid_shutdown,
    valid_execute,
};

const DonkeyPluginDescriptor* donkey_plugin_entry(void) {
  return &kDescriptor;
}
