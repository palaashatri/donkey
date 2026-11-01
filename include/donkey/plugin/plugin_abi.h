#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DONKEY_PLUGIN_ABI_VERSION_MAJOR 1
#define DONKEY_PLUGIN_ABI_VERSION_MINOR 0

#define DONKEY_CAP_NONE (0ULL)
#define DONKEY_CAP_READ_BINARY (1ULL << 0)
#define DONKEY_CAP_PROJECT_READ (1ULL << 1)
#define DONKEY_CAP_PROJECT_WRITE (1ULL << 2)
#define DONKEY_CAP_ANALYSIS (1ULL << 3)
#define DONKEY_CAP_PATCHING (1ULL << 4)
#define DONKEY_CAP_SUBPROCESS (1ULL << 5)
#define DONKEY_CAP_NETWORK (1ULL << 6)

typedef struct DonkeyPluginDescriptor {
  uint32_t struct_size;
  uint32_t abi_version_major;
  uint32_t abi_version_minor;
  const char* id;
  const char* name;
  const char* version;
  const char* author;
  const char* description;
  uint64_t requested_capabilities;

  int (*init)(void);
  void (*shutdown)(void);
  int (*execute)(const char* input_json, char* output_buf, size_t output_buf_len);
} DonkeyPluginDescriptor;

#define DONKEY_PLUGIN_ENTRY_SYMBOL "donkey_plugin_entry"
typedef const DonkeyPluginDescriptor* (*DonkeyPluginEntryFn)(void);

#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(__GNUC__)
#define DONKEY_PLUGIN_EXPORT __attribute__((dllexport))
#else
#define DONKEY_PLUGIN_EXPORT __declspec(dllexport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define DONKEY_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define DONKEY_PLUGIN_EXPORT
#endif

#ifdef __cplusplus
}
#endif
