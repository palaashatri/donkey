#pragma once

#include <cstdint>
#include <string>

#include "donkey/core/result.h"
#include "donkey/core/status.h"
#include "donkey/plugin/plugin_abi.h"

namespace donkey {

struct PluginManifest {
  std::string id;
  std::string name;
  std::string version;
  std::string author;
  std::string description;
  uint32_t abi_version_major = 0;
  uint32_t abi_version_minor = 0;
  uint64_t requested_capabilities = 0;
};

struct PluginExecutionResult {
  bool success = false;
  std::string output_json;
  std::string error_code;
  std::string error_message;
  int exit_code = 0;
  bool crashed = false;
  int termination_signal = 0;
  bool timed_out = false;
};

class PluginHost {
 public:
  PluginHost() = default;

  /// Inspect a plugin library manifest without running full initialization.
  /// Rejects incompatible ABI versions with Diagnostic.
  static Result<PluginManifest> inspect_manifest(const std::string& library_path);

  /// Execute a trusted plugin in-process. Checks requested capabilities against
  /// granted_capabilities.
  static Result<PluginExecutionResult> execute_trusted(
      const std::string& library_path, const std::string& input_json,
      uint64_t granted_capabilities = DONKEY_CAP_NONE);

  /// Execute an untrusted plugin inside an isolated child process with CPU/memory limits
  /// and crash isolation (Acceptance scenario A20).
  static Result<PluginExecutionResult> execute_isolated(
      const std::string& library_path, const std::string& input_json,
      uint64_t granted_capabilities = DONKEY_CAP_NONE, uint32_t timeout_seconds = 3,
      size_t max_memory_bytes = 64 * 1024 * 1024);
};

}  // namespace donkey
