#pragma once

#include <cstdint>
#include <string>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

struct IsolationConfig {
  /// Maximum CPU time allowed for the child parser in seconds (default 5).
  std::uint32_t timeout_seconds = 5;
  /// Maximum address space / memory limit for child parser in bytes (default 512 MB).
  std::uint64_t max_memory_bytes = 512 * 1024 * 1024;
  /// Test-only hook: instruct worker to deliberately crash with SIGSEGV to verify host recovery.
  bool force_worker_crash = false;
  /// Test-only hook: instruct worker to spin forever to verify timeout kill.
  bool force_worker_hang = false;
};

/// Reports whether the current host platform supports real OS process isolation.
[[nodiscard]] bool process_isolation_available() noexcept;

/// Parse untrusted binary file inside an isolated OS process boundary.
/// If the parser process crashes (e.g. SIGSEGV, SIGABRT, SIGBUS) or hangs/OOMs,
/// the host application catches the fault cleanly, does not crash, and returns
/// an error Diagnostic (e.g. Status::InvalidData with "binary.worker_crashed" or
/// Status::ResourceLimit with "binary.worker_timeout").
[[nodiscard]] Result<LoadedBinary> load_binary_isolated(const std::string& path,
                                                        const LoadOptions& options = {},
                                                        const IsolationConfig& config = {});

}  // namespace donkey
