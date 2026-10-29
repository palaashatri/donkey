#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace donkey {

/// Typed outcome of a core operation. These values are part of the public
/// contract: callers must not receive an empty success for an unsupported or
/// partially understood operation.
enum class Status : std::uint8_t {
  Success = 0,
  Partial,
  Unsupported,
  InvalidInput,
  ResourceLimit,
  Cancelled,
  PermissionDenied,
  CorruptProject,
  InternalError,
};

/// Stable, human-readable name for a status. Never returns nullptr.
const char* status_name(Status status) noexcept;

/// A diagnostic is safe to display: it contains a stable machine code, a short
/// message and an optional byte offset. It never contains whole binary
/// contents, environment secrets or unbounded exception text.
struct Diagnostic {
  Status status = Status::InternalError;
  std::string code;
  std::string message;
  std::optional<std::uint64_t> offset;

  static Diagnostic make(Status status, std::string code, std::string message,
                         std::optional<std::uint64_t> offset = std::nullopt);
};

}  // namespace donkey
