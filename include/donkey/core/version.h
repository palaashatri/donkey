#pragma once

#include <string_view>

namespace donkey {

/// Semantic version of the linked core, compiled from the CMake project
/// version. Machine output must use this, not a hand-maintained copy.
[[nodiscard]] std::string_view version() noexcept;

/// JSON schema version for machine-readable CLI output. Bump only with a
/// documented schema change.
inline constexpr int kJsonSchemaVersion = 1;

}  // namespace donkey
