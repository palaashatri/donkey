#pragma once

// An Itanium C++ ABI demangler (G10-T1). Written from the public ABI grammar; it does not
// use any demangler's source. The output follows GNU c++filt's spelling, which is what the
// corpus test (tests/fixtures/cpp/itanium-pairs.txt) records.

#include <cstddef>
#include <string>
#include <string_view>

#include "donkey/core/result.h"

namespace donkey {

struct DemangleOptions {
  std::size_t max_input_bytes = 4096;
  int max_depth = 256;
  std::size_t max_output_bytes = 16 * 1024;
};

/// True when `name` begins with the Itanium `_Z` prefix.
[[nodiscard]] bool is_itanium_name(std::string_view name) noexcept;

/// Demangles an Itanium-ABI name, for example `_ZN3foo3barEi` to `foo::bar(int)`.
/// Errors are `InvalidInput` with a code under `demangle.`: `not_mangled` for a name
/// without the `_Z` prefix, `syntax` for a malformed or unsupported name, and
/// `too_long`, `too_deep` and `too_large` for the limits in `DemangleOptions`.
[[nodiscard]] Result<std::string> demangle_itanium(std::string_view name,
                                                   const DemangleOptions& options = {});

}  // namespace donkey
