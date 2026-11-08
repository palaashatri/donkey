// libFuzzer entry point for the JSON reader (G11). The RPC front end parses every request with it.
// The harness asserts that the reader never crashes, that a rejection carries a `json.` code, and
// that an accepted document stays within the configured limits.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_json <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "donkey/core/json.h"

namespace {

std::size_t depth_of(const donkey::JsonValue& value, std::size_t depth) {
  std::size_t deepest = depth;
  for (const donkey::JsonValue& child : value.items) {
    const std::size_t below = depth_of(child, depth + 1);
    if (below > deepest) {
      deepest = below;
    }
  }
  return deepest;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 1U * 1024U * 1024U;
  if (size > kMaxFuzzInput) {
    return 0;
  }
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  const donkey::JsonLimits limits;
  const auto parsed = donkey::parse_json(text, limits);
  if (!parsed) {
    if (parsed.diagnostic().code.rfind("json.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (depth_of(parsed.value(), 0) > limits.max_depth + 1) {
    std::abort();
  }
  // Exercise the lookup the RPC dispatcher uses on every object it receives.
  (void)parsed.value().find("method");
  return 0;
}
