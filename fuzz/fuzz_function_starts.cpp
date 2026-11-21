// libFuzzer entry point for the LC_FUNCTION_STARTS reader (G23-T3). The input is the bytes of one
// table. The harness asserts that the reader never crashes, that a rejection carries a
// `function_starts.` code, and that every start it returns is inside the __TEXT range it was given,
// strictly ascending, and within the entry limit.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_function_starts <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/function_starts.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 1U << 20;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> table(reinterpret_cast<const std::byte*>(data), size);
  constexpr std::uint64_t kText = 0x100000000;
  constexpr std::uint64_t kTextSize = 0x10000;
  constexpr std::size_t kLimit = 4096;
  // The first byte picks the Thumb form, so both are reached.
  const bool thumb = (data[0] & 1U) != 0;
  const auto result = donkey::read_function_starts(table, kText, kTextSize, thumb, kLimit);
  if (!result) {
    if (result.diagnostic().code.rfind("function_starts.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (result.value().size() > kLimit) {
    std::abort();
  }
  std::uint64_t previous = 0;
  for (const std::uint64_t start : result.value()) {
    if (start < kText || start >= kText + kTextSize || (thumb && (start & 1U) != 0) ||
        (previous != 0 && start < previous)) {
      std::abort();
    }
    previous = start;
  }
  return 0;
}
