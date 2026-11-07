// libFuzzer entry point for the Zstandard decoder (G07). The input is a byte stream that may hold
// frames. The harness asserts that the decoder never crashes, that a rejection carries a `zstd.`
// code, and that the output stays within the configured limit.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_zstd <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/zstd.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 1U * 1024U * 1024U;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> input(reinterpret_cast<const std::byte*>(data), size);
  const donkey::ZstdOptions options{4U * 1024U * 1024U};
  const auto decoded = donkey::zstd_decompress(input, options);
  if (!decoded) {
    if (decoded.diagnostic().code.rfind("zstd.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (decoded.value().size() > options.max_output_bytes) {
    std::abort();
  }
  return 0;
}
