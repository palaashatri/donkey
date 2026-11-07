// libFuzzer entry point for the zlib decompressor used by compressed debug sections (G07). The
// input is a stream. The harness asserts that the decompressor never crashes, that every
// rejection carries an `inflate.` code, and that the output stays within the configured limit.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_inflate <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/inflate.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> stream(reinterpret_cast<const std::byte*>(data), size);
  const donkey::InflateOptions options;
  const auto out = donkey::inflate_zlib(stream, options);
  if (!out) {
    if (out.diagnostic().code.rfind("inflate.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (out.value().size() > options.max_output_bytes) {
    std::abort();
  }
  return 0;
}
