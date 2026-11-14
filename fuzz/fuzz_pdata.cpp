// libFuzzer entry point for the PE x64 exception-directory reader (G23-T2). The input is a file.
// It is parsed as a binary; a PE image's RUNTIME_FUNCTION entries are read. The harness asserts
// that the reader never crashes, that a rejection carries a `pe.` or `binary.` code, that every
// range it reports is non-empty, and that the counts add up.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_pdata <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>

#include "donkey/binary/image.h"
#include "donkey/binary/pdata.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 4U * 1024U * 1024U;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
  auto image = donkey::parse_binary(bytes, "<fuzz>");
  if (!image) {
    return 0;
  }
  constexpr std::size_t kLimit = 4096;
  auto read = donkey::read_pdata_of_image(image.value(), bytes, kLimit);
  if (!read) {
    if (read.diagnostic().code.rfind("pe.", 0) != 0 &&
        read.diagnostic().code.rfind("binary.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  const donkey::PdataReadResult& result = read.value();
  if (result.entries > kLimit || result.chained + result.malformed > result.entries ||
      result.functions.size() + result.chained + result.malformed > result.entries) {
    std::abort();
  }
  for (const donkey::PdataFunction& function : result.functions) {
    if (function.start == 0 || function.size == 0) {
      std::abort();
    }
  }
  return 0;
}
