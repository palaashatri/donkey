// libFuzzer entry point for the Intel HEX and Motorola S-record decoder (G15-T3). The
// harness asserts that an accepted decode is non-empty, lies within the size limit, and
// does not wrap the 64-bit address space.
//
// Build: cmake --preset fuzz-macos
// Run:   build/fuzz-macos/fuzz_records tests/fuzz/corpus/records -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/records.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::uint64_t kLimit = 1U << 20;
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
  const donkey::RecordFormat format = donkey::detect_record_format(bytes);
  if (format == donkey::RecordFormat::None) {
    return 0;
  }
  const auto decoded = donkey::decode_records(bytes, format, kLimit);
  if (!decoded) {
    if (decoded.diagnostic().code.empty()) {
      std::abort();
    }
    return 0;
  }
  const std::uint64_t length = decoded.value().bytes.size();
  if (length == 0 || length > kLimit || length > UINT64_MAX - decoded.value().base) {
    std::abort();
  }
  return 0;
}
