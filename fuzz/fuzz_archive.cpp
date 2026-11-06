// libFuzzer entry point for the static archive reader (G15-T1). Every input is read as
// an `ar` archive. The harness asserts that an accepted index never names bytes outside
// the input, and that the member count stays within the reader's limit.
//
// Build: cmake --preset fuzz-macos
// Run:   build/fuzz-macos/fuzz_archive tests/fuzz/corpus/archive -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/archive.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
  const donkey::ArchiveOptions options;
  const auto index = donkey::read_archive(bytes, options);
  if (!index) {
    if (index.diagnostic().code.empty()) {
      std::abort();
    }
    return 0;
  }
  if (index.value().members.size() > options.max_members) {
    std::abort();
  }
  for (const donkey::ArchiveMember& member : index.value().members) {
    if (member.offset > size || member.size > size - member.offset) {
      std::abort();  // a member must lie inside the archive
    }
  }
  return 0;
}
