// libFuzzer entry point for the ELF version-need reader (G24-T3). The first two bytes give the
// length of the string table; it and the `.gnu.version_r` bytes follow. The harness asserts that
// the reader never crashes, that a refusal carries an `elf.version_needs` code, that the entry
// counts stay within the limit, and that every index it returns is a version-need index (2 or more).
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_elf_versions <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/elf_versions.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 1U << 20;
  if (size < 2 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::size_t string_size =
      std::min<std::size_t>(size - 2, static_cast<std::size_t>(data[0]) | (data[1] << 8U));
  const auto* bytes = reinterpret_cast<const std::byte*>(data + 2);
  const std::span<const std::byte> strings(bytes, string_size);
  const std::span<const std::byte> section(bytes + string_size, size - 2 - string_size);
  constexpr std::size_t kLimit = 1024;
  const auto result = donkey::read_version_needs(section, strings, kLimit);
  if (!result) {
    if (result.diagnostic().code.rfind("elf.version_needs", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  const donkey::ElfVersionNeeds& needs = result.value();
  if (needs.files + needs.entries > kLimit || needs.by_index.size() != needs.entries) {
    std::abort();
  }
  for (const auto& [index, need] : needs.by_index) {
    if (index < 2) {
      std::abort();
    }
  }
  return 0;
}
