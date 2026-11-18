// libFuzzer entry point for the readers of ElfLoadScope (G24-T3): the input is read as an
// ld.so.cache image (read_loader_cache), then parsed as a binary and, when it is an ELF image, read
// as a library of a scope (its dynamic table, dynamic symbols, symbol versions and version
// definitions), then looked up with versioned, hidden and unversioned references. The harness
// asserts that nothing crashes, that every cache entry lies within the input, and that a Bound
// answer names a library of the scope.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_load_scope <scratch corpus copy> -max_total_time=60

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>

#include "donkey/binary/elf_load_scope.h"
#include "donkey/binary/image.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 1U << 20;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
  if (const auto cache = donkey::read_loader_cache(bytes); cache.has_value()) {
    for (const donkey::ElfLoaderCacheEntry& entry : cache.value()) {
      if (entry.name.size() >= size || entry.path.size() >= size) {
        std::abort();
      }
    }
  }
  auto image = donkey::parse_binary(bytes, "fuzz.so");
  if (!image) {
    return 0;
  }
  const std::array<donkey::ElfLoadScope::Input, 2> inputs = {
      donkey::ElfLoadScope::Input{"executable", nullptr, {}},
      donkey::ElfLoadScope::Input{"fuzz.so", &image.value(), bytes}};
  const donkey::ElfLoadScope scope = donkey::ElfLoadScope::from_images(inputs);
  for (const char* name : {"exit", "abort", "puts", ""}) {
    for (const char* version : {"", "GLIBC_2.2.5", "GLIBC_2.17"}) {
      for (const bool hidden : {false, true}) {
        const donkey::ElfBinding binding = scope.lookup(name, version, hidden);
        if (binding.outcome == donkey::ElfBinding::Outcome::Bound &&
            binding.library >= scope.libraries().size()) {
          std::abort();
        }
      }
    }
  }
  return 0;
}
