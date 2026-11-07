#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"

namespace {

std::string object_path(const char* name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/objects/" + name;
}

const donkey::Symbol* defined_symbol(const donkey::BinaryImage& image, const std::string& name) {
  for (const donkey::Symbol& symbol : image.symbols) {
    if (symbol.name == name && !symbol.imported) {
      return &symbol;
    }
  }
  return nullptr;
}

/// The bytes at `address` in the linked image, or an empty vector when no section with file
/// data holds the whole range.
std::vector<std::byte> bytes_at(const donkey::LoadedBinary& loaded, std::uint64_t address,
                                std::size_t length) {
  for (const donkey::Section& section : loaded.image.sections) {
    if (!section.has_file_data || address < section.address ||
        address - section.address >= section.file_size || length > section.file_size) {
      continue;
    }
    const std::uint64_t offset = section.file_offset + (address - section.address);
    if (offset > loaded.data.size() || length > loaded.data.size() - offset) {
      return {};
    }
    const std::span<const std::byte> bytes = loaded.data.span();
    return std::vector<std::byte>(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                  bytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
  }
  return {};
}

std::vector<std::byte> hex_bytes(const std::string& hex) {
  std::vector<std::byte> out;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<std::byte>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

}  // namespace

// The local-exec object is a gcc build of tests/fixtures/objects/tls.c. `read_tls` is the same
// bytes as in the executable `ld` links from it: the thread-pointer offsets (TPOFF32) of
// tls_counter (-0x20), tls_byte (-0x1c) and tls_pair+8 (-0x8) are the linker's, and the
// function has no other addresses. See tests/fixtures/objects/PROVENANCE.md.
TEST(RelocateTls, LocalExecOffsetsAreTheLinkersThreadPointerOffsets) {
  auto loaded = donkey::load_binary(object_path("tls-local-exec-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_FALSE(loaded.value().image.partial);

  const donkey::Symbol* read = defined_symbol(loaded.value().image, "read_tls");
  ASSERT_NE(read, nullptr);
  const std::vector<std::byte> linked = bytes_at(loaded.value(), read->address, 45);
  ASSERT_EQ(linked.size(), 45U);
  EXPECT_EQ(linked, hex_bytes("f30f1efa554889e564488b0425f8ffffff89c2648b0425e0ffffff01c2640fb6"
                              "0425e4ffffff0fbec001d05dc3"));
}

// The initial-exec object reaches its variables through GOT slots (R_X86_64_GOTTPOFF), and
// each slot holds the thread-pointer offset. `ld` relaxes these accesses in a static link, so
// the expected offsets are the linker's layout of the same TLS block: -0x20, -0x1c and -0x10.
TEST(RelocateTls, InitialExecSlotsHoldTheThreadPointerOffsets) {
  auto loaded = donkey::load_binary(object_path("tls-initial-exec-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_FALSE(loaded.value().image.partial);

  const donkey::Section* got = nullptr;
  for (const donkey::Section& section : loaded.value().image.sections) {
    if (section.name == ".got") {
      got = &section;
    }
  }
  ASSERT_NE(got, nullptr);
  ASSERT_EQ(got->file_size, 24U);  // one slot per thread-local symbol the code names
  std::vector<std::uint64_t> slots;
  const std::vector<std::byte> bytes = bytes_at(loaded.value(), got->address, 24);
  ASSERT_EQ(bytes.size(), 24U);
  for (std::size_t i = 0; i < 24; i += 8) {
    std::uint64_t value = 0;
    for (std::size_t b = 0; b < 8; ++b) {
      value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[i + b])) << (8 * b);
    }
    slots.push_back(value);
  }
  std::sort(slots.begin(), slots.end());
  EXPECT_EQ(slots, (std::vector<std::uint64_t>{0xffffffffffffffe0ULL, 0xffffffffffffffe4ULL,
                                               0xfffffffffffffff0ULL}));
}

// A global-dynamic access (`__tls_get_addr`) needs the dynamic linker, which a single static
// object cannot provide. It is reported as a relocation that is not applied: the image is
// partial, never a guessed address.
TEST(RelocateTls, GlobalDynamicAccessesAreReportedNotGuessed) {
  auto loaded = donkey::load_binary(object_path("tls-global-dynamic-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_TRUE(loaded.value().image.partial);
  bool reported = false;
  for (const donkey::Diagnostic& diagnostic : loaded.value().image.diagnostics) {
    if (diagnostic.code == "elf.relocation_type") {
      reported = true;
    }
  }
  EXPECT_TRUE(reported);
}
