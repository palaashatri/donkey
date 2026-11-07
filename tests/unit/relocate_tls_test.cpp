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

// A global-dynamic access (`__tls_get_addr`) is relaxed in a static link, as `ld` does: the
// 16-byte call sequence becomes `mov %fs:0,%rax; lea tpoff(%rax),%rax`, and the call's
// relocation is consumed. The 85 bytes of read_tls are the bytes `ld -static` writes for the
// same object (tests/fixtures/objects/PROVENANCE.md).
TEST(RelocateTls, GlobalDynamicAccessesRelaxToTheLinkersThreadPointerOffsets) {
  auto loaded = donkey::load_binary(object_path("tls-global-dynamic-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_FALSE(loaded.value().image.partial);

  const donkey::Symbol* read = defined_symbol(loaded.value().image, "read_tls");
  ASSERT_NE(read, nullptr);
  const std::vector<std::byte> linked = bytes_at(loaded.value(), read->address, 85);
  ASSERT_EQ(linked.size(), 85U);
  EXPECT_EQ(linked, hex_bytes("f30f1efa554889e5534883ec0864488b042500000000488d80f0ffffff488b40"
                              "0889c364488b042500000000488d80e0ffffff8b0001c364488b042500000000"
                              "488d80e4ffffff0fb6000fbec001d8488b5df8c9c3"));
}

// A local-dynamic access calls __tls_get_addr once for the module block; the 12-byte sequence
// becomes a thread-pointer load, and each variable's DTPOFF32 becomes its thread-pointer offset.
// The 65 bytes of read_ld are the bytes `ld -static` writes for the same object.
TEST(RelocateTls, LocalDynamicAccessesRelaxToTheLinkersOffsets) {
  auto loaded = donkey::load_binary(object_path("tls-local-dynamic-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_FALSE(loaded.value().image.partial);

  const donkey::Symbol* read = defined_symbol(loaded.value().image, "read_ld");
  ASSERT_NE(read, nullptr);
  const std::vector<std::byte> linked = bytes_at(loaded.value(), read->address, 65);
  ASSERT_EQ(linked.size(), 65U);
  EXPECT_EQ(linked,
            hex_bytes("f30f1efa554889e5534883ec0866666664488b0425000000004805f0ffffff48"
                      "8b400889c366666664488b0425000000004805e8ffffff8b0001d8488b5df8c9c3"));
}

// A global-dynamic access to a variable this object does not define cannot be relaxed: the
// variable's offset is unknown here. It stays partial, and the call is still reported as
// unresolved rather than guessed.
TEST(RelocateTls, GlobalDynamicAccessToAnUndefinedVariableStaysPartial) {
  auto loaded = donkey::load_binary(object_path("tls-global-dynamic-extern-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_TRUE(loaded.value().image.partial);
  bool unresolved = false;
  for (const donkey::Diagnostic& diagnostic : loaded.value().image.diagnostics) {
    if (diagnostic.code == "elf.relocation_unresolved") {
      unresolved = true;
    }
  }
  EXPECT_TRUE(unresolved);
}
