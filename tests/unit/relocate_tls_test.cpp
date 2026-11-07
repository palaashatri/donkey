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

// AArch64 uses variant I: the thread-pointer offset of a block variable is 16 plus its offset in
// the block. The local-exec object's read_tls is the 64 bytes `ld -static` writes for it (the
// ADD TPREL immediates); the test is in tests/fixtures/objects/PROVENANCE.md.
TEST(RelocateTls, LocalExecAArch64ImmediatesAreTheLinkersVariantOneOffsets) {
  auto loaded = donkey::load_binary(object_path("tls-local-exec-aarch64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_FALSE(loaded.value().image.partial);

  const donkey::Symbol* read = defined_symbol(loaded.value().image, "read_tls");
  ASSERT_NE(read, nullptr);
  const std::vector<std::byte> linked = bytes_at(loaded.value(), read->address, 64);
  ASSERT_EQ(linked.size(), 64U);
  EXPECT_EQ(linked,
            hex_bytes("40d03bd50000409100600091000440f9e103002a40d03bd500004091004000"
                      "91000040b92000000b41d03bd52100409121500091210040390000010bc0035fd6"));
}

// A TLSDESC access (GCC's default for -fPIC) is relaxed by a static link, as `ld` relaxes it:
// adrp, ldr, add and blr become movz, movk, nop and nop, and the rest of the sequence is the same.
// The 112 bytes of read_tls are the bytes `ld -static` writes for the same object.
TEST(RelocateTls, GlobalDynamicAArch64AccessesRelaxToTheLinkersOffsets) {
  auto loaded = donkey::load_binary(object_path("tls-global-dynamic-aarch64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  EXPECT_FALSE(loaded.value().image.partial);

  const donkey::Symbol* read = defined_symbol(loaded.value().image, "read_tls");
  ASSERT_NE(read, nullptr);
  const std::vector<std::byte> linked = bytes_at(loaded.value(), read->address, 112);
  ASSERT_EQ(linked.size(), 112U);
  EXPECT_EQ(linked, hex_bytes("fd7bbfa9fd0300910000a0d2000380f21f2003d51f2003d541d03bd520000"
                              "08b000440f9e203002a0000a0d2000280f21f2003d51f2003d541d03bd52000"
                              "008b000040b94100000b0000a0d2800280f21f2003d51f2003d542d03bd54000"
                              "008b000040392000000bfd7bc1a8c0035fd6"));
}

// The initial-exec object loads its variables' thread-pointer offsets from GOT slots, which is
// valid as it stands; each slot holds the offset of its variable (16, 20 and 24, the variant I
// offsets of tls_counter, tls_byte and tls_pair).
TEST(RelocateTls, InitialExecAArch64SlotsHoldTheThreadPointerOffsets) {
  auto loaded = donkey::load_binary(object_path("tls-initial-exec-aarch64.o"));
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
  const std::vector<std::byte> bytes = bytes_at(loaded.value(), got->address, 24);
  ASSERT_EQ(bytes.size(), 24U);
  std::vector<std::uint64_t> slots;
  for (std::size_t i = 0; i < 24; i += 8) {
    std::uint64_t value = 0;
    for (std::size_t b = 0; b < 8; ++b) {
      value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[i + b])) << (8 * b);
    }
    slots.push_back(value);
  }
  std::sort(slots.begin(), slots.end());
  EXPECT_EQ(slots, (std::vector<std::uint64_t>{0x10, 0x14, 0x18}));
}
