#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/image.h"
#include "donkey/core/result.h"
#include "donkey/core/sha256.h"

namespace {

using donkey::ByteReader;
using donkey::Endian;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

std::vector<std::byte> read_file(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  EXPECT_TRUE(file.good()) << path;
  const std::vector<char> chars((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes(chars.size());
  std::memcpy(bytes.data(), chars.data(), chars.size());
  return bytes;
}

std::vector<std::byte> read_fixture(const std::string& name) {
  return read_file(fixture_path(name));
}

std::string digest_hex(const std::vector<std::byte>& bytes) {
  return donkey::Sha256::hex(bytes);
}

TEST(Sha256, KnownVectors) {
  const auto hex_of = [](std::string_view text) {
    return donkey::Sha256::hex(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
  };
  EXPECT_EQ(hex_of(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(hex_of("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

  std::vector<std::byte> million(1000000, std::byte{'a'});
  EXPECT_EQ(digest_hex(million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

  // Incremental updates must match a single pass at every split point.
  const std::string_view input = "incremental hashing across block boundaries";
  const std::string expected = hex_of(input);
  for (std::size_t split = 0; split <= input.size(); ++split) {
    donkey::Sha256 hasher;
    hasher.update(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), split));
    hasher.update(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(input.data() + split), input.size() - split));
    const auto digest = hasher.finish();
    const std::string actual = donkey::Sha256::hex(digest);
    EXPECT_EQ(actual, expected) << "split=" << split;
  }
}

TEST(ByteReader, ReadsBothEndiannesses) {
  const std::vector<std::byte> bytes{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
      std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
  };
  const ByteReader reader(bytes);
  ASSERT_EQ(reader.size(), 8U);

  auto u16_little = reader.u16(0, Endian::Little);
  ASSERT_TRUE(u16_little.has_value());
  EXPECT_EQ(u16_little.value(), 0x0201U);
  auto u16_big = reader.u16(0, Endian::Big);
  ASSERT_TRUE(u16_big.has_value());
  EXPECT_EQ(u16_big.value(), 0x0102U);

  auto u32_little = reader.u32(2, Endian::Little);
  ASSERT_TRUE(u32_little.has_value());
  EXPECT_EQ(u32_little.value(), 0x06050403U);
  auto u64_big = reader.u64(0, Endian::Big);
  ASSERT_TRUE(u64_big.has_value());
  EXPECT_EQ(u64_big.value(), 0x0102030405060708ULL);
}

TEST(ByteReader, RejectsEveryOutOfBoundsRead) {
  const std::vector<std::byte> bytes(8, std::byte{0});
  const ByteReader reader(bytes);
  EXPECT_FALSE(reader.u8(8).has_value());
  EXPECT_FALSE(reader.u16(7, Endian::Little).has_value());
  EXPECT_FALSE(reader.u32(5, Endian::Little).has_value());
  EXPECT_FALSE(reader.u64(1, Endian::Little).has_value());
  EXPECT_FALSE(reader.slice(7, 2).has_value());
  EXPECT_FALSE(reader.slice(9, 0).has_value());
  EXPECT_EQ(reader.u8(8).diagnostic().code, "reader.out_of_bounds");
  EXPECT_TRUE(reader.slice(8, 0).has_value());
}

TEST(ByteReader, BoundedCStrings) {
  const std::string bytes = std::string("hello\0world", 11);
  const ByteReader reader(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()));
  auto hello = reader.c_string(0, 16);
  ASSERT_TRUE(hello.has_value());
  EXPECT_EQ(hello.value(), "hello");

  auto missing = reader.c_string(0, 5);
  EXPECT_FALSE(missing.has_value());
  EXPECT_EQ(missing.diagnostic().code, "reader.unterminated_string");

  auto beyond = reader.c_string(11, 1);
  EXPECT_FALSE(beyond.has_value());
}

TEST(ByteReader, SanitizesUntrustedNames) {
  EXPECT_EQ(donkey::sanitize_name("normal"), "normal");
  EXPECT_EQ(donkey::sanitize_name(std::string("bad\nname")), "bad?name");
  EXPECT_EQ(donkey::sanitize_name(std::string("\x01\x02", 2)), "<unnamed>");
  EXPECT_EQ(donkey::sanitize_name(""), "<unnamed>");
}

TEST(Binary, LoadsElfMetadata) {
  auto image = donkey::load_binary_file(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(image.has_value()) << image.diagnostic().message;
  const auto& elf = image.value();
  EXPECT_EQ(elf.format, donkey::BinaryFormat::Elf);
  EXPECT_EQ(elf.architecture, donkey::Architecture::X86_64);
  EXPECT_EQ(elf.bits, 64U);
  EXPECT_EQ(elf.endian, Endian::Little);
  EXPECT_EQ(elf.entry_point, 0x400100U);
  EXPECT_EQ(elf.image_base, 0x400000U);
  EXPECT_EQ(elf.sha256, "cb2f08393b7c54eb793cf315f56fe51e974372d1e1c9dba2a04af2d9991bcb43");
  EXPECT_FALSE(elf.partial);

  ASSERT_EQ(elf.sections.size(), 6U);
  EXPECT_EQ(elf.sections[1].name, ".text");
  EXPECT_TRUE(elf.sections[1].executable);
  EXPECT_TRUE(elf.sections[1].readable);
  EXPECT_FALSE(elf.sections[1].writable);
  EXPECT_EQ(elf.sections[1].address, 0x400100U);
  EXPECT_EQ(elf.sections[1].file_offset, 0x100U);

  ASSERT_EQ(elf.segments.size(), 1U);
  EXPECT_EQ(elf.segments[0].virtual_address, 0x400000U);
  EXPECT_EQ(elf.segments[0].file_size, 0x300U);

  bool found_start = false;
  bool found_puts = false;
  bool found_message = false;
  for (const auto& symbol : elf.symbols) {
    if (symbol.name == "_start") {
      found_start = true;
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Function);
      EXPECT_TRUE(symbol.exported);
      EXPECT_EQ(symbol.address, 0x400100U);
    }
    if (symbol.name == "puts") {
      found_puts = true;
      EXPECT_TRUE(symbol.imported);
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Import);
    }
    if (symbol.name == "message") {
      found_message = true;
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Object);
      EXPECT_EQ(symbol.size, 12U);
    }
  }
  EXPECT_TRUE(found_start);
  EXPECT_TRUE(found_puts);
  EXPECT_TRUE(found_message);
}

TEST(Binary, MapsOffsetsAndAddresses) {
  auto image = donkey::load_binary_file(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(image.has_value());

  auto offset = image.value().va_to_file_offset(0x400100);
  ASSERT_TRUE(offset.has_value());
  EXPECT_EQ(offset.value(), 0x100U);

  auto address = image.value().file_offset_to_va(0x100);
  ASSERT_TRUE(address.has_value());
  EXPECT_EQ(address.value(), 0x400100U);

  auto unmapped = image.value().va_to_file_offset(0x900000);
  EXPECT_FALSE(unmapped.has_value());
  EXPECT_EQ(unmapped.diagnostic().code, "image.unmapped_va");

  auto bad_offset = image.value().file_offset_to_va(0x300);
  EXPECT_FALSE(bad_offset.has_value());
  EXPECT_EQ(bad_offset.diagnostic().code, "image.unmapped_offset");
}

TEST(Binary, LoadsPeImportsAndExports) {
  auto image = donkey::load_binary_file(fixture_path("tiny-pe-x86_64.exe"));
  ASSERT_TRUE(image.has_value()) << image.diagnostic().message;
  const auto& pe = image.value();
  EXPECT_EQ(pe.format, donkey::BinaryFormat::Pe);
  EXPECT_EQ(pe.architecture, donkey::Architecture::X86_64);
  EXPECT_EQ(pe.bits, 64U);
  EXPECT_EQ(pe.image_base, 0x140000000U);
  EXPECT_EQ(pe.entry_point, 0x140001000U);

  ASSERT_EQ(pe.sections.size(), 2U);
  EXPECT_EQ(pe.sections[0].name, ".text");
  EXPECT_TRUE(pe.sections[0].executable);

  bool found_import = false;
  bool found_export = false;
  for (const auto& symbol : pe.symbols) {
    if (symbol.name == "ExitProcess") {
      found_import = true;
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Import);
      EXPECT_EQ(symbol.module, "KERNEL32.dll");
      EXPECT_EQ(symbol.address, 0x140002160U);
    }
    if (symbol.name == "tiny_export") {
      found_export = true;
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Export);
      EXPECT_EQ(symbol.module, "tiny.dll");
      EXPECT_EQ(symbol.address, 0x140001000U);
    }
  }
  EXPECT_TRUE(found_import);
  EXPECT_TRUE(found_export);

  auto offset = pe.va_to_file_offset(0x140001000);
  ASSERT_TRUE(offset.has_value());
  EXPECT_EQ(offset.value(), 0x200U);
}

TEST(Binary, LoadsMachOMetadata) {
  auto image = donkey::load_binary_file(fixture_path("tiny-macho-arm64"));
  ASSERT_TRUE(image.has_value()) << image.diagnostic().message;
  const auto& macho = image.value();
  EXPECT_EQ(macho.format, donkey::BinaryFormat::MachO);
  EXPECT_EQ(macho.architecture, donkey::Architecture::AArch64);
  EXPECT_EQ(macho.bits, 64U);
  EXPECT_EQ(macho.image_base, 0x100000000U);
  EXPECT_EQ(macho.entry_point, 0x100000F00U);

  ASSERT_EQ(macho.sections.size(), 1U);
  EXPECT_EQ(macho.sections[0].name, "__TEXT,__text");
  EXPECT_TRUE(macho.sections[0].executable);

  bool found_main = false;
  bool found_puts = false;
  for (const auto& symbol : macho.symbols) {
    if (symbol.name == "_main") {
      found_main = true;
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Function);
      EXPECT_TRUE(symbol.exported);
      EXPECT_EQ(symbol.address, 0x100000F00U);
    }
    if (symbol.name == "_puts") {
      found_puts = true;
      EXPECT_TRUE(symbol.imported);
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Import);
    }
  }
  EXPECT_TRUE(found_main);
  EXPECT_TRUE(found_puts);

  auto offset = macho.va_to_file_offset(0x100000F00);
  ASSERT_TRUE(offset.has_value());
  EXPECT_EQ(offset.value(), 0xF00U);
}

TEST(Binary, RawFallbackAndDeterministicHash) {
  const std::string bytes = "not an executable";
  const auto data =
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  auto first = donkey::parse_binary(data, "raw.bin");
  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(first.value().format, donkey::BinaryFormat::Raw);
  ASSERT_EQ(first.value().sections.size(), 1U);
  EXPECT_EQ(first.value().sections[0].name, "raw");
  EXPECT_EQ(first.value().file_size, bytes.size());

  auto second = donkey::parse_binary(data, "raw.bin");
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(first.value().sha256, second.value().sha256);
  EXPECT_EQ(first.value().sections.size(), second.value().sections.size());
}

TEST(Binary, PublicFixturesMatchRecordedHash) {
  for (const std::string name : {"tiny-elf-x86_64", "tiny-pe-x86_64.exe", "tiny-macho-arm64"}) {
    const auto bytes = read_fixture(name);
    auto image = donkey::parse_binary(bytes, name);
    ASSERT_TRUE(image.has_value()) << name << ": " << image.diagnostic().message;
    EXPECT_EQ(image.value().sha256, digest_hex(bytes)) << name;
    EXPECT_EQ(image.value().file_size, bytes.size()) << name;
  }
}

TEST(Binary, TruncatedFixturesNeverCrashOrHang) {
  for (const std::string name : {"tiny-elf-x86_64", "tiny-pe-x86_64.exe", "tiny-macho-arm64"}) {
    const auto bytes = read_fixture(name);
    ASSERT_FALSE(bytes.empty());
    for (std::size_t length = 0; length <= bytes.size(); ++length) {
      const auto slice = std::span<const std::byte>(bytes.data(), length);
      auto image = donkey::parse_binary(slice, name);
      if (!image) {
        EXPECT_FALSE(image.diagnostic().code.empty()) << name << " length=" << length;
      } else {
        EXPECT_GT(image.value().file_size, 0U);
        EXPECT_EQ(image.value().file_size, length);
      }
    }
  }
}

TEST(Binary, CorruptedHeadersAreRejectedDeterministically) {
  std::uint64_t state = 0x123456789ABCDEF0ULL;
  const auto next = [&state]() {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
  };

  for (const std::string name : {"tiny-elf-x86_64", "tiny-pe-x86_64.exe", "tiny-macho-arm64"}) {
    auto bytes = read_fixture(name);
    for (int iteration = 0; iteration < 256; ++iteration) {
      auto mutated = bytes;
      const std::size_t offset = static_cast<std::size_t>(next() % 256U);
      mutated[offset] = static_cast<std::byte>(next() & 0xFFU);
      auto first = donkey::parse_binary(mutated, name);
      auto second = donkey::parse_binary(mutated, name);
      ASSERT_EQ(first.has_value(), second.has_value()) << name << " offset=" << offset;
      if (!first) {
        EXPECT_EQ(first.diagnostic().code, second.diagnostic().code);
        EXPECT_FALSE(first.diagnostic().code.empty());
      }
    }
  }
}

TEST(Binary, RejectsEmptyAndMissingFiles) {
  auto empty = donkey::load_binary_file("/dev/null");
  EXPECT_FALSE(empty.has_value());
  EXPECT_EQ(empty.diagnostic().code, "image.empty_file");

  auto missing = donkey::load_binary_file("/definitely/not/a/real/file");
  EXPECT_FALSE(missing.has_value());
  EXPECT_EQ(missing.diagnostic().code, "io.open_failed");

  std::vector<std::byte> empty_bytes;
  auto parsed = donkey::parse_binary(empty_bytes, "empty");
  EXPECT_FALSE(parsed.has_value());
  EXPECT_EQ(parsed.diagnostic().code, "image.empty_file");
}

TEST(Binary, EnforcesFileSizeLimit) {
  donkey::LoadOptions options;
  options.max_file_bytes = 64;
  auto image = donkey::load_binary_file(fixture_path("tiny-elf-x86_64"), options);
  EXPECT_FALSE(image.has_value());
  EXPECT_EQ(image.diagnostic().code, "io.file_too_large");
}

}  // namespace
