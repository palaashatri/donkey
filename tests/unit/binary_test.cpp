#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
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
#include "donkey/binary/isolation.h"
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

TEST(Binary, LoadsElf32Metadata) {
  auto image = donkey::load_binary_file(fixture_path("tiny-elf-i386"));
  ASSERT_TRUE(image.has_value()) << image.diagnostic().message;
  const auto& elf = image.value();
  EXPECT_EQ(elf.format, donkey::BinaryFormat::Elf);
  EXPECT_EQ(elf.architecture, donkey::Architecture::X86);
  EXPECT_EQ(elf.bits, 32U);
  EXPECT_EQ(elf.endian, Endian::Little);
  EXPECT_EQ(elf.entry_point, 0x08048100U);
  EXPECT_EQ(elf.image_base, 0x08048000U);
  EXPECT_EQ(elf.sha256, "12b48c5ce6669b9d2d98c438199bac760fd4d57d44c4d35f01ea04ad8c9e3659");
  EXPECT_FALSE(elf.partial);

  ASSERT_EQ(elf.sections.size(), 6U);
  EXPECT_EQ(elf.sections[1].name, ".text");
  EXPECT_TRUE(elf.sections[1].executable);
  EXPECT_EQ(elf.sections[1].address, 0x08048100U);
  EXPECT_EQ(elf.sections[1].file_offset, 0x100U);

  ASSERT_EQ(elf.segments.size(), 1U);
  EXPECT_EQ(elf.segments[0].virtual_address, 0x08048000U);

  bool found_start = false;
  bool found_puts = false;
  for (const auto& symbol : elf.symbols) {
    if (symbol.name == "_start") {
      found_start = true;
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Function);
      EXPECT_EQ(symbol.address, 0x08048100U);
    }
    if (symbol.name == "puts") {
      found_puts = true;
      EXPECT_TRUE(symbol.imported);
    }
  }
  EXPECT_TRUE(found_start);
  EXPECT_TRUE(found_puts);
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

TEST(Binary, SectionsWithoutAddressNeverClaimVirtualSpace) {
  auto image = donkey::load_binary_file(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(image.has_value());

  // .symtab/.strtab/.shstrtab have sh_addr == 0. They used to be mapped as if
  // they lived at VA 0, so VA 0 resolved to their file contents.
  const auto zero = image.value().va_to_file_offset(0x0);
  EXPECT_FALSE(zero.has_value());
  EXPECT_EQ(zero.diagnostic().code, "image.unmapped_va");

  for (std::uint64_t va = 0x0; va < 0x100; va += 0x8) {
    EXPECT_FALSE(image.value().va_to_file_offset(va).has_value()) << va;
    EXPECT_EQ(image.value().section_for_va(va), nullptr) << va;
  }

  const auto* text = image.value().section_for_va(0x400100);
  ASSERT_NE(text, nullptr);
  EXPECT_EQ(text->name, ".text");

  // File offset 0 is still reachable through the LOAD segment.
  const auto mapped = image.value().file_offset_to_va(0x0);
  ASSERT_TRUE(mapped.has_value());
  EXPECT_EQ(mapped.value(), 0x400000U);
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

TEST(Binary, LoadsPe32ImportsAndExports) {
  auto image = donkey::load_binary_file(fixture_path("tiny-pe-i386.exe"));
  ASSERT_TRUE(image.has_value()) << image.diagnostic().message;
  const auto& pe = image.value();
  EXPECT_EQ(pe.format, donkey::BinaryFormat::Pe);
  EXPECT_EQ(pe.architecture, donkey::Architecture::X86);
  EXPECT_EQ(pe.bits, 32U);
  EXPECT_EQ(pe.image_base, 0x10000000U);
  EXPECT_EQ(pe.entry_point, 0x10001000U);
  EXPECT_EQ(pe.format_detail, "PE32 (2 sections)");

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
    }
    if (symbol.name == "tiny_export") {
      found_export = true;
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Export);
    }
  }
  EXPECT_TRUE(found_import);
  EXPECT_TRUE(found_export);

  auto offset = pe.va_to_file_offset(0x10001000);
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

TEST(Binary, LoadsMachO32Metadata) {
  auto image = donkey::load_binary_file(fixture_path("tiny-macho-i386"));
  ASSERT_TRUE(image.has_value()) << image.diagnostic().message;
  const auto& macho = image.value();
  EXPECT_EQ(macho.format, donkey::BinaryFormat::MachO);
  EXPECT_EQ(macho.architecture, donkey::Architecture::X86);
  EXPECT_EQ(macho.bits, 32U);
  EXPECT_EQ(macho.image_base, 0x00001000U);
  EXPECT_EQ(macho.entry_point, 0x00001F00U);
  EXPECT_EQ(macho.format_detail, "Mach-O 32 (MH_EXECUTE)");

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
      EXPECT_EQ(symbol.address, 0x00001F00U);
    }
    if (symbol.name == "_puts") {
      found_puts = true;
      EXPECT_TRUE(symbol.imported);
      EXPECT_EQ(symbol.kind, donkey::SymbolKind::Import);
    }
  }
  EXPECT_TRUE(found_main);
  EXPECT_TRUE(found_puts);

  auto offset = macho.va_to_file_offset(0x00001F00);
  ASSERT_TRUE(offset.has_value());
  EXPECT_EQ(offset.value(), 0xF00U);
}

TEST(Binary, LoadsFatMachOSlicesAndRejectsMissingSlice) {
  auto default_slice = donkey::load_binary_file(fixture_path("tiny-macho-fat"));
  ASSERT_TRUE(default_slice.has_value()) << default_slice.diagnostic().message;
  EXPECT_EQ(default_slice.value().architecture, donkey::Architecture::AArch64);
  EXPECT_EQ(default_slice.value().bits, 64U);
  ASSERT_EQ(default_slice.value().fat_architectures.size(), 2U);
  EXPECT_EQ(default_slice.value().fat_architectures[0], donkey::Architecture::X86);
  EXPECT_EQ(default_slice.value().fat_architectures[1], donkey::Architecture::AArch64);

  donkey::LoadOptions x86_options;
  x86_options.preferred_architecture = donkey::Architecture::X86;
  auto x86_slice = donkey::load_binary_file(fixture_path("tiny-macho-fat"), x86_options);
  ASSERT_TRUE(x86_slice.has_value()) << x86_slice.diagnostic().message;
  EXPECT_EQ(x86_slice.value().architecture, donkey::Architecture::X86);
  EXPECT_EQ(x86_slice.value().bits, 32U);
  EXPECT_EQ(x86_slice.value().entry_point, 0x00001F00U);
  auto x86_offset = x86_slice.value().va_to_file_offset(0x00001F00);
  ASSERT_TRUE(x86_offset.has_value());
  EXPECT_EQ(x86_offset.value(), 0x1F00U);

  donkey::LoadOptions missing_options;
  missing_options.preferred_architecture = donkey::Architecture::RiscV64;
  auto missing_slice = donkey::load_binary_file(fixture_path("tiny-macho-fat"), missing_options);
  ASSERT_FALSE(missing_slice.has_value());
  EXPECT_EQ(missing_slice.diagnostic().code, "macho.slice_not_found");
}

TEST(Binary, RawImportWithExplicitMetadata) {
  const std::vector<std::byte> raw_code{
      std::byte{0x55}, std::byte{0x48}, std::byte{0x89}, std::byte{0xE5}, std::byte{0xC3},
  };
  donkey::LoadOptions options;
  options.force_raw = true;
  options.preferred_architecture = donkey::Architecture::X86_64;
  options.raw_base_address = 0x800000;
  options.raw_entry_point = 0x800001;
  options.has_raw_entry_point = true;

  auto parsed = donkey::parse_binary(raw_code, "shellcode.bin", options);
  ASSERT_TRUE(parsed.has_value()) << parsed.diagnostic().message;
  const auto& image = parsed.value();
  EXPECT_EQ(image.format, donkey::BinaryFormat::Raw);
  EXPECT_EQ(image.architecture, donkey::Architecture::X86_64);
  EXPECT_EQ(image.bits, 64U);
  EXPECT_EQ(image.image_base, 0x800000U);
  EXPECT_EQ(image.entry_point, 0x800001U);
  ASSERT_EQ(image.sections.size(), 1U);
  EXPECT_TRUE(image.sections[0].executable);
  auto offset = image.va_to_file_offset(0x800001);
  ASSERT_TRUE(offset.has_value());
  EXPECT_EQ(offset.value(), 1U);
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
  for (const std::string name :
       {"tiny-elf-x86_64", "tiny-elf-i386", "tiny-pe-x86_64.exe", "tiny-pe-i386.exe",
        "tiny-macho-arm64", "tiny-macho-i386", "tiny-macho-fat"}) {
    const auto bytes = read_fixture(name);
    auto image = donkey::parse_binary(bytes, name);
    ASSERT_TRUE(image.has_value()) << name << ": " << image.diagnostic().message;
    EXPECT_EQ(image.value().sha256, digest_hex(bytes)) << name;
    EXPECT_EQ(image.value().file_size, bytes.size()) << name;
  }
}

TEST(Binary, TruncatedFixturesNeverCrashOrHang) {
  for (const std::string name :
       {"tiny-elf-x86_64", "tiny-elf-i386", "tiny-pe-x86_64.exe", "tiny-pe-i386.exe",
        "tiny-macho-arm64", "tiny-macho-i386", "tiny-macho-fat"}) {
    const auto bytes = read_fixture(name);
    ASSERT_FALSE(bytes.empty());
    // Step by 1 byte across headers and by 16 bytes in trailing padding on larger fat binaries.
    for (std::size_t length = 0; length <= bytes.size();
         length += (length < 512 || length + 16 > bytes.size()) ? 1 : 16) {
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

  for (const std::string name :
       {"tiny-elf-x86_64", "tiny-elf-i386", "tiny-pe-x86_64.exe", "tiny-pe-i386.exe",
        "tiny-macho-arm64", "tiny-macho-i386", "tiny-macho-fat"}) {
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
  struct ScopedTempFile {
    std::filesystem::path path;
    ~ScopedTempFile() {
      std::error_code ec;
      std::filesystem::remove(path, ec);
    }
  };
  static std::atomic<std::uint64_t> test_counter{0};
  const std::string empty_path =
      (std::filesystem::temp_directory_path() /
       ("test_empty_bin_" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
        std::to_string(test_counter.fetch_add(1))))
          .string();
  ScopedTempFile cleaner{empty_path};
  {
    std::ofstream ofs(empty_path, std::ios::binary | std::ios::trunc);
  }
  auto empty = donkey::load_binary_file(empty_path);
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

TEST(Binary, IsolatedLoaderParsesValidBinariesIdentically) {
  if (!donkey::process_isolation_available()) {
    GTEST_SKIP() << "OS process isolation not supported on this platform";
  }

  const std::string path = fixture_path("tiny-elf-x86_64");
  auto direct = donkey::load_binary(path);
  ASSERT_TRUE(direct.has_value()) << direct.diagnostic().message;

  auto isolated = donkey::load_binary_isolated(path);
  ASSERT_TRUE(isolated.has_value()) << isolated.diagnostic().message;

  const auto& img_direct = direct.value().image;
  const auto& img_iso = isolated.value().image;
  EXPECT_EQ(img_iso.format, img_direct.format);
  EXPECT_EQ(img_iso.architecture, img_direct.architecture);
  EXPECT_EQ(img_iso.entry_point, img_direct.entry_point);
  EXPECT_EQ(img_iso.sha256, img_direct.sha256);
  EXPECT_EQ(img_iso.sections.size(), img_direct.sections.size());
  EXPECT_EQ(img_iso.symbols.size(), img_direct.symbols.size());
  EXPECT_EQ(isolated.value().data.size(), direct.value().data.size());
}

TEST(Binary, IsolatedLoaderCapturesWorkerCrashCleanly) {
  if (!donkey::process_isolation_available()) {
    GTEST_SKIP() << "OS process isolation not supported on this platform";
  }

  const std::string path = fixture_path("tiny-elf-x86_64");
  donkey::IsolationConfig config;
  config.force_worker_crash = true;

  // The child process will crash with SIGSEGV, but the parent supervisor must survive!
  auto result = donkey::load_binary_isolated(path, {}, config);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "binary.worker_crashed");
  EXPECT_NE(result.diagnostic().message.find("signal"), std::string::npos);
}

TEST(Binary, IsolatedLoaderEnforcesTimeoutOnWorkerHang) {
  if (!donkey::process_isolation_available()) {
    GTEST_SKIP() << "OS process isolation not supported on this platform";
  }

  const std::string path = fixture_path("tiny-elf-x86_64");
  donkey::IsolationConfig config;
  config.force_worker_hang = true;
  config.timeout_seconds = 1;

  // Supervisor must kill the hanging child after 1s timeout and report ResourceLimit
  auto result = donkey::load_binary_isolated(path, {}, config);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "binary.worker_timeout");
  EXPECT_EQ(result.diagnostic().status, donkey::Status::ResourceLimit);
}

}  // namespace
