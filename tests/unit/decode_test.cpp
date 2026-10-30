#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/decode/decode.h"

namespace {

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

std::vector<std::byte> read_fixture(const std::string& name) {
  std::ifstream file(fixture_path(name), std::ios::binary);
  EXPECT_TRUE(file.good()) << name;
  const std::vector<char> chars((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes(chars.size());
  std::memcpy(bytes.data(), chars.data(), chars.size());
  return bytes;
}

std::span<const std::byte> section_bytes(const donkey::BinaryImage& image,
                                         const std::vector<std::byte>& file,
                                         const std::string& name) {
  for (const auto& section : image.sections) {
    if (section.name == name && section.has_file_data) {
      return std::span<const std::byte>(file.data() + section.file_offset,
                                        static_cast<std::size_t>(section.file_size));
    }
  }
  return {};
}

TEST(Decode, RejectsUnsupportedArchitectures) {
  auto raw = donkey::Decoder::create(donkey::Architecture::Unknown, donkey::Endian::Little);
  ASSERT_FALSE(raw.has_value());
  EXPECT_EQ(raw.diagnostic().code, "decode.unsupported_architecture");

  auto riscv = donkey::Decoder::create(donkey::Architecture::RiscV64, donkey::Endian::Little);
  ASSERT_FALSE(riscv.has_value());
}

TEST(Decode, X86_64KnownPrologueAndCallTarget) {
  const auto file = read_fixture("tiny-elf-x86_64");
  auto image = donkey::parse_binary(file, "tiny-elf-x86_64");
  ASSERT_TRUE(image.has_value());

  auto decoder = donkey::Decoder::create(donkey::Architecture::X86_64, donkey::Endian::Little);
  ASSERT_TRUE(decoder.has_value()) << decoder.diagnostic().message;

  const auto text = section_bytes(image.value(), file, ".text");
  ASSERT_EQ(text.size(), 16U);
  auto stream = decoder.value().decode(text, 0x400100, 10);
  ASSERT_TRUE(stream.has_value());
  const auto& instructions = stream.value().instructions;
  ASSERT_EQ(instructions.size(), 10U);
  EXPECT_FALSE(stream.value().truncated);

  EXPECT_EQ(instructions[0].address, 0x400100U);
  EXPECT_EQ(instructions[0].length, 1U);
  EXPECT_EQ(instructions[0].mnemonic, "push");
  EXPECT_EQ(donkey::instruction_bytes_hex(instructions[0]), "55");

  EXPECT_EQ(instructions[1].address, 0x400101U);
  EXPECT_EQ(instructions[1].length, 3U);
  EXPECT_EQ(instructions[1].mnemonic, "mov");
  EXPECT_EQ(instructions[1].operands, "rbp, rsp");

  EXPECT_EQ(instructions[2].address, 0x400104U);
  EXPECT_EQ(instructions[2].length, 5U);
  EXPECT_EQ(instructions[2].mnemonic, "call");
  EXPECT_EQ(instructions[2].classification, donkey::InstructionClass::Call);
  ASSERT_TRUE(instructions[2].direct_target.has_value());
  EXPECT_EQ(instructions[2].direct_target.value(), 0x400109U);

  EXPECT_EQ(instructions[3].classification, donkey::InstructionClass::Other);
  EXPECT_EQ(instructions[7].mnemonic, "nop");
}

TEST(Decode, AArch64KnownPrologueAndReturn) {
  const auto file = read_fixture("tiny-macho-arm64");
  auto image = donkey::parse_binary(file, "tiny-macho-arm64");
  ASSERT_TRUE(image.has_value());

  auto decoder = donkey::Decoder::create(donkey::Architecture::AArch64, donkey::Endian::Little);
  ASSERT_TRUE(decoder.has_value()) << decoder.diagnostic().message;

  const auto text = section_bytes(image.value(), file, "__TEXT,__text");
  ASSERT_EQ(text.size(), 20U);
  auto stream = decoder.value().decode(text, 0x100000F00, 8);
  ASSERT_TRUE(stream.has_value());
  const auto& instructions = stream.value().instructions;
  ASSERT_EQ(instructions.size(), 5U);

  EXPECT_EQ(instructions[0].mnemonic, "stp");
  EXPECT_EQ(instructions[0].length, 4U);
  EXPECT_EQ(instructions[1].mnemonic, "mov");
  EXPECT_EQ(instructions[2].mnemonic, "mov");
  EXPECT_EQ(instructions[3].mnemonic, "ldp");
  EXPECT_EQ(instructions[4].mnemonic, "ret");
  EXPECT_EQ(instructions[4].classification, donkey::InstructionClass::Return);
}

TEST(Decode, InvalidBytesReturnDiagnosticAndStopTheStream) {
  auto decoder = donkey::Decoder::create(donkey::Architecture::X86_64, donkey::Endian::Little);
  ASSERT_TRUE(decoder.has_value());

  const std::vector<std::byte> truncated = {std::byte{0xFF}};
  auto single = decoder.value().decode_one(truncated, 0x1000);
  ASSERT_FALSE(single.has_value());
  EXPECT_EQ(single.diagnostic().code, "decode.invalid_instruction");

  const std::vector<std::byte> data = {std::byte{0x90}, std::byte{0xFF}};
  auto stream = decoder.value().decode(data, 0x1000, 10);
  ASSERT_TRUE(stream.has_value());
  ASSERT_EQ(stream.value().instructions.size(), 1U);
  EXPECT_TRUE(stream.value().truncated);
  EXPECT_EQ(stream.value().stop_reason, "decode.invalid_instruction");
}

TEST(Decode, HonorsInstructionLimit) {
  auto decoder = donkey::Decoder::create(donkey::Architecture::X86_64, donkey::Endian::Little);
  ASSERT_TRUE(decoder.has_value());
  std::vector<std::byte> nops(64, std::byte{0x90});
  auto stream = decoder.value().decode(nops, 0x1000, 4);
  ASSERT_TRUE(stream.has_value());
  EXPECT_EQ(stream.value().instructions.size(), 4U);
  EXPECT_TRUE(stream.value().truncated);
  EXPECT_EQ(stream.value().stop_reason, "decode.instruction_limit");
}

TEST(Analysis, ExtractsStringsWithEncodingsAndAddresses) {
  const std::string ascii("hello\0", 6);
  std::string utf16;
  for (const char ch : std::string("wide")) {
    utf16.push_back(ch);
    utf16.push_back('\0');
  }
  utf16 += std::string("\0\0", 2);

  std::string payload;
  payload += ascii;
  payload += utf16;
  payload += "x";  // too short
  const auto bytes = std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()),
                                                payload.size());
  auto image = donkey::parse_binary(bytes, "strings.bin");
  ASSERT_TRUE(image.has_value());

  auto strings = donkey::extract_strings(image.value(), bytes);
  ASSERT_TRUE(strings.has_value());
  ASSERT_EQ(strings.value().size(), 2U);
  EXPECT_EQ(strings.value()[0].text, "hello");
  EXPECT_EQ(strings.value()[0].encoding, "ascii");
  EXPECT_EQ(strings.value()[1].text, "wide");
  EXPECT_EQ(strings.value()[1].encoding, "utf-16le");
}

TEST(Analysis, ElfFindsCallTargetsFunctionsAndStrings) {
  const auto file = read_fixture("tiny-elf-x86_64");
  auto image = donkey::parse_binary(file, "tiny-elf-x86_64");
  ASSERT_TRUE(image.has_value());

  auto result = donkey::analyze(image.value(), file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const auto& analysis = result.value();

  EXPECT_EQ(analysis.instructions.size(), 10U);
  ASSERT_EQ(analysis.xrefs.size(), 1U);
  EXPECT_EQ(analysis.xrefs[0].from, 0x400104U);
  EXPECT_EQ(analysis.xrefs[0].to, 0x400109U);
  EXPECT_EQ(analysis.xrefs[0].kind, donkey::XrefKind::Call);

  bool found_start = false;
  bool found_call_target = false;
  for (const auto& function : analysis.functions) {
    if (function.address == 0x400100U) {
      found_start = true;
      EXPECT_EQ(function.name, "_start");
      EXPECT_TRUE(function.from_symbol);
    }
    if (function.address == 0x400109U) {
      found_call_target = true;
      EXPECT_EQ(function.name, "sub_400109");
      EXPECT_FALSE(function.from_symbol);
    }
  }
  EXPECT_TRUE(found_start);
  EXPECT_TRUE(found_call_target);

  ASSERT_EQ(analysis.strings.size(), 1U);
  EXPECT_EQ(analysis.strings[0].text, "hello world");
  EXPECT_EQ(analysis.strings[0].address, 0x400180U);
  EXPECT_TRUE(analysis.strings[0].mapped);
}

TEST(Analysis, PeSeedsExportedFunction) {
  const auto file = read_fixture("tiny-pe-x86_64.exe");
  auto image = donkey::parse_binary(file, "tiny-pe-x86_64.exe");
  ASSERT_TRUE(image.has_value());

  auto result = donkey::analyze(image.value(), file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  ASSERT_EQ(result.value().functions.size(), 2U);
  EXPECT_EQ(result.value().functions[0].address, 0x140001000U);
  EXPECT_EQ(result.value().functions[0].name, "tiny_export");
  EXPECT_TRUE(result.value().functions[0].exported);
  EXPECT_FALSE(result.value().functions[0].from_symbol);
  EXPECT_EQ(result.value().functions[1].address, 0x140001009U);
  EXPECT_EQ(result.value().functions[1].name, "sub_140001009");

  ASSERT_EQ(result.value().xrefs.size(), 1U);
  EXPECT_EQ(result.value().xrefs[0].kind, donkey::XrefKind::Call);
  EXPECT_EQ(result.value().xrefs[0].from, 0x140001004U);
  EXPECT_EQ(result.value().xrefs[0].to, 0x140001009U);
}

TEST(Analysis, MachOArm64IsMarkedPartialForDataXrefs) {
  const auto file = read_fixture("tiny-macho-arm64");
  auto image = donkey::parse_binary(file, "tiny-macho-arm64");
  ASSERT_TRUE(image.has_value());

  auto result = donkey::analyze(image.value(), file);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result.value().partial);
  EXPECT_EQ(result.value().instructions.size(), 5U);
  bool found = false;
  for (const auto& function : result.value().functions) {
    if (function.address == 0x100000F00U) {
      found = true;
      EXPECT_EQ(function.name, "_main");
    }
  }
  EXPECT_TRUE(found);
  bool noted = false;
  for (const auto& diagnostic : result.value().diagnostics) {
    noted = noted || diagnostic.code == "analysis.arm64_data_xrefs_incomplete";
  }
  EXPECT_TRUE(noted);
}

}  // namespace
