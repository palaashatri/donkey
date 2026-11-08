#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/analysis/signatures.h"
#include "donkey/binary/image.h"
#include "donkey/binary/separate_debug.h"

namespace {

using donkey::Architecture;
using donkey::BinaryImage;
using donkey::Section;
using donkey::Signature;
using donkey::SignatureFunction;
using donkey::SignatureMatch;
using donkey::SignatureSet;
using donkey::SignatureWildcard;

constexpr std::uint64_t kBase = 0x1000;

/// A raw x86-64 image whose only section holds `bytes` at kBase.
BinaryImage image_of(std::size_t size) {
  BinaryImage image;
  image.path = "<signature test>";
  image.architecture = Architecture::X86_64;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = size;
  image.entry_point = kBase;
  Section section;
  section.id = donkey::SectionId{1};
  section.name = ".text";
  section.type = "synthetic";
  section.file_offset = 0;
  section.file_size = size;
  section.address = kBase;
  section.virtual_size = size;
  section.readable = true;
  section.executable = true;
  section.has_file_data = true;
  image.sections.push_back(section);
  return image;
}

/// A function body: a frame prologue, then a counting pattern, so every byte is distinct enough.
std::vector<std::byte> function_bytes(std::size_t size, std::uint8_t seed) {
  std::vector<std::byte> bytes(size);
  for (std::size_t i = 0; i < size; ++i) {
    bytes[i] = static_cast<std::byte>((i * 37U + seed * 11U + 0x55U) & 0xFFU);
  }
  return bytes;
}

SignatureSet set_for(std::vector<Signature> signatures) {
  SignatureSet set;
  set.library = "testlib";
  set.version = "1.0";
  set.license = "MIT";
  set.architecture = "x86_64";
  set.signatures = std::move(signatures);
  return set;
}

std::vector<SignatureMatch> identify(const SignatureSet& set, const std::vector<std::byte>& file,
                                     std::uint64_t address, std::uint64_t end,
                                     std::vector<std::uint64_t> user_named = {}) {
  const BinaryImage image = image_of(file.size());
  const std::vector<SignatureFunction> functions{{address, end}};
  auto result = donkey::identify_functions(set, image, file, functions, user_named);
  EXPECT_TRUE(result.has_value()) << result.diagnostic().message;
  return result.has_value() ? result.value() : std::vector<SignatureMatch>{};
}

}  // namespace

TEST(Signatures, Crc32IsTheZlibCheckValue) {
  const std::string check = "123456789";
  std::vector<std::byte> bytes;
  for (const char c : check) {
    bytes.push_back(static_cast<std::byte>(c));
  }
  EXPECT_EQ(donkey::gnu_crc32(bytes), 0xCBF43926U);
}

TEST(Signatures, AFunctionMatchesItsOwnSignatureWithItsProvenance) {
  const auto body = function_bytes(40, 1);
  auto signature = donkey::make_signature(body, "lib_func");
  ASSERT_TRUE(signature.has_value()) << signature.diagnostic().message;
  std::vector<std::byte> file(body.begin(), body.end());
  const auto matches = identify(set_for({signature.value()}), file, kBase, kBase + body.size());
  ASSERT_EQ(matches.size(), 1U);
  EXPECT_EQ(matches[0].address, kBase);
  EXPECT_EQ(matches[0].name, "lib_func");
  EXPECT_EQ(matches[0].provenance, "signature testlib 1.0");
  EXPECT_FALSE(matches[0].ambiguous);
  EXPECT_EQ(matches[0].candidates, 1U);
}

// The bytes at offsets 20 to 23 stand for an address the loader fills in. They may differ between
// builds, and the function still matches. A change anywhere else does not.
TEST(Signatures, WildcardsLeaveRelocatedBytesOutOfTheComparison) {
  const auto body = function_bytes(48, 2);
  // One wildcard in the prefix (bytes 20 to 23) and one in the tail after it (bytes 36 to 39).
  auto signature = donkey::make_signature(body, "relocated",
                                          {SignatureWildcard{20, 4}, SignatureWildcard{36, 4}});
  ASSERT_TRUE(signature.has_value()) << signature.diagnostic().message;
  const SignatureSet set = set_for({signature.value()});

  auto relocated = body;
  relocated[20] = std::byte{0x11};
  relocated[21] = std::byte{0x22};
  relocated[22] = std::byte{0x33};
  relocated[23] = std::byte{0x44};
  relocated[36] = std::byte{0x55};
  relocated[39] = std::byte{0x66};
  std::vector<std::byte> file(relocated.begin(), relocated.end());
  EXPECT_EQ(identify(set, file, kBase, kBase + body.size()).size(), 1U);

  auto changed = body;
  changed[30] = std::byte{0x99};  // outside the wildcards, in the tail
  file.assign(changed.begin(), changed.end());
  EXPECT_TRUE(identify(set, file, kBase, kBase + body.size()).empty());

  auto prefix_changed = body;
  prefix_changed[3] = std::byte{0x99};  // outside the wildcard, in the prefix
  file.assign(prefix_changed.begin(), prefix_changed.end());
  EXPECT_TRUE(identify(set, file, kBase, kBase + body.size()).empty());
}

TEST(Signatures, APatternThatNamesDifferentFunctionsNamesNothing) {
  const auto body = function_bytes(40, 3);
  auto first = donkey::make_signature(body, "first_name");
  auto second = donkey::make_signature(body, "second_name");
  ASSERT_TRUE(first.has_value() && second.has_value());
  std::vector<std::byte> file(body.begin(), body.end());
  const auto matches =
      identify(set_for({first.value(), second.value()}), file, kBase, kBase + body.size());
  ASSERT_EQ(matches.size(), 1U);
  EXPECT_TRUE(matches[0].ambiguous);
  EXPECT_TRUE(matches[0].name.empty());
  EXPECT_TRUE(matches[0].provenance.empty());
  EXPECT_EQ(matches[0].candidates, 2U);
}

TEST(Signatures, AUserNamedFunctionIsNeverRenamed) {
  const auto body = function_bytes(40, 4);
  auto signature = donkey::make_signature(body, "lib_func");
  ASSERT_TRUE(signature.has_value());
  const SignatureSet set = set_for({signature.value()});
  std::vector<std::byte> file(body.begin(), body.end());
  // The same function matches when nobody has named it...
  EXPECT_EQ(identify(set, file, kBase, kBase + body.size()).size(), 1U);
  // ...and is skipped entirely once the user has named it.
  EXPECT_TRUE(identify(set, file, kBase, kBase + body.size(), {kBase}).empty());
}

TEST(Signatures, ASetForAnotherArchitectureIsRefused) {
  SignatureSet set = set_for({});
  set.architecture = "AArch64";
  const std::vector<std::byte> file(64, std::byte{0});
  const BinaryImage image = image_of(file.size());
  const std::vector<SignatureFunction> functions{{kBase, kBase + 16}};
  auto result = donkey::identify_functions(set, image, file, functions, {});
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "sig.architecture");
}

TEST(Signatures, ASetRoundTripsThroughItsCanonicalText) {
  const auto body = function_bytes(40, 5);
  auto plain = donkey::make_signature(body, "plain");
  auto relocated = donkey::make_signature(body, "with \"quotes\" and \\ slashes",
                                          {SignatureWildcard{8, 4}, SignatureWildcard{30, 2}});
  ASSERT_TRUE(plain.has_value() && relocated.has_value());
  const SignatureSet original = set_for({plain.value(), relocated.value()});
  const std::string text = donkey::write_signature_set(original);
  auto parsed = donkey::parse_signature_set(text);
  ASSERT_TRUE(parsed.has_value()) << parsed.diagnostic().message;
  const SignatureSet& back = parsed.value();
  EXPECT_EQ(back.library, "testlib");
  EXPECT_EQ(back.version, "1.0");
  EXPECT_EQ(back.license, "MIT");
  EXPECT_EQ(back.architecture, "x86_64");
  ASSERT_EQ(back.signatures.size(), 2U);
  EXPECT_EQ(back.signatures[1].name, "with \"quotes\" and \\ slashes");
  EXPECT_EQ(back.signatures[1].wildcards.size(), 2U);
  EXPECT_EQ(back.signatures[1].crc32, relocated.value().crc32);
  EXPECT_EQ(back.signatures[0].prefix, plain.value().prefix);
  // Writing again gives the same text: the form is canonical.
  EXPECT_EQ(donkey::write_signature_set(back), text);
}

TEST(Signatures, TheParserRefusesMalformedSetsAndSaysWhy) {
  const std::string head =
      "{\"format\": \"donkey.signatures.v1\", \"library\": \"l\", \"version\": \"1\", "
      "\"license\": \"MIT\", \"architecture\": \"x86_64\", \"signatures\": [";
  const std::string good_sig =
      "{\"name\": \"f\", \"length\": 2, \"prefix\": \"abcd\", \"wildcards\": [], \"crc32\": 1}";
  const struct Case {
    std::string text;
    std::string code;
  } cases[] = {
      {"{", ""},  // not JSON
      {"[]", "sig.format"},
      {"{\"format\": \"donkey.signatures.v0\"}", "sig.format"},
      {"{\"format\": \"donkey.signatures.v1\", \"version\": \"1\", \"license\": \"MIT\", "
       "\"architecture\": \"x86_64\", \"signatures\": []}",
       "sig.field"},  // no library
      {head + "{\"name\": \"f\", \"length\": 2, \"prefix\": \"abc\", \"wildcards\": [], "
              "\"crc32\": 1}]}",
       "sig.value"},  // an odd-length prefix
      {head + "{\"name\": \"f\", \"length\": 3, \"prefix\": \"abcd\", \"wildcards\": [], "
              "\"crc32\": 1}]}",
       "sig.value"},  // a prefix of the wrong size
      {head + "{\"name\": \"f\", \"length\": 4, \"prefix\": \"abcdef01\", \"wildcards\": "
              "[[0, 2], [1, 2]], \"crc32\": 1}]}",
       "sig.value"},  // overlapping wildcards
      {head + "{\"name\": \"f\", \"length\": 4, \"prefix\": \"abcdef01\", \"wildcards\": "
              "[[3, 2]], \"crc32\": 1}]}",
       "sig.value"},  // a wildcard past the end
      {head + "{\"name\": \"f\", \"length\": 2, \"prefix\": \"abcd\", \"wildcards\": [], "
              "\"crc32\": 4294967296}]}",
       "sig.value"},  // a CRC wider than 32 bits
      {head + "{\"name\": \"f\", \"length\": 1.5, \"prefix\": \"ab\", \"wildcards\": [], "
              "\"crc32\": 1}]}",
       "sig.value"},  // a fractional length
      {head + "{\"name\": \"\", \"length\": 2, \"prefix\": \"abcd\", \"wildcards\": [], "
              "\"crc32\": 1}]}",
       "sig.value"},  // an empty name
      {head + "{\"name\": \"f\", \"length\": 2, \"prefix\": \"abcd\", \"wildcards\": [], "
              "\"crc32\": 1}]",
       ""},  // not closed
      {head + "{\"name\": \"f\", \"length\": 2, \"prefix\": \"abcd\", \"crc32\": 1}]}",
       "sig.field"},  // no wildcards member
  };
  for (const Case& c : cases) {
    auto parsed = donkey::parse_signature_set(c.text);
    EXPECT_FALSE(parsed.has_value()) << c.text;
    if (!parsed.has_value() && !c.code.empty()) {
      EXPECT_EQ(parsed.diagnostic().code, c.code) << c.text;
    }
  }
  // The well-formed one is accepted, so the cases above fail for their own reasons.
  EXPECT_TRUE(donkey::parse_signature_set(head + good_sig + "]}").has_value());
}

TEST(Signatures, MakingASignatureRefusesBadInput) {
  EXPECT_FALSE(donkey::make_signature({}, "empty").has_value());
  const auto body = function_bytes(8, 6);
  EXPECT_FALSE(donkey::make_signature(body, "").has_value());
  EXPECT_FALSE(donkey::make_signature(body, "past", {SignatureWildcard{6, 4}}).has_value());
  EXPECT_FALSE(
      donkey::make_signature(body, "overlap", {SignatureWildcard{0, 4}, SignatureWildcard{2, 2}})
          .has_value());
  EXPECT_FALSE(donkey::make_signature(body, "empty_span", {SignatureWildcard{2, 0}}).has_value());
}

// The start mode (G09-T3): a candidate start is matched with each signature's own length, so an
// analysis that stopped too early or ran past the function does not matter.
TEST(Signatures, StartModeMatchesASignatureWithItsOwnLengthAtTheStart) {
  const auto body = function_bytes(40, 1);
  auto signature = donkey::make_signature(body, "lib_func");
  ASSERT_TRUE(signature.has_value()) << signature.diagnostic().message;
  std::vector<std::byte> file(body.begin(), body.end());
  file.resize(64, std::byte{0xCC});  // the bytes after the function do not belong to it
  const BinaryImage image = image_of(file.size());
  const std::vector<std::uint64_t> starts{kBase, kBase + 1};
  auto result = donkey::identify_at_starts(set_for({signature.value()}), image, file, starts, {});
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  ASSERT_EQ(result.value().size(), 1U);  // kBase + 1 is not the start of a signature's bytes
  EXPECT_EQ(result.value()[0].address, kBase);
  EXPECT_EQ(result.value()[0].name, "lib_func");
  EXPECT_EQ(result.value()[0].length, 40U);
  EXPECT_FALSE(result.value()[0].ambiguous);
}

TEST(Signatures, StartModeNeverNamesAStartTheUserNamed) {
  const auto body = function_bytes(40, 1);
  auto signature = donkey::make_signature(body, "lib_func");
  ASSERT_TRUE(signature.has_value());
  std::vector<std::byte> file(body.begin(), body.end());
  const BinaryImage image = image_of(file.size());
  const std::vector<std::uint64_t> starts{kBase};
  const std::vector<std::uint64_t> named{kBase};
  auto result =
      donkey::identify_at_starts(set_for({signature.value()}), image, file, starts, named);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().empty());
}

// Two signatures match at the same start, one for the whole body and one for its first 20 bytes.
// The longer one is the function's extent, so its name is reported with its length.
TEST(Signatures, StartModeReportsTheLongestOfSeveralMatchingLengths) {
  const auto body = function_bytes(40, 1);
  auto whole = donkey::make_signature(body, "whole");
  auto head = donkey::make_signature(std::span<const std::byte>(body.data(), 20), "head");
  ASSERT_TRUE(whole.has_value());
  ASSERT_TRUE(head.has_value());
  std::vector<std::byte> file(body.begin(), body.end());
  const BinaryImage image = image_of(file.size());
  const std::vector<std::uint64_t> starts{kBase};
  auto result =
      donkey::identify_at_starts(set_for({head.value(), whole.value()}), image, file, starts, {});
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  ASSERT_EQ(result.value().size(), 1U);
  EXPECT_EQ(result.value()[0].name, "whole");
  EXPECT_EQ(result.value()[0].length, 40U);
}
