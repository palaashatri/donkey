#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/project/project.h"
#include "donkey/project/string_literals.h"

namespace {

using donkey::Annotation;
using donkey::AnnotationKind;
using donkey::Architecture;
using donkey::BinaryImage;
using donkey::Section;

constexpr std::uint64_t kBase = 0x2000;

/// A raw image whose one section maps `size` file bytes at kBase.
BinaryImage image_of(std::size_t size) {
  BinaryImage image;
  image.path = "<literal test>";
  image.architecture = Architecture::X86_64;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = size;
  Section section;
  section.id = donkey::SectionId{1};
  section.name = ".rodata";
  section.type = "synthetic";
  section.file_offset = 0;
  section.file_size = size;
  section.address = kBase;
  section.virtual_size = size;
  section.readable = true;
  section.has_file_data = true;
  image.sections.push_back(section);
  return image;
}

Annotation data_range(std::uint64_t address, const std::string& text) {
  Annotation annotation;
  annotation.kind = AnnotationKind::DataRange;
  annotation.address = address;
  annotation.text = text;
  return annotation;
}

std::vector<std::byte> bytes_of(const std::string& text) {
  std::vector<std::byte> out;
  for (const char c : text) {
    out.push_back(static_cast<std::byte>(c));
  }
  return out;
}

}  // namespace

TEST(StringLiterals, AUserStringBecomesItsCLiteralEscapesIncluded) {
  // "hello\0" at 0x2000; a quote, a backslash, a newline and a control byte then a terminator at
  // 0x2006; "xyz" with no terminator at 0x200e (refused); a UTF-16 string at 0x2011 (refused).
  const std::string file_text = std::string("hello\0", 6) + std::string("a\"b\\c\n\x01\0", 8) +
                                "xyz" + std::string("h\0i\0\0\0", 6);
  const auto file = bytes_of(file_text);
  const BinaryImage image = image_of(file.size());
  const std::vector<Annotation> annotations{
      data_range(kBase, "string:6"),
      data_range(kBase + 6, "string:8"),
      data_range(kBase + 14, "string:3"),
      data_range(kBase + 17, "string16:6"),
  };
  const auto literals = donkey::string_literals(annotations, image, file);
  ASSERT_EQ(literals.size(), 2U);
  EXPECT_EQ(literals.at(kBase), "\"hello\"");
  EXPECT_EQ(literals.at(kBase + 6), "\"a\\\"b\\\\c\\n\\001\"");
}

TEST(StringLiterals, OnlyDataRangesOfAFileThatHoldsThemCount) {
  const auto file = bytes_of(std::string("ab\0", 3));
  const BinaryImage image = image_of(file.size());
  Annotation rename;
  rename.kind = AnnotationKind::Rename;
  rename.address = kBase;
  rename.text = "name";
  const std::vector<Annotation> annotations{
      rename, data_range(kBase, "string:100"),  // runs past the file
      data_range(kBase + 0x100, "string:3"),    // not mapped by the image
      data_range(kBase, "3:1"),                 // an array, not a string
  };
  EXPECT_TRUE(donkey::string_literals(annotations, image, file).empty());
}
