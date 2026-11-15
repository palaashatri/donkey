#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/binary/pdata.h"

namespace {

std::string fixture_path() {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/pdata-pe-x86_64.dll";
}

const donkey::PdataFunction* find_start(const donkey::PdataReadResult& read, std::uint64_t start) {
  for (const donkey::PdataFunction& function : read.functions) {
    if (function.start == start) {
      return &function;
    }
  }
  return nullptr;
}

}  // namespace

// G23-T2: the RUNTIME_FUNCTION entries of the x64 DLL. Its three functions are at the addresses
// objdump prints; hidden_fn is never called or exported, so only this directory names it.
TEST(Pdata, ReadsTheExceptionDirectoryOfAnX64Dll) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto read = donkey::read_pdata_of_image(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_EQ(read.value().entries, 40U);
  EXPECT_EQ(read.value().functions.size(), 40U);
  EXPECT_EQ(read.value().chained, 0U);
  EXPECT_EQ(read.value().malformed, 0U);
  EXPECT_FALSE(read.value().truncated);
  const auto* hidden = find_start(read.value(), 0x2c8251390ULL);
  ASSERT_NE(hidden, nullptr);
  EXPECT_EQ(hidden->size, 0x16U);  // EndAddress 0x2C82513A6 in llvm-readobj --unwind
  EXPECT_NE(find_start(read.value(), 0x2c82513b0ULL), nullptr);
  EXPECT_NE(find_start(read.value(), 0x2c82513d0ULL), nullptr);
}

TEST(Pdata, EntryLimitTruncatesTheDirectory) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto read = donkey::read_pdata_of_image(loaded.value().image, loaded.value().data, 5);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_TRUE(read.value().truncated);
  EXPECT_EQ(read.value().entries, 5U);
  EXPECT_EQ(read.value().functions.size(), 5U);
}

TEST(Pdata, NonPeImageYieldsNothing) {
  donkey::BinaryImage image;
  image.format = donkey::BinaryFormat::Elf;
  image.architecture = donkey::Architecture::X86_64;
  auto read = donkey::read_pdata_of_image(image, {});
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_TRUE(read.value().functions.empty());
}

// The analysis marks a start found only by the exception directory with the unwind provenance.
TEST(Pdata, AnalysisSeedsHiddenFunctionWithUnwindProvenance) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto analyzed = donkey::analyze(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  bool found = false;
  for (const donkey::Function& function : analyzed.value().functions) {
    if (function.address == 0x2c8251390ULL) {
      found = true;
      EXPECT_TRUE(function.from_unwind);
    }
  }
  EXPECT_TRUE(found);
}

namespace {

void put_u32(std::vector<std::byte>& file, std::size_t at, std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) {
    file[at + i] = static_cast<std::byte>((value >> (8 * i)) & 0xFFU);
  }
}

}  // namespace

TEST(Pdata, AnEntryOutsideItsSectionIsNotReadFromTheNextFileBytes) {
  // A two-entry directory at RVA 0x5008 (24 bytes). The section holding it maps RVAs 0x5000 to
  // 0x5013 to file offsets 0x400 to 0x413, so only the first entry is in it. The second entry's
  // RVA, 0x5014, is backed by no file data; the bytes at 0x414 that follow the first entry in the
  // file belong to nothing here, yet hold a plausible entry, which must not become a function.
  constexpr std::uint64_t kImageBase = 0x140000000ULL;
  std::vector<std::byte> file(0x600, std::byte{0});
  put_u32(file, 0x3c, 0x40);     // e_lfanew
  file[0x58] = std::byte{0x0b};  // PE32+ magic 0x20b
  file[0x59] = std::byte{0x02};
  put_u32(file, 0x58 + 108, 16);              // NumberOfRvaAndSizes
  put_u32(file, 0x58 + 112 + 3 * 8, 0x5008);  // exception directory RVA
  put_u32(file, 0x58 + 112 + 3 * 8 + 4, 24);  // and size: two entries
  put_u32(file, 0x408, 0x2000);               // entry 0: begin
  put_u32(file, 0x40c, 0x2010);               //          end
  put_u32(file, 0x410, 0x6000);               //          unwind info
  put_u32(file, 0x414, 0x1000);               // bytes after it: a plausible begin,
  put_u32(file, 0x418, 0x1010);               // end
  put_u32(file, 0x41c, 0x6000);               // and unwind info
  file[0x500] = std::byte{0x01};              // UNWIND_INFO version 1, no chain

  donkey::BinaryImage image;
  image.format = donkey::BinaryFormat::Pe;
  image.architecture = donkey::Architecture::X86_64;
  image.image_base = kImageBase;
  image.file_size = file.size();
  donkey::Section pdata;
  pdata.name = ".pdata";
  pdata.address = kImageBase + 0x5000;
  pdata.file_offset = 0x400;
  pdata.file_size = 0x14;
  image.sections.push_back(pdata);
  donkey::Section xdata;
  xdata.name = ".xdata";
  xdata.address = kImageBase + 0x6000;
  xdata.file_offset = 0x500;
  xdata.file_size = 0x10;
  image.sections.push_back(xdata);

  auto read = donkey::read_pdata_of_image(image, file, 1000);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  ASSERT_EQ(read.value().functions.size(), 1U);
  EXPECT_EQ(read.value().functions[0].start, kImageBase + 0x2000);
  EXPECT_EQ(read.value().malformed, 1U);
  EXPECT_EQ(find_start(read.value(), kImageBase + 0x1000), nullptr);

  // The analysis seeds from the directory, so an entry it could not read leaves it Partial and
  // says so: a function start may be missing.
  auto analyzed = donkey::analyze(image, file);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  EXPECT_TRUE(analyzed.value().partial);
  bool reported = false;
  for (const donkey::Diagnostic& diagnostic : analyzed.value().diagnostics) {
    reported = reported || diagnostic.code == "analysis.pdata_incomplete";
  }
  EXPECT_TRUE(reported);
}

TEST(Pdata, AnEntryWithAGapInItsMiddleIsNotRead) {
  // One 12-byte entry at RVA 0x5000. Section A maps RVAs 0x5000 to 0x5003 to file 0x400, section B
  // maps 0x5008 to 0x500b to file 0x408, and nothing maps 0x5004 to 0x5007. The entry's first and
  // last bytes map to 0x400 and 0x40b, 11 apart, as if it were contiguous; its EndAddress field is
  // not mapped at all, so the entry is not read (the bytes at file 0x404 belong to nothing here).
  constexpr std::uint64_t kImageBase = 0x140000000ULL;
  std::vector<std::byte> file(0x600, std::byte{0});
  put_u32(file, 0x3c, 0x40);
  file[0x58] = std::byte{0x0b};
  file[0x59] = std::byte{0x02};
  put_u32(file, 0x58 + 108, 16);
  put_u32(file, 0x58 + 112 + 3 * 8, 0x5000);
  put_u32(file, 0x58 + 112 + 3 * 8 + 4, 12);
  put_u32(file, 0x400, 0x2000);  // BeginAddress (mapped by section A)
  put_u32(file, 0x404, 0x2010);  // the bytes under the unmapped EndAddress RVAs
  put_u32(file, 0x408, 0x6000);  // UnwindInfo (mapped by section B)
  file[0x500] = std::byte{0x01};

  donkey::BinaryImage image;
  image.format = donkey::BinaryFormat::Pe;
  image.architecture = donkey::Architecture::X86_64;
  image.image_base = kImageBase;
  image.file_size = file.size();
  for (const auto& [name, rva, offset, size] :
       {std::tuple<const char*, std::uint64_t, std::uint64_t, std::uint64_t>{".a", 0x5000, 0x400,
                                                                             4},
        {".b", 0x5008, 0x408, 4},
        {".xdata", 0x6000, 0x500, 0x10}}) {
    donkey::Section section;
    section.name = name;
    section.address = kImageBase + rva;
    section.file_offset = offset;
    section.file_size = size;
    image.sections.push_back(section);
  }
  auto read = donkey::read_pdata_of_image(image, file, 1000);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_TRUE(read.value().functions.empty());
  EXPECT_EQ(read.value().malformed, 1U);
}
