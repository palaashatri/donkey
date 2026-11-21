// Mach-O compact unwind (G23-T3): the __unwind_info reader against llvm-objdump's listing of the
// stripped fixtures, its refusals on synthetic sections, and the seeds the analysis takes from it.
// Fixtures and oracle: tests/fixtures/unwind_info/PROVENANCE.md.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/function_starts.h"
#include "donkey/binary/image.h"
#include "donkey/binary/isolation.h"
#include "donkey/binary/unwind_info.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/unwind_info/" + name;
}

struct Expected {
  std::string name;
  std::vector<donkey::UnwindInfoEntry> entries;
  std::uint64_t end;
  /// Every function of the unstripped build (`llvm-nm -n`), for the analysis test.
  std::vector<std::uint64_t> functions;
};

// `llvm-objdump --macho --unwind-info` on each fixture; the symbols from the unstripped link.
std::vector<Expected> oracle() {
  return {
      {"unwind_x86_64",
       {{0x1000003a0, 0x01000000},
        {0x100000410, 0x01010001},
        {0x100000450, 0x01030161},
        {0x1000004d0, 0x01010001}},
       0x1000004fa,
       {0x1000003a0, 0x1000003b0, 0x100000410, 0x100000450, 0x100000490, 0x1000004d0}},
      {"unwind_arm64",
       {{0x100000350, 0x02000000},
        {0x100000358, 0x02011010},
        {0x1000003b4, 0x04000001},
        {0x100000400, 0x04000003},
        {0x100000494, 0x04000001}},
       0x1000004c8,
       {0x100000350, 0x100000358, 0x1000003b4, 0x100000400, 0x100000454, 0x100000494}},
  };
}

void put32(std::vector<std::byte>& data, std::size_t at, std::uint32_t value) {
  if (data.size() < at + 4) {
    data.resize(at + 4);
  }
  for (std::size_t byte = 0; byte < 4; ++byte) {
    data[at + byte] = static_cast<std::byte>((value >> (8U * byte)) & 0xffU);
  }
}

void put16(std::vector<std::byte>& data, std::size_t at, std::uint16_t value) {
  if (data.size() < at + 2) {
    data.resize(at + 2);
  }
  data[at] = static_cast<std::byte>(value & 0xffU);
  data[at + 1] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

/// A section with one common encoding (0x01000000), an index of one page over [0x100, 0x200) and
/// its sentinel, and the page at offset 56: regular with entries 0x100 (0x02000000) and 0x180
/// (0x01000000), or compressed with entries 0x100 (common encoding 0) and 0x140 (the page's own
/// encoding 0x04000005).
std::vector<std::byte> section(bool compressed) {
  std::vector<std::byte> data;
  put32(data, 0, 1);   // version
  put32(data, 4, 28);  // common encodings
  put32(data, 8, 1);
  put32(data, 12, 32);  // personalities
  put32(data, 16, 0);
  put32(data, 20, 32);  // index
  put32(data, 24, 2);
  put32(data, 28, 0x01000000);
  put32(data, 32, 0x100);  // index[0]
  put32(data, 36, 56);
  put32(data, 40, 56);
  put32(data, 44, 0x200);  // the sentinel
  put32(data, 48, 0);
  put32(data, 52, 56);
  if (!compressed) {
    put32(data, 56, 2);
    put16(data, 60, 8);
    put16(data, 62, 2);
    put32(data, 64, 0x100);
    put32(data, 68, 0x02000000);
    put32(data, 72, 0x180);
    put32(data, 76, 0x01000000);
  } else {
    put32(data, 56, 3);
    put16(data, 60, 12);  // entries
    put16(data, 62, 2);
    put16(data, 64, 20);  // the page's encodings
    put16(data, 66, 1);
    put32(data, 68, 0x00000000);          // common encoding 0, offset 0
    put32(data, 72, (1U << 24) | 0x40U);  // the page's encoding 0, offset 0x40
    put32(data, 76, 0x04000005);
  }
  return data;
}

constexpr std::uint64_t kBase = 0x100000000;

std::string code_of(const std::vector<std::byte>& data, std::size_t limit = 1U << 20) {
  auto read = donkey::read_unwind_info(data, kBase, donkey::Endian::Little, limit);
  return read ? std::string("accepted") : read.diagnostic().code;
}

}  // namespace

// Every entry and the end of the range, as `llvm-objdump --macho --unwind-info` lists them.
TEST(UnwindInfo, MatchTheOracle) {
  for (const Expected& want : oracle()) {
    auto loaded = donkey::load_binary(fixture(want.name));
    ASSERT_TRUE(loaded.has_value()) << want.name << ": " << loaded.diagnostic().message;
    auto read = donkey::read_unwind_info_of_image(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(read.has_value()) << want.name << ": " << read.diagnostic().message;
    ASSERT_EQ(read.value().entries.size(), want.entries.size()) << want.name;
    for (std::size_t i = 0; i < want.entries.size(); ++i) {
      EXPECT_EQ(read.value().entries[i].start, want.entries[i].start) << want.name << " " << i;
      EXPECT_EQ(read.value().entries[i].encoding, want.entries[i].encoding)
          << want.name << " " << i;
    }
    EXPECT_EQ(read.value().end, want.end) << want.name;
  }
}

// The linker folds adjacent functions that share an encoding into one entry, so every entry is a
// function start of the unstripped build, and some starts have no entry.
TEST(UnwindInfo, EntriesAreASubsetOfTheFunctionStarts) {
  for (const Expected& want : oracle()) {
    for (const donkey::UnwindInfoEntry& entry : want.entries) {
      EXPECT_NE(std::find(want.functions.begin(), want.functions.end(), entry.start),
                want.functions.end())
          << want.name << " " << std::hex << entry.start;
    }
    EXPECT_LT(want.entries.size(), want.functions.size()) << want.name;
  }
}

TEST(UnwindInfo, AnImageWithoutTheSectionHasNoEntries) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-macho-arm64");
  ASSERT_TRUE(loaded.has_value());
  auto read = donkey::read_unwind_info_of_image(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(read.has_value());
  EXPECT_TRUE(read.value().entries.empty());
}

TEST(UnwindInfo, ReadsRegularAndCompressedPages) {
  auto regular = donkey::read_unwind_info(section(false), kBase, donkey::Endian::Little);
  ASSERT_TRUE(regular.has_value()) << regular.diagnostic().message;
  ASSERT_EQ(regular.value().entries.size(), 2U);
  EXPECT_EQ(regular.value().entries[0].start, kBase + 0x100);
  EXPECT_EQ(regular.value().entries[0].encoding, 0x02000000U);
  EXPECT_EQ(regular.value().entries[1].start, kBase + 0x180);
  EXPECT_EQ(regular.value().entries[1].encoding, 0x01000000U);
  EXPECT_EQ(regular.value().end, kBase + 0x200);

  auto compressed = donkey::read_unwind_info(section(true), kBase, donkey::Endian::Little);
  ASSERT_TRUE(compressed.has_value()) << compressed.diagnostic().message;
  ASSERT_EQ(compressed.value().entries.size(), 2U);
  EXPECT_EQ(compressed.value().entries[0].start, kBase + 0x100);
  EXPECT_EQ(compressed.value().entries[0].encoding, 0x01000000U);
  EXPECT_EQ(compressed.value().entries[1].start, kBase + 0x140);
  EXPECT_EQ(compressed.value().entries[1].encoding, 0x04000005U);
}

TEST(UnwindInfo, AnIndexWithOnlyTheSentinelHasNoEntries) {
  auto data = section(false);
  put32(data, 24, 1);  // the index is just entry 0, which has a page: no sentinel
  EXPECT_EQ(code_of(data), "unwind_info.bad_index");
  put32(data, 20, 44);  // the index is just the sentinel
  auto read = donkey::read_unwind_info(data, kBase, donkey::Endian::Little);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_TRUE(read.value().entries.empty());
  EXPECT_EQ(read.value().end, kBase + 0x200);
}

TEST(UnwindInfo, RefusesBrokenSections) {
  // Too short for the header, and another version.
  EXPECT_EQ(code_of(std::vector<std::byte>(27)), "unwind_info.bad_header");
  {
    auto data = section(false);
    put32(data, 0, 2);
    EXPECT_EQ(code_of(data), "unwind_info.bad_header");
  }
  // Arrays outside the section: the index, the common encodings with a count that would overflow
  // a 64-bit size, the personalities.
  {
    auto data = section(false);
    put32(data, 24, 100);
    EXPECT_EQ(code_of(data), "unwind_info.outside_section");
    data = section(false);
    put32(data, 8, 0xffffffffU);
    EXPECT_EQ(code_of(data), "unwind_info.outside_section");
    data = section(false);
    put32(data, 12, 0xfffffff0U);
    put32(data, 16, 1);
    EXPECT_EQ(code_of(data), "unwind_info.outside_section");
  }
  // A page and a page's entries outside the section.
  {
    auto data = section(false);
    put32(data, 36, 0xfff0);
    EXPECT_EQ(code_of(data), "unwind_info.outside_section");
    data = section(false);
    put16(data, 62, 3);
    EXPECT_EQ(code_of(data), "unwind_info.outside_section");
    data = section(true);
    put16(data, 66, 4);
    EXPECT_EQ(code_of(data), "unwind_info.outside_section");
  }
  // Index function offsets that decrease, and an entry before the sentinel with no page.
  {
    auto data = section(false);
    put32(data, 44, 0x80);
    EXPECT_EQ(code_of(data), "unwind_info.bad_index");
    data = section(false);
    put32(data, 36, 0);  // index[0] comes before the sentinel and has no page
    EXPECT_EQ(code_of(data), "unwind_info.bad_index");
  }
  // A page kind other than 2 or 3, and entries outside their index range.
  {
    auto data = section(false);
    put32(data, 56, 1);
    EXPECT_EQ(code_of(data), "unwind_info.bad_page");
    data = section(false);
    put32(data, 72, 0x200);  // the range is [0x100, 0x200)
    EXPECT_EQ(code_of(data), "unwind_info.bad_page");
    data = section(false);
    put32(data, 64, 0x80);
    EXPECT_EQ(code_of(data), "unwind_info.bad_page");
    data = section(true);
    put32(data, 72, (1U << 24) | 0x100U);
    EXPECT_EQ(code_of(data), "unwind_info.bad_page");
  }
  // A compressed entry whose encoding index names nothing: one common and one page encoding.
  {
    auto data = section(true);
    put32(data, 72, (2U << 24) | 0x40U);
    EXPECT_EQ(code_of(data), "unwind_info.bad_encoding_index");
  }
  // Entries that do not increase.
  {
    auto data = section(false);
    put32(data, 72, 0x100);
    EXPECT_EQ(code_of(data), "unwind_info.unsorted");
  }
  // More entries than the limit.
  EXPECT_EQ(code_of(section(false), 1), "unwind_info.too_many");
  EXPECT_EQ(code_of(section(false), 2), "accepted");
}

// The image base plus the sentinel's offset must not wrap past the top of the address space.
TEST(UnwindInfo, RefusesAWrappingRange) {
  auto read =
      donkey::read_unwind_info(section(false), 0xffffffffffffff00ULL, donkey::Endian::Little);
  ASSERT_FALSE(read.has_value());
  EXPECT_EQ(read.diagnostic().code, "unwind_info.bad_index");
}

TEST(UnwindInfo, AnIsolatedLoadGivesTheSameEntries) {
  if (!donkey::process_isolation_available()) {
    GTEST_SKIP() << "OS process isolation not supported on this platform";
  }
  auto direct = donkey::load_binary(fixture("unwind_x86_64"));
  ASSERT_TRUE(direct.has_value()) << direct.diagnostic().message;
  auto isolated = donkey::load_binary_isolated(fixture("unwind_x86_64"));
  ASSERT_TRUE(isolated.has_value()) << isolated.diagnostic().message;
  auto a = donkey::read_unwind_info_of_image(direct.value().image, direct.value().data);
  auto b = donkey::read_unwind_info_of_image(isolated.value().image, isolated.value().data);
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value()) << b.diagnostic().message;
  ASSERT_EQ(b.value().entries.size(), a.value().entries.size());
  for (std::size_t i = 0; i < a.value().entries.size(); ++i) {
    EXPECT_EQ(b.value().entries[i].start, a.value().entries[i].start);
  }
}

// Linked without LC_FUNCTION_STARTS and stripped, the image names only its entry point. The
// compact unwind entries give the starts that no call reaches (functions reached through the
// table in data), each marked as an unwind start, and the calls give the rest: every function of
// the unstripped build is found.
TEST(Analysis, MachOUnwindInfoSeedsAStrippedBinary) {
  for (const Expected& want : oracle()) {
    auto loaded = donkey::load_binary(fixture(want.name));
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded.value().image.function_starts_size, 0U) << want.name;
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
    EXPECT_FALSE(analysis.value().partial) << want.name;
    const auto& functions = analysis.value().functions;
    for (const std::uint64_t start : want.functions) {
      const auto found =
          std::find_if(functions.begin(), functions.end(),
                       [&](const donkey::Function& f) { return f.address == start; });
      ASSERT_NE(found, functions.end()) << want.name << " " << std::hex << start;
      const bool listed =
          std::any_of(want.entries.begin(), want.entries.end(),
                      [&](const donkey::UnwindInfoEntry& e) { return e.start == start; });
      EXPECT_EQ(found->from_unwind, listed) << want.name << " " << std::hex << start;
    }
  }
}

// On the LC_FUNCTION_STARTS fixtures, which have both tables, every compact unwind entry is one of
// the linker's function starts (here, one folded entry each: all four functions share an encoding).
TEST(UnwindInfo, AgreesWithFunctionStarts) {
  for (const std::string name : {"starts_x86_64", "starts_arm64"}) {
    auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/function_starts/" + name);
    ASSERT_TRUE(loaded.has_value());
    auto compact = donkey::read_unwind_info_of_image(loaded.value().image, loaded.value().data);
    auto starts = donkey::read_function_starts_of_image(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(compact.has_value()) << compact.diagnostic().message;
    ASSERT_TRUE(starts.has_value());
    ASSERT_EQ(compact.value().entries.size(), 1U) << name;
    for (const donkey::UnwindInfoEntry& entry : compact.value().entries) {
      EXPECT_NE(std::find(starts.value().begin(), starts.value().end(), entry.start),
                starts.value().end())
          << name << " " << std::hex << entry.start;
    }
  }
}

// UNWIND_IS_NOT_FUNCTION_START marks a range inside a function: the entry is kept, and its address
// is not a start. On a regular page the flag is in the entry; on a compressed page it comes from
// the common encoding the entry names. The unflagged neighbour stays a start.
TEST(UnwindInfo, AnEntryInsideAFunctionIsNotAStart) {
  auto regular = section(false);
  put32(regular, 76, 0x81000000U);  // the entry at 0x180
  auto read = donkey::read_unwind_info(regular, kBase, donkey::Endian::Little);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_EQ(read.value().entries.size(), 2U);
  EXPECT_EQ(donkey::unwind_function_starts(read.value()),
            (std::vector<std::uint64_t>{kBase + 0x100}));

  auto compressed = section(true);
  put32(compressed, 28, 0x81000000U);  // common encoding 0, named by the entry at 0x100
  read = donkey::read_unwind_info(compressed, kBase, donkey::Endian::Little);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_EQ(read.value().entries.size(), 2U);
  EXPECT_EQ(donkey::unwind_function_starts(read.value()),
            (std::vector<std::uint64_t>{kBase + 0x140}));
}

// A page's arrays follow its header and do not overlap each other.
TEST(UnwindInfo, RefusesArraysOverlappingTheHeaderOrEachOther) {
  auto data = section(false);
  put16(data, 60, 0);  // regular entries read from the page header
  EXPECT_EQ(code_of(data), "unwind_info.bad_page");
  data = section(true);
  put16(data, 60, 8);  // compressed entries start inside the 12-byte header
  EXPECT_EQ(code_of(data), "unwind_info.bad_page");
  data = section(true);
  put16(data, 64, 4);  // compressed encodings start inside the header
  EXPECT_EQ(code_of(data), "unwind_info.bad_page");
  data = section(true);
  put16(data, 60, 16);  // the entries (72..80) run into the encodings (76..80)
  EXPECT_EQ(code_of(data), "unwind_info.bad_page");
  EXPECT_EQ(code_of(section(true)), "accepted");
}
