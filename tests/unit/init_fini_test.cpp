// G24: ELF initialisation and termination function starts (donkey/binary/init_fini.h), on a
// synthetic image that covers each rule and on a library the test build links.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/binary/init_fini.h"

namespace {

void put64(std::vector<std::byte>& data, std::size_t at, std::uint64_t value) {
  if (data.size() < at + 8) {
    data.resize(at + 8);
  }
  for (std::size_t i = 0; i < 8; ++i) {
    data[at + i] = static_cast<std::byte>((value >> (8U * i)) & 0xffU);
  }
}

donkey::Section section(const char* name, std::uint64_t address, std::uint64_t offset,
                        std::uint64_t size, bool executable = false) {
  donkey::Section out;
  out.name = name;
  out.address = address;
  out.file_offset = offset;
  out.file_size = size;
  out.virtual_size = size;
  out.executable = executable;
  out.has_file_data = true;
  return out;
}

}  // namespace

// Each rule once:
// - `.init` starts a function;
// - DT_FINI names one;
// - an array entry is its file value when no relocation covers it, and the RELATIVE addend when one
//   does;
// - an entry with a symbolic relocation names another image;
// - 0 and -1 are placeholders;
// - an array without its size, and one that is not a whole number of pointers, are unreadable.
TEST(InitFini, ReadsTagsSectionsAndRelocatedArrays) {
  std::vector<std::byte> data(0x400);
  // .init_array at 0x2000: 0x1111 (no relocation), 0 (RELATIVE, addend 0x1500), 0x9999 (R_X86_64_64
  // against a symbol: another image), -1 (a placeholder).
  put64(data, 0x100, 0x1111);
  put64(data, 0x108, 0);
  put64(data, 0x110, 0x9999);
  put64(data, 0x118, ~std::uint64_t{0});
  // .rela.dyn: (place, info, addend).
  put64(data, 0x200, 0x2008);
  put64(data, 0x208, 8);  // R_X86_64_RELATIVE
  put64(data, 0x210, 0x1500);
  put64(data, 0x218, 0x2010);
  put64(data, 0x220, (std::uint64_t{1} << 32) | 1U);  // R_X86_64_64, symbol 1
  put64(data, 0x228, 0);
  // .dynamic: DT_FINI 0x1800, DT_PREINIT_ARRAY without DT_PREINIT_ARRAYSZ, DT_NULL.
  put64(data, 0x300, 13);
  put64(data, 0x308, 0x1800);
  put64(data, 0x310, 32);
  put64(data, 0x318, 0x2000);
  put64(data, 0x320, 0);
  put64(data, 0x328, 0);

  donkey::BinaryImage image;
  image.format = donkey::BinaryFormat::Elf;
  image.architecture = donkey::Architecture::X86_64;
  image.bits = 64;
  image.sections.push_back(section(".init", 0x1000, 0x0, 4, true));
  image.sections.push_back(section(".init_array", 0x2000, 0x100, 32));
  image.sections.push_back(section(".fini_array", 0x2100, 0x180, 12));  // not whole pointers
  image.sections.push_back(section(".rela.dyn", 0x3000, 0x200, 48));
  image.sections.push_back(section(".dynamic", 0x3100, 0x300, 48));

  const auto read = donkey::read_init_fini_of_image(image, data);
  EXPECT_EQ(read.starts, (std::vector<std::uint64_t>{0x1000, 0x1111, 0x1500, 0x1800}));
  EXPECT_EQ(read.unreadable, 2U);
}

TEST(InitFini, AnotherFormatHasNone) {
  donkey::BinaryImage image;
  image.format = donkey::BinaryFormat::Pe;
  const auto read = donkey::read_init_fini_of_image(image, {});
  EXPECT_TRUE(read.starts.empty());
  EXPECT_EQ(read.unreadable, 0U);
}

// The corpus library is built by the test build. On an ELF host, its C runtime functions are found
// and marked, each one a function symbol of the library.
TEST(Analysis, ElfInitAndFiniFunctionsAreSeeded) {
  auto loaded = donkey::load_binary(DONKEY_CORPUS_O0_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  if (loaded.value().image.format != donkey::BinaryFormat::Elf) {
    GTEST_SKIP() << "the corpus library is not ELF on this host";
  }
  const auto read = donkey::read_init_fini_of_image(loaded.value().image, loaded.value().data);
  ASSERT_FALSE(read.starts.empty());
  EXPECT_EQ(read.unreadable, 0U);
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
  const auto& functions = analysis.value().functions;
  std::size_t marked = 0;
  for (const std::uint64_t start : read.starts) {
    const auto found = std::find_if(functions.begin(), functions.end(),
                                    [&](const donkey::Function& f) { return f.address == start; });
    ASSERT_NE(found, functions.end()) << std::hex << start;
    EXPECT_TRUE(found->from_init_fini) << std::hex << start;
    ++marked;
    // Each is a function symbol of the unstripped library (`_init`, `_fini`, `frame_dummy`, ...).
    const auto& symbols = loaded.value().image.symbols;
    EXPECT_TRUE(std::any_of(symbols.begin(), symbols.end(),
                            [&](const donkey::Symbol& s) {
                              return s.address == start &&
                                     (s.kind == donkey::SymbolKind::Function || s.name == "_init" ||
                                      s.name == "_fini");
                            }))
        << std::hex << start;
  }
  EXPECT_GE(marked, 2U);
}
