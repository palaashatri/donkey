#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "donkey/binary/image.h"
#include "relocate_support.h"

namespace {

using relocate_support::adrp_target_page;
using relocate_support::defined_symbol;
using relocate_support::expect_no_relocation_gaps;
using relocate_support::little_endian;
using relocate_support::object_path;
using relocate_support::offset_of;
using relocate_support::section_holding;

// The sizes in tests/fixtures/objects/reloc-common.c.
constexpr std::uint64_t kCounterSize = 4;
constexpr std::uint64_t kBufferSize = 64;
constexpr std::uint64_t kWideSize = 8;

bool disjoint(std::uint64_t a, std::uint64_t a_size, std::uint64_t b, std::uint64_t b_size) {
  return a + a_size <= b || b + b_size <= a;
}

}  // namespace

// `-fcommon` leaves three tentative definitions as COMMON symbols. They must be placed in
// zero-filled storage after the allocated sections, not left unresolved.
TEST(RelocateCommon, CommonSymbolsArePlacedInBssAndDoNotOverlap) {
  for (const char* name : {"reloc-common-x86_64.o", "reloc-common-aarch64.o"}) {
    SCOPED_TRACE(name);
    auto loaded = donkey::load_binary(object_path(name));
    ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
    const donkey::BinaryImage& image = loaded.value().image;
    expect_no_relocation_gaps(image);
    for (const donkey::Diagnostic& diagnostic : image.diagnostics) {
      EXPECT_NE(diagnostic.code, "elf.relocation_unresolved") << diagnostic.message;
      EXPECT_NE(diagnostic.code, "elf.common_size") << diagnostic.message;
      EXPECT_NE(diagnostic.code, "elf.common_alignment") << diagnostic.message;
    }

    const donkey::Symbol* counter = defined_symbol(image, "shared_counter");
    const donkey::Symbol* buffer = defined_symbol(image, "shared_buffer");
    const donkey::Symbol* wide = defined_symbol(image, "shared_wide");
    ASSERT_NE(counter, nullptr);
    ASSERT_NE(buffer, nullptr);
    ASSERT_NE(wide, nullptr);
    for (const donkey::Symbol* symbol : {counter, buffer, wide}) {
      const donkey::Section* storage = section_holding(image, symbol->address);
      ASSERT_NE(storage, nullptr) << symbol->name << " is not in a linked section";
      EXPECT_EQ(storage->name, ".bss") << symbol->name;
      EXPECT_FALSE(storage->has_file_data) << symbol->name << " is zero-filled storage";
    }
    EXPECT_TRUE(disjoint(counter->address, kCounterSize, buffer->address, kBufferSize));
    EXPECT_TRUE(disjoint(buffer->address, kBufferSize, wide->address, kWideSize));
    EXPECT_TRUE(disjoint(counter->address, kCounterSize, wide->address, kWideSize));
  }
}

// x86-64: `movsbl disp(%rip)` reads shared_buffer+3 and `addl disp(%rip)` reads
// shared_counter. The displacement is relative to the next instruction, and the
// relocation's -4 addend accounts for the displacement field itself.
TEST(RelocateCommon, X86_64RipRelativeAccessReachesEachCommonSymbol) {
  auto loaded = donkey::load_binary(object_path("reloc-common-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const std::span<const std::byte> bytes = loaded.value().data.span();

  const donkey::Symbol* function = defined_symbol(image, "read_shared");
  const donkey::Symbol* counter = defined_symbol(image, "shared_counter");
  const donkey::Symbol* buffer = defined_symbol(image, "shared_buffer");
  ASSERT_NE(function, nullptr);
  ASSERT_NE(counter, nullptr);
  ASSERT_NE(buffer, nullptr);

  bool buffer_reached = false;
  bool counter_reached = false;
  for (std::uint64_t site = function->address; site + 7 <= function->address + function->size;
       ++site) {
    std::uint64_t at = 0;
    if (!offset_of(image, site, at)) {
      continue;
    }
    const std::uint64_t opcode = little_endian(bytes, at, 3);
    if (opcode == 0x05BE0FU) {  // movsbl disp32(%rip), %eax: 0f be 05, seven bytes long
      const auto disp = static_cast<std::int32_t>(little_endian(bytes, at + 3, 4));
      const auto effective = static_cast<std::int64_t>(site) + 7 + disp;
      buffer_reached |= static_cast<std::uint64_t>(effective) == buffer->address + 3;
    } else if ((opcode & 0xFFFFU) == 0x0503U) {  // addl disp32(%rip), %eax: 03 05, six bytes
      const auto disp = static_cast<std::int32_t>(little_endian(bytes, at + 2, 4));
      const auto effective = static_cast<std::int64_t>(site) + 6 + disp;
      counter_reached |= static_cast<std::uint64_t>(effective) == counter->address;
    }
  }
  EXPECT_TRUE(buffer_reached) << "no access reaches shared_buffer+3";
  EXPECT_TRUE(counter_reached) << "no access reaches shared_counter";
}

// AArch64: each ADRP names the page of its symbol, and the load that follows carries the
// low 12 bits, scaled by the access size.
TEST(RelocateCommon, AArch64PageAccessReachesEachCommonSymbol) {
  auto loaded = donkey::load_binary(object_path("reloc-common-aarch64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const std::span<const std::byte> bytes = loaded.value().data.span();

  const donkey::Symbol* function = defined_symbol(image, "read_shared");
  const donkey::Symbol* counter = defined_symbol(image, "shared_counter");
  const donkey::Symbol* buffer = defined_symbol(image, "shared_buffer");
  ASSERT_NE(function, nullptr);
  ASSERT_NE(counter, nullptr);
  ASSERT_NE(buffer, nullptr);

  // The compiler interleaves the two ADRPs with their loads, so each load pairs with the
  // latest ADRP that wrote its base register.
  struct Page {
    std::uint32_t word;
    std::uint64_t site;
  };
  std::array<std::optional<Page>, 32> last_adrp{};
  bool buffer_reached = false;
  bool counter_reached = false;
  for (std::uint64_t site = function->address; site + 4 <= function->address + function->size;
       site += 4) {
    std::uint64_t at = 0;
    if (!offset_of(image, site, at)) {
      continue;
    }
    const auto word = static_cast<std::uint32_t>(little_endian(bytes, at, 4));
    if ((word & 0x9F00'0000U) == 0x9000'0000U) {  // ADRP writes its destination register
      last_adrp[word & 0x1FU] = Page{word, site};
      continue;
    }
    // A load or store with an unsigned 12-bit offset: the size is in bits 30-31, the base
    // register in bits 5-9.
    if ((word & 0x3B00'0000U) != 0x3900'0000U) {
      continue;
    }
    const std::optional<Page>& page = last_adrp[(word >> 5U) & 0x1FU];
    if (!page) {
      continue;
    }
    const std::uint64_t scale = word >> 30U;
    const std::uint64_t effective =
        adrp_target_page(page->word, page->site) + (((word >> 10U) & 0xFFFU) << scale);
    buffer_reached |= effective == buffer->address + 3;
    counter_reached |= effective == counter->address;
  }
  EXPECT_TRUE(buffer_reached) << "no access reaches shared_buffer+3";
  EXPECT_TRUE(counter_reached) << "no access reaches shared_counter";
}
