#include "donkey/binary/plt.h"

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "elf_dynamic.h"

namespace donkey {
namespace {

using binary::detail::kMaxRelocationEntries;
using binary::detail::kRelaEntrySize;

constexpr std::uint64_t kJumpSlotX86_64 = 7;      // R_X86_64_JUMP_SLOT
constexpr std::uint64_t kJumpSlotAArch64 = 1026;  // R_AARCH64_JUMP_SLOT

/// The GOT slot an AArch64 PLT entry jumps through: `adrp x16, page; ldr x17, [x16, #off];
/// add x16, x16, #lo; br x17`, the 16-byte entry of `.plt` and `.plt.sec`. The slot is the page
/// of the ADRP plus the LDR's offset, which the instruction scales by 8. The caller tries every
/// 4-byte position, so a BTI or padding instruction before the sequence does not matter. A sequence
/// that no JUMP_SLOT names (PLT0, for one) yields nothing.
std::optional<std::uint64_t> aarch64_plt_slot(const ByteReader& reader, std::uint64_t file_at,
                                              std::uint64_t address) {
  const auto adrp = reader.u32(file_at, Endian::Little);
  const auto ldr = reader.u32(file_at + 4, Endian::Little);
  const auto add = reader.u32(file_at + 8, Endian::Little);
  const auto br = reader.u32(file_at + 12, Endian::Little);
  if (!adrp || !ldr || !add || !br) {
    return std::nullopt;
  }
  const std::uint32_t a = adrp.value();
  const std::uint32_t l = ldr.value();
  const std::uint32_t d = add.value();
  if ((a & 0x9F00'001FU) != 0x9000'0010U ||  // adrp x16, page
      (l & 0xFFC0'03FFU) != 0xF940'0211U ||  // ldr x17, [x16, #imm]
      (d & 0xFFC0'03FFU) != 0x9100'0210U ||  // add x16, x16, #lo
      br.value() != 0xD61F'0220U) {          // br x17
    return std::nullopt;
  }
  // The ADRP's 21-bit page offset: immhi:immlo, sign-extended.
  std::int64_t pages =
      static_cast<std::int64_t>(((a >> 5U) & 0x7'FFFFU) << 2U | ((a >> 29U) & 0x3U));
  if ((pages & 0x10'0000) != 0) {
    pages -= 0x20'0000;
  }
  const auto page = static_cast<std::int64_t>(address & ~std::uint64_t{0xFFF}) + (pages << 12);
  const std::uint64_t offset = ((l >> 10U) & 0xFFFU) * 8U;
  return static_cast<std::uint64_t>(page) + offset;
}

}  // namespace

/// Stub address -> imported name, for the PLT entries that jump through a JUMP_SLOT.
std::map<std::uint64_t, std::string> plt_stub_imports(const BinaryImage& image,
                                                      std::span<const std::byte> data) {
  std::map<std::uint64_t, std::string> stubs;
  const bool aarch64 = image.architecture == Architecture::AArch64;
  if (!aarch64 && image.architecture != Architecture::X86_64) {
    return stubs;
  }
  const std::uint64_t jump_slot = aarch64 ? kJumpSlotAArch64 : kJumpSlotX86_64;
  // The GOT slot each JUMP_SLOT relocation fills, and the import it names.
  std::map<std::uint64_t, std::string> got_names;
  const std::vector<std::string> names = binary::detail::dynamic_symbol_names(image, data);
  const ByteReader reader(data);
  for (const Section& section : image.sections) {
    if (section.name != ".rela.plt" || !section.has_file_data) {
      continue;
    }
    const std::uint64_t count = section.file_size / kRelaEntrySize;
    for (std::uint64_t i = 0; i < count && i < kMaxRelocationEntries; ++i) {
      const std::uint64_t entry = section.file_offset + i * kRelaEntrySize;
      const auto place = reader.u64(entry, Endian::Little);
      const auto info_word = reader.u64(entry + 8, Endian::Little);
      if (!place || !info_word) {
        break;
      }
      if ((info_word.value() & 0xffffffffU) != jump_slot) {
        continue;
      }
      const std::uint64_t symbol = info_word.value() >> 32;
      got_names[place.value()] = symbol < names.size() ? names[symbol] : std::string();
    }
  }
  // x86-64: each PLT entry starts with an indirect jump through its GOT slot (`ff 25 disp32`).
  // The jump may follow an `endbr64` or a `bnd` prefix, so every 16-byte entry is searched.
  // AArch64: each 16-byte entry loads its slot's address with an ADRP and an LDR.
  for (const Section& section : image.sections) {
    if ((section.name != ".plt" && section.name != ".plt.sec") || !section.has_file_data) {
      continue;
    }
    if (aarch64) {
      // The stubs are not on a fixed stride: lld 18 emits 24-byte entries, each starting with an
      // ADRP, so a scan on 16-byte boundaries names one stub in two and misses the rest. Every
      // 4-byte position is tried instead. A match needs the whole sequence and a slot a JUMP_SLOT
      // names, so unrelated code gets no name.
      for (std::uint64_t at = 0; at + 16 <= section.file_size; at += 4) {
        const auto got = aarch64_plt_slot(reader, section.file_offset + at, section.address + at);
        if (!got) {
          continue;
        }
        if (const auto it = got_names.find(*got); it != got_names.end()) {
          stubs[section.address + at] = it->second;
        }
      }
      continue;
    }
    for (std::uint64_t entry = 0; entry + 16 <= section.file_size; entry += 16) {
      for (std::uint64_t at = 0; at <= 10; ++at) {
        const std::uint64_t base = section.file_offset + entry + at;
        const auto op0 = reader.u8(base);
        const auto op1 = reader.u8(base + 1);
        if (!op0 || !op1 || op0.value() != 0xff || op1.value() != 0x25) {
          continue;
        }
        const auto disp = reader.u32(base + 2, Endian::Little);
        if (!disp) {
          break;
        }
        const std::uint64_t next = section.address + entry + at + 6;
        const std::uint64_t got =
            next + static_cast<std::uint64_t>(static_cast<std::int64_t>(
                       static_cast<std::int32_t>(static_cast<std::uint32_t>(disp.value()))));
        if (const auto it = got_names.find(got); it != got_names.end()) {
          stubs[section.address + entry] = it->second;
        }
        break;
      }
    }
  }
  return stubs;
}

}  // namespace donkey
