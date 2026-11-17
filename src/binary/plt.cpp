#include "donkey/binary/plt.h"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "elf_dynamic.h"

namespace donkey {
namespace {

using binary::detail::kMaxRelocationEntries;
using binary::detail::kRelaEntrySize;

constexpr std::uint64_t kJumpSlotX86_64 = 7;       // R_X86_64_JUMP_SLOT
constexpr std::uint64_t kGlobDatX86_64 = 6;        // R_X86_64_GLOB_DAT
constexpr std::uint64_t kJumpSlotAArch64 = 1026;   // R_AARCH64_JUMP_SLOT
constexpr std::uint64_t kIRelativeX86_64 = 37;     // R_X86_64_IRELATIVE
constexpr std::uint64_t kIRelativeAArch64 = 1032;  // R_AARCH64_IRELATIVE

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

namespace {

std::map<std::uint64_t, std::string> glob_dat_slots(const BinaryImage& image,
                                                    std::span<const std::byte> data,
                                                    bool include_defined);

/// Stub address -> the name its relocation names, for the PLT entries that jump through a
/// JUMP_SLOT, and the `.plt.got` entries that jump through a GLOB_DAT slot. Only imports, unless
/// `include_defined`: then also the image's own interposable functions.
std::map<std::uint64_t, std::string> stub_names(const BinaryImage& image,
                                                std::span<const std::byte> data,
                                                bool include_defined) {
  std::map<std::uint64_t, std::string> stubs;
  const bool aarch64 = image.architecture == Architecture::AArch64;
  if (!aarch64 && image.architecture != Architecture::X86_64) {
    return stubs;
  }
  const std::uint64_t jump_slot = aarch64 ? kJumpSlotAArch64 : kJumpSlotX86_64;
  // The GOT slot each JUMP_SLOT relocation fills, and the import it names.
  std::map<std::uint64_t, std::string> got_names;
  const std::vector<std::string> names = binary::detail::dynamic_symbol_names(image, data);
  const std::vector<bool> undefined = binary::detail::dynamic_symbol_undefined(image, data);
  const auto is_undefined = [&undefined](std::uint64_t symbol) {
    return symbol < undefined.size() && undefined[symbol];
  };
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
      const std::string name = symbol < names.size() ? names[symbol] : std::string();
      // A JUMP_SLOT can name an interposable function the image defines and exports. Its stub is
      // a call to the image's own function, not to an import, so it is listed only on request.
      // The relocation's own symbol decides, not its name: an image can define one symbol and
      // import another of the same name.
      if (name.empty() || (!include_defined && !is_undefined(symbol))) {
        continue;
      }
      got_names[place.value()] = name;
    }
  }
  // An IRELATIVE slot holds what an ifunc resolver chose (libc's memcpy, strlen). Its addend is the
  // resolver, which an exported IFUNC symbol names: the stub is named by that symbol. The ifunc is
  // the image's own function, so these are listed only with `include_defined`.
  if (include_defined) {
    std::map<std::uint64_t, std::string> exported_at;
    for (const Symbol& symbol : image.symbols) {
      if (symbol.exported && !symbol.imported && !symbol.name.empty() && symbol.address != 0) {
        exported_at.emplace(symbol.address, symbol.name);
      }
    }
    const std::uint64_t irelative = aarch64 ? kIRelativeAArch64 : kIRelativeX86_64;
    for (const Section& section : image.sections) {
      if ((section.name != ".rela.plt" && section.name != ".rela.dyn") || !section.has_file_data) {
        continue;
      }
      const std::uint64_t count = section.file_size / kRelaEntrySize;
      for (std::uint64_t i = 0; i < count && i < kMaxRelocationEntries; ++i) {
        const std::uint64_t entry = section.file_offset + i * kRelaEntrySize;
        const auto place = reader.u64(entry, Endian::Little);
        const auto info_word = reader.u64(entry + 8, Endian::Little);
        const auto addend = reader.u64(entry + 16, Endian::Little);
        if (!place || !info_word || !addend) {
          break;
        }
        if ((info_word.value() & 0xffffffffU) != irelative) {
          continue;
        }
        if (const auto name = exported_at.find(addend.value()); name != exported_at.end()) {
          got_names.emplace(place.value(), name->second);
        }
      }
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
          // lld starts an entry whose address escapes with `bti c` (any BTI form): the entry, and
          // so the function, starts at the BTI, not at the ADRP after it.
          std::uint64_t entry = at;
          if (at >= 4) {
            if (const auto before = reader.u32(section.file_offset + at - 4, Endian::Little);
                before && (before.value() & 0xFFFF'FF3FU) == 0xD503'241FU) {
              entry = at - 4;
            }
          }
          stubs[section.address + entry] = it->second;
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
  // x86-64 `.plt.got`: lazy binding is off for these imports, so each entry jumps through a
  // GLOB_DAT slot (`ff 25 disp32`, after an optional ENDBR64 or BND prefix) and has no JUMP_SLOT.
  // Entries are 8 bytes (`jmp *slot(%rip); xchg %ax,%ax`) or 16 with IBT. Each 8-byte position is
  // searched; a match needs a slot that a GLOB_DAT for an import names, so other bytes get no name.
  if (!aarch64) {
    const std::map<std::uint64_t, std::string> slots = glob_dat_slots(image, data, include_defined);
    for (const Section& section : image.sections) {
      if (section.name != ".plt.got" || !section.has_file_data) {
        continue;
      }
      // An entry starts at an 8-byte boundary; its jump is in its first 8 bytes. The next entry
      // starts at the first 8-byte boundary after the jump, which steps over a 16-byte IBT entry.
      std::uint64_t entry = 0;
      while (entry + 6 <= section.file_size) {
        std::optional<std::uint64_t> jump;
        for (std::uint64_t at = entry; at < entry + 8 && at + 6 <= section.file_size; ++at) {
          const auto op0 = reader.u8(section.file_offset + at);
          const auto op1 = reader.u8(section.file_offset + at + 1);
          if (op0 && op1 && op0.value() == 0xff && op1.value() == 0x25) {
            jump = at;
            break;
          }
        }
        if (!jump) {
          entry += 8;
          continue;
        }
        const auto disp = reader.u32(section.file_offset + *jump + 2, Endian::Little);
        if (!disp) {
          break;
        }
        const std::uint64_t next = section.address + *jump + 6;
        const std::uint64_t got =
            next + static_cast<std::uint64_t>(static_cast<std::int64_t>(
                       static_cast<std::int32_t>(static_cast<std::uint32_t>(disp.value()))));
        if (const auto it = slots.find(got); it != slots.end()) {
          stubs[section.address + entry] = it->second;
        }
        entry = (*jump + 6 + 7) & ~std::uint64_t{7};
      }
    }
  }
  return stubs;
}

std::map<std::uint64_t, std::string> glob_dat_slots(const BinaryImage& image,
                                                    std::span<const std::byte> data,
                                                    bool include_defined) {
  std::map<std::uint64_t, std::string> slots;
  if (image.architecture != Architecture::X86_64) {
    return slots;
  }
  // A GLOB_DAT can also name a symbol the image defines (an address the image takes for itself).
  // Only the names the image imports are listed, so a call to its own function is never reported
  // as an unbound import.
  const std::vector<std::string> names = binary::detail::dynamic_symbol_names(image, data);
  const std::vector<bool> undefined = binary::detail::dynamic_symbol_undefined(image, data);
  const auto is_undefined = [&undefined](std::uint64_t symbol) {
    return symbol < undefined.size() && undefined[symbol];
  };
  const ByteReader reader(data);
  for (const Section& section : image.sections) {
    if (section.name != ".rela.dyn" || !section.has_file_data) {
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
      if ((info_word.value() & 0xffffffffU) != kGlobDatX86_64) {
        continue;
      }
      const std::uint64_t symbol = info_word.value() >> 32;
      if (symbol == 0 || symbol >= names.size() || names[symbol].empty() ||
          (!include_defined && !is_undefined(symbol))) {
        continue;
      }
      slots[place.value()] = names[symbol];
    }
  }
  return slots;
}

}  // namespace

std::map<std::uint64_t, std::string> plt_stub_imports(const BinaryImage& image,
                                                      std::span<const std::byte> data) {
  return stub_names(image, data, false);
}

std::map<std::uint64_t, std::string> plt_stub_targets(const BinaryImage& image,
                                                      std::span<const std::byte> data) {
  return stub_names(image, data, true);
}

std::map<std::uint64_t, std::string> got_import_slots(const BinaryImage& image,
                                                      std::span<const std::byte> data) {
  return glob_dat_slots(image, data, false);
}

}  // namespace donkey
