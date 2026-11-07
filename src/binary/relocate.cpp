#include "donkey/binary/relocate.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/byte_reader.h"

namespace donkey {
namespace {

constexpr std::uint16_t kEtRel = 1;
constexpr std::uint16_t kMachineX86_64 = 62;
constexpr std::uint16_t kMachineAarch64 = 183;
constexpr std::uint32_t kShtSymtab = 2;
constexpr std::uint32_t kShtRela = 4;
constexpr std::uint32_t kShtNobits = 8;
constexpr std::uint64_t kShfAlloc = 0x2;
constexpr std::uint64_t kShfTls = 0x400;
constexpr std::uint16_t kShnUndef = 0;
constexpr std::uint16_t kShnAbs = 0xfff1;
constexpr std::uint16_t kShnCommon = 0xfff2;
constexpr std::size_t kSectionHeaderSize = 64;
constexpr std::size_t kSymbolSize = 24;
constexpr std::size_t kRelaSize = 24;
constexpr std::uint64_t kBodyAlignment = 16;
constexpr std::uint64_t kMaxSymbolNameBytes = 4096;

// x86-64 relocation types (System V psABI).
constexpr std::uint32_t kR_X86_64_64 = 1;
constexpr std::uint32_t kR_X86_64_PC32 = 2;
constexpr std::uint32_t kR_X86_64_PLT32 = 4;
constexpr std::uint32_t kR_X86_64_32 = 10;
constexpr std::uint32_t kR_X86_64_32S = 11;
constexpr std::uint32_t kR_X86_64_GOTPCREL = 9;
constexpr std::uint32_t kR_X86_64_GOTPCRELX = 41;
constexpr std::uint32_t kR_X86_64_REX_GOTPCRELX = 42;
constexpr std::uint32_t kR_X86_64_DTPOFF32 = 21;
constexpr std::uint32_t kR_X86_64_TLSGD = 19;
constexpr std::uint32_t kR_X86_64_TLSLD = 20;
constexpr std::uint32_t kR_X86_64_TPOFF64 = 18;
constexpr std::uint32_t kR_X86_64_GOTTPOFF = 22;
constexpr std::uint32_t kR_X86_64_TPOFF32 = 23;
// AArch64 relocation types (ELF for the Arm 64-bit Architecture).
constexpr std::uint32_t kR_AARCH64_ABS64 = 257;
constexpr std::uint32_t kR_AARCH64_PREL32 = 261;
constexpr std::uint32_t kR_AARCH64_JUMP26 = 282;
constexpr std::uint32_t kR_AARCH64_CALL26 = 283;
constexpr std::uint32_t kR_AARCH64_ADR_PREL_PG_HI21 = 275;
constexpr std::uint32_t kR_AARCH64_ADD_ABS_LO12_NC = 277;
constexpr std::uint32_t kR_AARCH64_LDST8_ABS_LO12_NC = 278;
constexpr std::uint32_t kR_AARCH64_LDST16_ABS_LO12_NC = 284;
constexpr std::uint32_t kR_AARCH64_LDST32_ABS_LO12_NC = 285;
constexpr std::uint32_t kR_AARCH64_LDST64_ABS_LO12_NC = 286;
constexpr std::uint32_t kR_AARCH64_ADR_GOT_PAGE = 311;
constexpr std::uint32_t kR_AARCH64_LD64_GOT_LO12_NC = 312;
constexpr std::uint32_t kR_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 = 541;
constexpr std::uint32_t kR_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC = 542;
constexpr std::uint32_t kR_AARCH64_TLSLE_ADD_TPREL_HI12 = 549;
constexpr std::uint32_t kR_AARCH64_TLSLE_ADD_TPREL_LO12 = 550;
constexpr std::uint32_t kR_AARCH64_TLSLE_ADD_TPREL_LO12_NC = 551;
constexpr std::uint32_t kR_AARCH64_TLSDESC_LD64_LO12 = 563;
constexpr std::uint32_t kR_AARCH64_TLSDESC_ADR_PAGE21 = 562;
constexpr std::uint32_t kR_AARCH64_TLSDESC_ADD_LO12 = 564;
constexpr std::uint32_t kR_AARCH64_TLSDESC_CALL = 569;

Endian endian_of(std::span<const std::byte> file) {
  return static_cast<unsigned>(file[5]) == 2 ? Endian::Big : Endian::Little;
}

Diagnostic error_at(Status status, const char* code, std::string message) {
  return Diagnostic::make(status, code, std::move(message));
}

std::uint64_t round_up(std::uint64_t value, std::uint64_t alignment) {
  return (value + alignment - 1) / alignment * alignment;
}

void store(std::vector<std::byte>& bytes, std::uint64_t at, unsigned width, std::uint64_t value,
           Endian endian) {
  for (unsigned i = 0; i < width; ++i) {
    const unsigned shift = endian == Endian::Little ? 8U * i : 8U * (width - 1U - i);
    bytes[static_cast<std::size_t>(at) + i] = static_cast<std::byte>((value >> shift) & 0xFFU);
  }
}

std::uint64_t load(const std::vector<std::byte>& bytes, std::uint64_t at, unsigned width,
                   Endian endian) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < width; ++i) {
    const unsigned shift = endian == Endian::Little ? 8U * i : 8U * (width - 1U - i);
    value |= static_cast<std::uint64_t>(
                 std::to_integer<unsigned>(bytes[static_cast<std::size_t>(at) + i]))
             << shift;
  }
  return value;
}

template <typename T>
T zero_or(const Result<T>& result) {
  return result ? result.value() : T{};
}

bool fits_int32(std::int64_t value) {
  return value >= std::numeric_limits<std::int32_t>::min() &&
         value <= std::numeric_limits<std::int32_t>::max();
}

/// True for the relocation types that reach a symbol through its GOT slot.
/// One thread-local access of a dynamic model (GD or LD) in an x86-64 section.
struct TlsAccess {
  std::uint64_t where = 0;         ///< the displacement's offset in its section
  std::uint32_t type = 0;          ///< TLSGD or TLSLD
  std::uint64_t symbol_index = 0;  ///< the symbol the access names
  std::int64_t addend = 0;
};

/// A dynamic access as GCC and Clang emit it for x86-64: `lea x@tlsgd(%rip),%rdi` with data16
/// padding (16 bytes with the call), or `lea x@tlsld(%rip),%rdi` (12 bytes with the call). The
/// call's relocation is the paired PLT32 against __tls_get_addr.
struct TlsCallSite {
  std::uint64_t start = 0;  ///< the sequence's first byte, relative to its section
  std::uint64_t call = 0;   ///< the offset of the call's relocation
};

/// True when the bytes `expected` sit at `at` in `out`.
bool bytes_are(const std::vector<std::byte>& out, std::uint64_t at,
               std::initializer_list<std::uint8_t> expected) {
  if (at > out.size() || expected.size() > out.size() - at) {
    return false;
  }
  std::size_t i = 0;
  for (const std::uint8_t byte : expected) {
    if (std::to_integer<std::uint8_t>(out[at + i]) != byte) {
      return false;
    }
    ++i;
  }
  return true;
}

/// The call sequence around the displacement at `where`, if its bytes are one of the forms above.
std::optional<TlsCallSite> match_tls_call_site(const std::vector<std::byte>& out,
                                               std::uint64_t section_offset,
                                               std::uint64_t section_size, std::uint64_t where,
                                               bool local_dynamic) {
  if (local_dynamic) {
    // lea (7 bytes, displacement at +3), then call (5 bytes, displacement at +8).
    if (where < 3 || where - 3 + 12 > section_size) {
      return std::nullopt;
    }
    const std::uint64_t start = where - 3;
    if (!bytes_are(out, section_offset + start, {0x48, 0x8d, 0x3d}) ||
        !bytes_are(out, section_offset + start + 7, {0xe8})) {
      return std::nullopt;
    }
    return TlsCallSite{start, start + 8};
  }
  // data16 lea (8 bytes, displacement at +4), then data16 data16 rex.W call (8 bytes, displacement
  // at +12).
  if (where < 4 || where - 4 + 16 > section_size) {
    return std::nullopt;
  }
  const std::uint64_t start = where - 4;
  if (!bytes_are(out, section_offset + start, {0x66, 0x48, 0x8d, 0x3d}) ||
      !bytes_are(out, section_offset + start + 8, {0x66, 0x66, 0x48, 0xe8})) {
    return std::nullopt;
  }
  return TlsCallSite{start, start + 12};
}

bool is_got_relocation(std::uint16_t machine, std::uint32_t type) {
  if (machine == kMachineX86_64) {
    return type == kR_X86_64_GOTPCREL || type == kR_X86_64_GOTPCRELX ||
           type == kR_X86_64_REX_GOTPCRELX || type == kR_X86_64_GOTTPOFF;
  }
  return type == kR_AARCH64_ADR_GOT_PAGE || type == kR_AARCH64_LD64_GOT_LO12_NC ||
         type == kR_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 ||
         type == kR_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC;
}

/// Writes into the ADRP at file offset `at`, placed at address `place`, the page of
/// `target` relative to the page of the instruction, in 4 KiB units split over immlo
/// (bits 29-30) and immhi (bits 5-23). Returns false when the page is out of range.
bool patch_adrp(std::vector<std::byte>& out, std::uint64_t at, std::int64_t place,
                std::int64_t target, Endian endian) {
  constexpr std::int64_t kPageMask = 0xFFF;
  const std::int64_t pages = (target & ~kPageMask) - (place & ~kPageMask);
  const std::int64_t value = pages >> 12;
  if (value < -(std::int64_t{1} << 20) || value >= (std::int64_t{1} << 20)) {
    return false;
  }
  const auto imm = static_cast<std::uint64_t>(value) & 0x1F'FFFFU;
  const std::uint64_t instruction = load(out, at, 4, endian);
  const std::uint64_t patched = (instruction & ~std::uint64_t{0x60FF'FFE0U}) |
                                ((imm & 0x3U) << 29U) | (((imm >> 2U) & 0x7'FFFFU) << 5U);
  store(out, at, 4, patched, endian);
  return true;
}

/// Writes the low 12 bits of `value` (already shifted for the access size) into the 12-bit
/// immediate (bits 10-21) of the instruction at file offset `at`.
void patch_imm12(std::vector<std::byte>& out, std::uint64_t at, std::uint64_t value,
                 Endian endian) {
  const std::uint64_t instruction = load(out, at, 4, endian);
  store(out, at, 4, (instruction & ~std::uint64_t{0x003F'FC00U}) | ((value & 0xFFFU) << 10U),
        endian);
}

struct SectionHeader {
  std::uint32_t type = 0;
  std::uint64_t flags = 0;
  std::uint64_t alignment = 0;
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
  std::uint32_t link = 0;
  std::uint32_t info = 0;
  std::uint64_t entry_size = 0;
};

}  // namespace

bool is_relocatable_elf(std::span<const std::byte> file) {
  if (file.size() < 0x12 || file[0] != std::byte{0x7F} || file[1] != std::byte{'E'} ||
      file[2] != std::byte{'L'} || file[3] != std::byte{'F'} || file[4] != std::byte{2}) {
    return false;
  }
  const ByteReader reader(file);
  const auto type = reader.u16(16, endian_of(file));
  return type && type.value() == kEtRel;
}

Result<std::vector<std::byte>> link_relocatable_object(std::span<const std::byte> file,
                                                       BinaryImage& image) {
  const ByteReader reader(file);
  const Endian endian = endian_of(file);
  const auto fail = [](const char* code, std::string message) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, code, std::move(message));
  };

  const auto machine = reader.u16(18, endian);
  const auto section_offset = reader.u64(0x28, endian);
  const auto section_entry_size = reader.u16(0x3A, endian);
  const auto section_count = reader.u16(0x3C, endian);
  if (!machine || !section_offset || !section_entry_size || !section_count) {
    return fail("elf.truncated", "the object's header is truncated");
  }
  if (section_entry_size.value() != kSectionHeaderSize) {
    return fail("elf.section_entry_size", "the section header size is not 64 bytes");
  }
  const std::uint64_t count = section_count.value();
  if (count != image.sections.size()) {
    return fail("elf.section_count", "the section table does not match the parsed sections");
  }
  if (section_offset.value() > file.size() ||
      count * kSectionHeaderSize > file.size() - section_offset.value()) {
    return fail("elf.section_table", "the section table extends past the end of the file");
  }

  std::vector<SectionHeader> headers(static_cast<std::size_t>(count));
  for (std::uint64_t i = 0; i < count; ++i) {
    const std::uint64_t at = section_offset.value() + i * kSectionHeaderSize;
    SectionHeader& header = headers[static_cast<std::size_t>(i)];
    header.type = zero_or(reader.u32(at + 4, endian));
    header.flags = zero_or(reader.u64(at + 8, endian));
    header.offset = zero_or(reader.u64(at + 24, endian));
    header.size = zero_or(reader.u64(at + 32, endian));
    header.link = zero_or(reader.u32(at + 40, endian));
    header.info = zero_or(reader.u32(at + 44, endian));
    header.alignment = zero_or(reader.u64(at + 48, endian));
    header.entry_size = zero_or(reader.u64(at + 56, endian));
  }

  // Layout: the thread-local sections first, as one block, then the other allocated sections
  // in section order, all from kObjectBase. The block's offsets are what TPOFF relocations
  // need: with x86-64's variant II the block ends at the thread pointer.
  std::vector<std::optional<std::uint64_t>> placed(static_cast<std::size_t>(count));
  std::uint64_t next = kObjectBase;
  std::optional<std::uint64_t> tls_base;
  std::uint64_t tls_end = 0;
  std::uint64_t tls_align = 1;
  for (int pass = 0; pass < 2; ++pass) {
    for (std::size_t i = 1; i < headers.size(); ++i) {
      const SectionHeader& header = headers[i];
      const bool thread_local_section = (header.flags & kShfTls) != 0;
      if ((header.flags & kShfAlloc) == 0 || thread_local_section != (pass == 0)) {
        continue;
      }
      const std::uint64_t alignment = std::max<std::uint64_t>(header.alignment, 1);
      next = round_up(next, alignment);
      if (header.size > std::numeric_limits<std::uint64_t>::max() - next) {
        return fail("elf.layout_overflow", "the allocated sections do not fit in 64 bits");
      }
      placed[i] = next;
      image.sections[i].address = next;
      if (thread_local_section) {
        if (!tls_base) {
          tls_base = next;
        }
        tls_end = next + header.size;
        tls_align = std::max(tls_align, alignment);
      }
      next += header.size;
    }
  }
  image.image_base = kObjectBase;
  // The block is rounded to its alignment, as the static TLS block is.
  const std::uint64_t tls_size = tls_base ? round_up(tls_end - *tls_base, tls_align) : 0;
  // The thread-pointer offset of a thread-local address, or nothing outside the block.
  const auto tp_offset = [&](std::uint64_t address) -> std::optional<std::int64_t> {
    if (!tls_base || address < *tls_base || address > tls_end) {
      return std::nullopt;
    }
    if (machine.value() == kMachineAarch64) {
      return static_cast<std::int64_t>(address - *tls_base) + 16;
    }
    return static_cast<std::int64_t>(address - *tls_base) - static_cast<std::int64_t>(tls_size);
  };

  // The output: the file, then a copy of each allocated section that has file data.
  std::vector<std::byte> out(file.begin(), file.end());
  std::vector<std::optional<std::uint64_t>> body(static_cast<std::size_t>(count));
  for (std::size_t i = 1; i < headers.size(); ++i) {
    const SectionHeader& header = headers[i];
    if (!placed[i] || header.type == kShtNobits || header.size == 0) {
      continue;
    }
    if (header.offset > file.size() || header.size > file.size() - header.offset) {
      return fail("elf.section_out_of_bounds", "a section extends past the end of the file");
    }
    while (out.size() % kBodyAlignment != 0) {
      out.push_back(std::byte{0});
    }
    body[i] = out.size();
    out.insert(out.end(), file.begin() + static_cast<std::ptrdiff_t>(header.offset),
               file.begin() + static_cast<std::ptrdiff_t>(header.offset + header.size));
    image.sections[i].file_offset = *body[i];
    image.sections[i].file_size = header.size;
  }

  std::vector<Diagnostic> diagnostics;
  const auto note = [&](Status status, const char* code, std::string message) {
    image.partial = true;
    diagnostics.push_back(error_at(status, code, std::move(message)));
  };

  // Symbols: their addresses in the layout, from the first symbol table.
  std::vector<std::optional<std::uint64_t>> symbol_address;
  std::vector<std::string> symbol_name;
  std::map<std::string, std::uint64_t> defined;
  // Common symbols are placed after the allocated sections, in order, each aligned.
  std::uint64_t common_next = next;
  for (const SectionHeader& table : headers) {
    if (table.type != kShtSymtab) {
      continue;
    }
    if (table.link >= headers.size() || table.entry_size != kSymbolSize) {
      note(Status::Unsupported, "elf.symbol_table", "the symbol table cannot be read");
      break;
    }
    const SectionHeader& strings = headers[table.link];
    const auto strings_view =
        (strings.offset <= file.size() && strings.size <= file.size() - strings.offset)
            ? std::string_view(reinterpret_cast<const char*>(file.data() + strings.offset),
                               static_cast<std::size_t>(strings.size))
            : std::string_view();
    const std::uint64_t entries = table.size / kSymbolSize;
    if (table.offset > file.size() || table.size > file.size() - table.offset) {
      note(Status::Unsupported, "elf.symbol_table", "the symbol table cannot be read");
      break;
    }
    for (std::uint64_t k = 0; k < entries; ++k) {
      const std::uint64_t at = table.offset + k * kSymbolSize;
      const std::uint32_t name_offset = zero_or(reader.u32(at, endian));
      const std::uint16_t section_index = zero_or(reader.u16(at + 6, endian));
      const std::uint64_t value = zero_or(reader.u64(at + 8, endian));
      std::string name;
      if (name_offset != 0 && name_offset < strings_view.size()) {
        const std::string_view rest = strings_view.substr(name_offset);
        const std::size_t length = std::min<std::size_t>(
            rest.find('\0') == std::string_view::npos ? rest.size() : rest.find('\0'),
            kMaxSymbolNameBytes);
        name = std::string(rest.substr(0, length));
      }
      std::optional<std::uint64_t> address;
      if (section_index == kShnAbs) {
        address = value;
      } else if (section_index == kShnCommon) {
        // st_value is the alignment and st_size the size. The symbol is zero-filled storage.
        const std::uint64_t size = zero_or(reader.u64(at + 16, endian));
        const std::uint64_t alignment = std::max<std::uint64_t>(value, 1);
        if ((alignment & (alignment - 1)) != 0) {
          note(Status::Unsupported, "elf.common_alignment",
               "a common symbol's alignment is not a power of two");
        } else if (size >
                   std::numeric_limits<std::uint64_t>::max() - round_up(common_next, alignment)) {
          note(Status::Unsupported, "elf.common_size", "the common symbols do not fit in 64 bits");
        } else {
          common_next = round_up(common_next, alignment);
          address = common_next;
          common_next += size;
        }
      } else if (section_index != kShnUndef && section_index < placed.size() &&
                 placed[section_index]) {
        address = *placed[section_index] + value;
      }
      if (address && !name.empty()) {
        defined.emplace(name, *address);
      }
      symbol_address.push_back(address);
      symbol_name.push_back(std::move(name));
    }
    break;
  }
  if (common_next != next) {
    // The common symbols as one zero-filled section, after the allocated sections.
    Section common;
    common.id = SectionId{image.sections.size() + 1};
    common.name = ".bss";
    common.type = "nobits";
    common.address = next;
    common.virtual_size = common_next - next;
    common.readable = true;
    common.writable = true;
    common.has_file_data = false;
    image.sections.push_back(common);
    next = common_next;
  }
  for (Symbol& symbol : image.symbols) {
    if (symbol.imported) {
      continue;
    }
    if (const auto found = defined.find(symbol.name); found != defined.end()) {
      symbol.address = found->second;
    }
  }

  // Relocations: each RELA section patches the section named by its `info` field.
  const bool known_machine =
      machine.value() == kMachineX86_64 || machine.value() == kMachineAarch64;
  if (!known_machine) {
    note(Status::Unsupported, "elf.relocation_machine",
         "relocations are applied for x86-64 and AArch64 objects only");
  }
  // GOT: an 8-byte slot for each defined symbol that a GOT relocation names, placed after the
  // allocated sections. The static link stores the symbol's address in its slot, so a
  // GOT-relative access loads that address.
  std::map<std::uint64_t, std::uint64_t> got_slot;  // symbol index -> slot address
  std::set<std::uint64_t> tp_symbols;  // symbols whose slot holds a thread-pointer offset
  if (known_machine) {
    std::vector<std::uint64_t> got_symbols;
    for (const SectionHeader& relocations : headers) {
      if (relocations.type != kShtRela || relocations.entry_size != kRelaSize ||
          relocations.offset > file.size() || relocations.size > file.size() - relocations.offset) {
        continue;
      }
      const std::size_t target = relocations.info;
      if (target == 0 || target >= headers.size() || !placed[target] || !body[target]) {
        continue;
      }
      for (std::uint64_t k = 0; k < relocations.size / kRelaSize; ++k) {
        const std::uint64_t info =
            zero_or(reader.u64(relocations.offset + k * kRelaSize + 8, endian));
        const auto type = static_cast<std::uint32_t>(info & 0xFFFF'FFFFU);
        const std::uint64_t symbol_index = info >> 32U;
        if (!is_got_relocation(machine.value(), type) || symbol_index == 0 ||
            symbol_index >= symbol_address.size() || !symbol_address[symbol_index] ||
            got_slot.contains(symbol_index)) {
          continue;
        }
        if (type == kR_X86_64_GOTTPOFF || type == kR_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 ||
            type == kR_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC) {
          tp_symbols.insert(symbol_index);
        }
        got_slot.emplace(symbol_index, 0);
        got_symbols.push_back(symbol_index);
      }
    }
    if (!got_symbols.empty()) {
      while (out.size() % 8 != 0) {
        out.push_back(std::byte{0});
      }
      const std::uint64_t got_address = round_up(next, 8);
      const std::uint64_t got_file = out.size();
      out.resize(out.size() + got_symbols.size() * 8, std::byte{0});
      for (std::size_t i = 0; i < got_symbols.size(); ++i) {
        const std::uint64_t index = got_symbols[i];
        got_slot[index] = got_address + i * 8;
        std::uint64_t value = *symbol_address[index];
        if (tp_symbols.contains(index)) {
          const auto offset = tp_offset(value);
          if (offset) {
            value = static_cast<std::uint64_t>(*offset);
          } else {
            note(Status::Unsupported, "elf.tls_symbol",
                 "an initial-exec slot names a symbol that is not thread-local");
            value = 0;
          }
        }
        store(out, got_file + i * 8, 8, value, endian);
      }
      Section got;
      got.id = SectionId{image.sections.size() + 1};
      got.name = ".got";
      got.type = "got";
      got.file_offset = got_file;
      got.file_size = got_symbols.size() * 8;
      got.virtual_size = got.file_size;
      got.alignment = 8;
      got.address = got_address;
      got.readable = true;
      got.writable = true;
      got.has_file_data = true;
      image.sections.push_back(got);
    }
  }

  for (const SectionHeader& relocations : headers) {
    if (relocations.type != kShtRela || !known_machine) {
      continue;
    }
    const std::size_t target = relocations.info;
    if (target == 0 || target >= headers.size() || !placed[target] || !body[target]) {
      continue;  // debug information and other non-allocated targets are not applied
    }
    if (relocations.entry_size != kRelaSize || relocations.offset > file.size() ||
        relocations.size > file.size() - relocations.offset) {
      note(Status::Unsupported, "elf.relocation_table", "a relocation table cannot be read");
      continue;
    }
    const SectionHeader& target_header = headers[target];
    const std::uint64_t entries = relocations.size / kRelaSize;

    // The dynamic thread-local models (GD and LD) call __tls_get_addr. A static link relaxes each
    // such sequence to a thread-pointer access and drops the call, as ld does. Only sequences
    // whose bytes, call relocation and symbol all check out are relaxed; the rest are reported.
    std::map<std::uint64_t, TlsCallSite> relaxed_sites;  // keyed by the access's displacement
    std::set<std::pair<std::uint64_t, std::uint32_t>>
        consumed;                                   // (offset, type) of relocations gone
    std::map<std::uint64_t, std::int64_t> desc_tp;  // TLSDESC sites -> offset
    bool local_dynamic_here = false;
    if (machine.value() == kMachineX86_64) {
      std::map<std::uint64_t, std::uint64_t> plt_calls;  // PLT32 offset -> symbol index
      std::vector<TlsAccess> accesses;
      for (std::uint64_t k = 0; k < entries; ++k) {
        const std::uint64_t at = relocations.offset + k * kRelaSize;
        const std::uint64_t where = zero_or(reader.u64(at, endian));
        const std::uint64_t info = zero_or(reader.u64(at + 8, endian));
        const auto type = static_cast<std::uint32_t>(info & 0xFFFF'FFFFU);
        if (type == kR_X86_64_PLT32) {
          plt_calls[where] = info >> 32U;
        } else if (type == kR_X86_64_TLSGD || type == kR_X86_64_TLSLD) {
          accesses.push_back(
              TlsAccess{where, type, info >> 32U,
                        static_cast<std::int64_t>(zero_or(reader.u64(at + 16, endian)))});
        }
      }
      for (const TlsAccess& access : accesses) {
        const bool local_dynamic = access.type == kR_X86_64_TLSLD;
        const auto site = match_tls_call_site(out, *body[target], target_header.size, access.where,
                                              local_dynamic);
        if (!site) {
          continue;
        }
        const auto call = plt_calls.find(site->call);
        if (call == plt_calls.end() || call->second >= symbol_name.size() ||
            symbol_name[call->second] != "__tls_get_addr") {
          continue;
        }
        if (!local_dynamic) {
          // GD becomes `lea tpoff(%rax)`: the symbol must be defined here, thread-local, and its
          // offset must fit. The -4 of the displacement is the PC-relative correction, so the
          // symbol's own offset is its address plus the addend plus 4.
          if (access.symbol_index == 0 || access.symbol_index >= symbol_address.size() ||
              !symbol_address[access.symbol_index]) {
            continue;
          }
          const auto offset = tp_offset(*symbol_address[access.symbol_index] +
                                        static_cast<std::uint64_t>(access.addend) + 4);
          if (!offset || !fits_int32(*offset)) {
            continue;
          }
        }
        relaxed_sites[access.where] = *site;
        consumed.insert({site->call, kR_X86_64_PLT32});
        local_dynamic_here = local_dynamic_here || local_dynamic;
      }
    }
    if (machine.value() == kMachineAarch64) {
      // A TLSDESC access (GCC's and Clang's default for -fPIC) is four instructions, each with
      // one relocation: adrp xD; ldr xN,[xD]; add xD,xD,#lo12; blr xN. A static link relaxes it
      // to the thread-pointer offset, as ld does: movz xD (the offset's bits 31:16), movk xD
      // (bits 15:0), then two nops. The offset is the thread-pointer offset of the symbol.
      std::map<std::uint64_t, std::pair<std::uint32_t, std::uint64_t>>
          desc;  // offset -> (type, symbol)
      for (std::uint64_t k = 0; k < entries; ++k) {
        const std::uint64_t at = relocations.offset + k * kRelaSize;
        const std::uint64_t where = zero_or(reader.u64(at, endian));
        const std::uint64_t info = zero_or(reader.u64(at + 8, endian));
        const auto type = static_cast<std::uint32_t>(info & 0xFFFF'FFFFU);
        if (type == kR_AARCH64_TLSDESC_ADR_PAGE21 || type == kR_AARCH64_TLSDESC_LD64_LO12 ||
            type == kR_AARCH64_TLSDESC_ADD_LO12 || type == kR_AARCH64_TLSDESC_CALL) {
          desc.emplace(where, std::make_pair(type, info >> 32U));
        }
      }
      const auto desc_is = [&](std::uint64_t offset, std::uint32_t type, std::uint64_t symbol) {
        const auto found = desc.find(offset);
        return found != desc.end() && found->second.first == type && found->second.second == symbol;
      };
      for (const auto& [where, entry] : desc) {
        if (entry.first != kR_AARCH64_TLSDESC_ADR_PAGE21) {
          continue;
        }
        const std::uint64_t symbol = entry.second;
        if (where + 16 > target_header.size ||
            !desc_is(where + 4, kR_AARCH64_TLSDESC_LD64_LO12, symbol) ||
            !desc_is(where + 8, kR_AARCH64_TLSDESC_ADD_LO12, symbol) ||
            !desc_is(where + 12, kR_AARCH64_TLSDESC_CALL, symbol)) {
          continue;
        }
        if (symbol == 0 || symbol >= symbol_address.size() || !symbol_address[symbol]) {
          continue;
        }
        const std::uint64_t base = *body[target] + where;
        const std::uint64_t adrp = load(out, base, 4, endian);
        const std::uint64_t ldr = load(out, base + 4, 4, endian);
        const std::uint64_t add = load(out, base + 8, 4, endian);
        const std::uint64_t blr = load(out, base + 12, 4, endian);
        const std::uint64_t reg = adrp & 0x1FU;
        const bool shape = (adrp & 0x9F00'0000U) == 0x9000'0000U &&  // adrp
                           (ldr & 0xFFFF'FC00U) == 0xF940'0000U &&   // ldr xN, [xD]
                           ((ldr >> 5U) & 0x1FU) == reg &&
                           (add & 0xFFC0'0000U) == 0x9100'0000U &&  // add xD, xD, #lo12
                           (add & 0x1FU) == reg && ((add >> 5U) & 0x1FU) == reg &&
                           (blr & 0xFFFF'FC1FU) == 0xD63F'0000U;  // blr xN
        if (!shape) {
          continue;
        }
        const auto offset = tp_offset(*symbol_address[symbol]);
        if (!offset || *offset < 0 || *offset > 0xFFFF'FFFFLL) {
          continue;
        }
        desc_tp.emplace(where, *offset);
        consumed.insert({where + 4, kR_AARCH64_TLSDESC_LD64_LO12});
        consumed.insert({where + 8, kR_AARCH64_TLSDESC_ADD_LO12});
        consumed.insert({where + 12, kR_AARCH64_TLSDESC_CALL});
      }
    }
    for (std::uint64_t k = 0; k < entries; ++k) {
      const std::uint64_t at = relocations.offset + k * kRelaSize;
      const std::uint64_t where = zero_or(reader.u64(at, endian));
      const std::uint64_t info = zero_or(reader.u64(at + 8, endian));
      const std::int64_t addend = static_cast<std::int64_t>(zero_or(reader.u64(at + 16, endian)));
      const std::uint64_t symbol_index = info >> 32U;
      const auto type = static_cast<std::uint32_t>(info & 0xFFFF'FFFFU);

      // The call of a relaxed dynamic access no longer exists: its bytes now hold the
      // thread-pointer access, and its relocation has nothing left to patch.
      if (consumed.contains({where, type})) {
        continue;
      }
      std::uint64_t symbol = 0;
      if (symbol_index != 0) {
        if (symbol_index >= symbol_address.size() || !symbol_address[symbol_index]) {
          const std::string name =
              symbol_index < symbol_name.size() && !symbol_name[symbol_index].empty()
                  ? symbol_name[symbol_index]
                  : "#" + std::to_string(symbol_index);
          note(Status::Unsupported, "elf.relocation_unresolved",
               "relocation against '" + name +
                   "' is not applied: the symbol is not defined in this object");
          continue;
        }
        symbol = *symbol_address[symbol_index];
      }
      if (where > target_header.size) {
        note(Status::Unsupported, "elf.relocation_range", "a relocation lies outside its section");
        continue;
      }
      const std::uint64_t place = *placed[target] + where;  // address of the patched location
      const std::uint64_t file_place = *body[target] + where;
      const auto s = static_cast<std::int64_t>(symbol);
      const auto p = static_cast<std::int64_t>(place);
      // A GOT relocation addresses the symbol's slot rather than the symbol itself.
      std::optional<std::uint64_t> slot;
      if (is_got_relocation(machine.value(), type)) {
        const auto found = got_slot.find(symbol_index);
        if (found == got_slot.end()) {
          note(Status::Unsupported, "elf.relocation_got",
               "a GOT relocation names no symbol defined in this object");
          continue;
        }
        slot = found->second;
      }

      if (machine.value() == kMachineX86_64) {
        switch (type) {
          case kR_X86_64_64:
            if (where + 8 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            store(out, file_place, 8, symbol + static_cast<std::uint64_t>(addend), endian);
            break;
          case kR_X86_64_PC32:
          case kR_X86_64_PLT32: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            const std::int64_t value = s + addend - p;
            if (!fits_int32(value)) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a PC-relative value does not fit in 32 bits");
              break;
            }
            store(out, file_place, 4, static_cast<std::uint64_t>(value) & 0xFFFF'FFFFU, endian);
            break;
          }
          case kR_X86_64_32:
          case kR_X86_64_32S: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            const std::int64_t value = s + addend;
            const bool ok =
                type == kR_X86_64_32 ? (value >= 0 && value <= 0xFFFF'FFFFLL) : fits_int32(value);
            if (!ok) {
              note(Status::Unsupported, "elf.relocation_range",
                   "an absolute value does not fit in 32 bits");
              break;
            }
            store(out, file_place, 4, static_cast<std::uint64_t>(value) & 0xFFFF'FFFFU, endian);
            break;
          }
          case kR_X86_64_GOTPCREL:
          case kR_X86_64_GOTPCRELX:
          case kR_X86_64_REX_GOTPCRELX:
          case kR_X86_64_GOTTPOFF: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            // The 32-bit displacement from the instruction to the GOT slot. The relaxable
            // forms are patched as they are: the instruction still loads through the slot.
            const std::int64_t value = static_cast<std::int64_t>(*slot) + addend - p;
            if (!fits_int32(value)) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a GOT displacement does not fit in 32 bits");
              break;
            }
            store(out, file_place, 4, static_cast<std::uint64_t>(value) & 0xFFFF'FFFFU, endian);
            break;
          }
          case kR_X86_64_TPOFF32:
          case kR_X86_64_TPOFF64: {
            // Local-exec: the thread-pointer offset of the symbol plus the addend.
            const std::uint64_t width = type == kR_X86_64_TPOFF32 ? 4 : 8;
            if (where + width > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            const auto offset = tp_offset(symbol + static_cast<std::uint64_t>(addend));
            if (!offset) {
              note(Status::Unsupported, "elf.tls_symbol",
                   "a thread-local relocation names a symbol that is not thread-local");
              break;
            }
            if (width == 4 && !fits_int32(*offset)) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a thread-pointer offset does not fit in 32 bits");
              break;
            }
            store(out, file_place, static_cast<unsigned>(width),
                  static_cast<std::uint64_t>(*offset), endian);
            break;
          }
          case kR_X86_64_TLSGD:
          case kR_X86_64_TLSLD: {
            const auto found = relaxed_sites.find(where);
            if (found == relaxed_sites.end()) {
              note(Status::Unsupported, "elf.tls_model",
                   "a dynamic thread-local access is not a GCC or Clang sequence that calls "
                   "__tls_get_addr for a symbol this object defines; it is not applied");
              break;
            }
            const std::uint64_t site_at = *body[target] + found->second.start;
            if (type == kR_X86_64_TLSLD) {
              // The module block's base is the thread pointer; the offsets are in the add that
              // follows (DTPOFF32 below).
              const std::uint8_t code[12] = {0x66, 0x66, 0x66, 0x64, 0x48, 0x8b,
                                             0x04, 0x25, 0x00, 0x00, 0x00, 0x00};
              for (std::size_t i = 0; i < sizeof(code); ++i) {
                out[site_at + i] = static_cast<std::byte>(code[i]);
              }
              break;
            }
            // GD: `mov %fs:0,%rax; lea tpoff(%rax),%rax`, the same 16 bytes ld writes.
            const auto offset = tp_offset(symbol + static_cast<std::uint64_t>(addend) + 4);
            if (!offset || !fits_int32(*offset)) {
              note(Status::Unsupported, "elf.tls_symbol",
                   "a thread-local symbol's offset does not fit; the access is not applied");
              break;
            }
            const std::uint8_t mov[9] = {0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00};
            const std::uint8_t lea[3] = {0x48, 0x8d, 0x80};
            for (std::size_t i = 0; i < sizeof(mov); ++i) {
              out[site_at + i] = static_cast<std::byte>(mov[i]);
            }
            for (std::size_t i = 0; i < sizeof(lea); ++i) {
              out[site_at + sizeof(mov) + i] = static_cast<std::byte>(lea[i]);
            }
            store(out, site_at + 12, 4, static_cast<std::uint64_t>(*offset) & 0xFFFF'FFFFU, endian);
            break;
          }
          case kR_X86_64_DTPOFF32: {
            // Only the add after a relaxed local-dynamic call takes a module offset, and that
            // offset is the variable's thread-pointer offset. Anywhere else it is not applied.
            if (!local_dynamic_here) {
              note(
                  Status::Unsupported, "elf.tls_model",
                  "a module-relative offset outside a relaxed local-dynamic access is not applied");
              break;
            }
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            const auto offset = tp_offset(symbol + static_cast<std::uint64_t>(addend));
            if (!offset || !fits_int32(*offset)) {
              note(Status::Unsupported, "elf.tls_symbol",
                   "a thread-local symbol's offset does not fit; the access is not applied");
              break;
            }
            store(out, file_place, 4, static_cast<std::uint64_t>(*offset) & 0xFFFF'FFFFU, endian);
            break;
          }
          default:
            note(Status::Unsupported, "elf.relocation_type",
                 "x86-64 relocation type " + std::to_string(type) + " is not applied");
            break;
        }
      } else {
        switch (type) {
          case kR_AARCH64_PREL32: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            const std::int64_t value = s + addend - p;
            if (!fits_int32(value)) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a PC-relative value does not fit in 32 bits");
              break;
            }
            store(out, file_place, 4, static_cast<std::uint64_t>(value) & 0xFFFF'FFFFU, endian);
            break;
          }
          case kR_AARCH64_ABS64:
            if (where + 8 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            store(out, file_place, 8, symbol + static_cast<std::uint64_t>(addend), endian);
            break;
          case kR_AARCH64_CALL26:
          case kR_AARCH64_JUMP26: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            const std::int64_t delta = s + addend - p;
            const std::int64_t words = delta / 4;
            if ((delta % 4) != 0 || words < -(std::int64_t{1} << 25) ||
                words >= (std::int64_t{1} << 25)) {
              note(Status::Unsupported, "elf.relocation_range", "a branch target is out of range");
              break;
            }
            const std::uint64_t instruction = load(out, file_place, 4, endian);
            const std::uint64_t patched = (instruction & ~std::uint64_t{0x03FF'FFFFU}) |
                                          (static_cast<std::uint64_t>(words) & 0x03FF'FFFFU);
            store(out, file_place, 4, patched, endian);
            break;
          }
          case kR_AARCH64_ADR_PREL_PG_HI21:
          case kR_AARCH64_ADR_GOT_PAGE:
          case kR_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            // The page of the data (S + A), or of its GOT slot, relative to this ADRP.
            const std::int64_t destination = slot ? static_cast<std::int64_t>(*slot) : s + addend;
            if (!patch_adrp(out, file_place, p, destination, endian)) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a page-relative address does not fit in 21 bits");
            }
            break;
          }
          case kR_AARCH64_ADD_ABS_LO12_NC:
          case kR_AARCH64_LDST8_ABS_LO12_NC:
          case kR_AARCH64_LDST16_ABS_LO12_NC:
          case kR_AARCH64_LDST32_ABS_LO12_NC:
          case kR_AARCH64_LDST64_ABS_LO12_NC:
          case kR_AARCH64_LD64_GOT_LO12_NC:
          case kR_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            // The low 12 bits of the address (S + A, or the GOT slot) go in the instruction's
            // 12-bit immediate. A load or store scales them by its access size. The _NC forms
            // do not check that the offset is aligned.
            const unsigned scale =
                type == kR_AARCH64_LDST16_ABS_LO12_NC   ? 1U
                : type == kR_AARCH64_LDST32_ABS_LO12_NC ? 2U
                : (type == kR_AARCH64_LDST64_ABS_LO12_NC || type == kR_AARCH64_LD64_GOT_LO12_NC ||
                   type == kR_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC)
                    ? 3U
                    : 0U;
            const std::uint64_t address = slot ? *slot : static_cast<std::uint64_t>(s + addend);
            patch_imm12(out, file_place, (address & 0xFFFU) >> scale, endian);
            break;
          }
          case kR_AARCH64_TLSLE_ADD_TPREL_HI12:
          case kR_AARCH64_TLSLE_ADD_TPREL_LO12:
          case kR_AARCH64_TLSLE_ADD_TPREL_LO12_NC: {
            if (where + 4 > target_header.size) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a relocation lies outside its section");
              break;
            }
            const auto offset = tp_offset(symbol + static_cast<std::uint64_t>(addend));
            if (!offset || *offset < 0) {
              note(Status::Unsupported, "elf.tls_symbol",
                   "a thread-local relocation names a symbol that is not thread-local");
              break;
            }
            const auto tp = static_cast<std::uint64_t>(*offset);
            if ((type == kR_AARCH64_TLSLE_ADD_TPREL_HI12 && (tp >> 24U) != 0) ||
                (type == kR_AARCH64_TLSLE_ADD_TPREL_LO12 && (tp >> 12U) != 0)) {
              note(Status::Unsupported, "elf.relocation_range",
                   "a thread-pointer offset does not fit the instruction's immediate");
              break;
            }
            // The high part shifts by 12 (the instruction's lsl #12); the low parts are the
            // offset's low 12 bits.
            patch_imm12(out, file_place, type == kR_AARCH64_TLSLE_ADD_TPREL_HI12 ? (tp >> 12U) : tp,
                        endian);
            break;
          }
          case kR_AARCH64_TLSDESC_ADR_PAGE21: {
            const auto found = desc_tp.find(where);
            if (found == desc_tp.end()) {
              note(Status::Unsupported, "elf.tls_model",
                   "a TLSDESC access is not the sequence GCC or Clang emits for a thread-local "
                   "symbol this object defines; it is not applied");
              break;
            }
            // movz xD, #tp>>16, lsl #16; movk xD, #tp&0xffff; nop; nop: the same words ld writes.
            const auto tp = static_cast<std::uint64_t>(found->second);
            const std::uint64_t reg = load(out, file_place, 4, endian) & 0x1FU;
            store(out, file_place, 4, 0xD2A0'0000U | (((tp >> 16U) & 0xFFFFU) << 5U) | reg, endian);
            store(out, file_place + 4, 4, 0xF280'0000U | ((tp & 0xFFFFU) << 5U) | reg, endian);
            store(out, file_place + 8, 4, 0xD503'201FU, endian);
            store(out, file_place + 12, 4, 0xD503'201FU, endian);
            break;
          }
          case kR_AARCH64_TLSDESC_LD64_LO12:
          case kR_AARCH64_TLSDESC_ADD_LO12:
          case kR_AARCH64_TLSDESC_CALL:
            note(Status::Unsupported, "elf.tls_model",
                 "a TLSDESC access is not the sequence GCC or Clang emits; it is not applied");
            break;
          default:
            note(Status::Unsupported, "elf.relocation_type",
                 "AArch64 relocation type " + std::to_string(type) + " is not applied");
            break;
        }
      }
    }
  }

  for (Diagnostic& diagnostic : diagnostics) {
    image.diagnostics.push_back(std::move(diagnostic));
  }
  return out;
}

}  // namespace donkey
