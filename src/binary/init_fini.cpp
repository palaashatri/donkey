#include "donkey/binary/init_fini.h"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <string_view>

#include "donkey/binary/byte_reader.h"
#include "donkey/core/checked.h"

namespace donkey {

namespace {

constexpr std::uint64_t kDtNull = 0;
constexpr std::uint64_t kDtInit = 12;
constexpr std::uint64_t kDtFini = 13;
constexpr std::uint64_t kDtInitArray = 25;
constexpr std::uint64_t kDtFiniArray = 26;
constexpr std::uint64_t kDtInitArraySize = 27;
constexpr std::uint64_t kDtFiniArraySize = 28;
constexpr std::uint64_t kDtPreinitArray = 32;
constexpr std::uint64_t kDtPreinitArraySize = 33;
constexpr std::size_t kMaxDynamicEntries = 4096;
constexpr std::size_t kMaxRelocations = 1'000'000;

/// R_*_RELATIVE for the image's machine, or 0 when it has none this reader knows.
std::uint64_t relative_type(Architecture architecture) {
  switch (architecture) {
    case Architecture::X86_64:
    case Architecture::X86:
      return 8;  // R_X86_64_RELATIVE, R_386_RELATIVE
    case Architecture::AArch64:
      return 1027;  // R_AARCH64_RELATIVE
    case Architecture::Arm:
      return 23;  // R_ARM_RELATIVE
    default:
      return 0;
  }
}

struct Reader {
  const BinaryImage& image;
  ByteReader bytes;
  unsigned pointer = 8;

  std::optional<std::uint64_t> word_at_file(std::uint64_t offset) const {
    if (pointer == 8) {
      auto value = bytes.u64(offset, image.endian);
      return value ? std::optional<std::uint64_t>(value.value()) : std::nullopt;
    }
    auto value = bytes.u32(offset, image.endian);
    return value ? std::optional<std::uint64_t>(value.value()) : std::nullopt;
  }

  std::optional<std::uint64_t> word_at(std::uint64_t address) const {
    auto offset = image.va_to_file_offset(address);
    if (!offset) {
      return std::nullopt;
    }
    return word_at_file(offset.value());
  }
};

/// The relocations of the dynamic relocation tables that matter for the arrays: for each place,
/// the value a RELATIVE relocation gives it (RELA: the addend; REL: the file's bytes), or nothing
/// when another relocation type (a symbolic one) covers it.
struct Relocations {
  std::map<std::uint64_t, std::optional<std::uint64_t>> places;
  bool truncated = false;
};

Relocations read_relocations(const Reader& reader) {
  Relocations out;
  const std::uint64_t relative = relative_type(reader.image.architecture);
  const bool wide = reader.pointer == 8;
  for (const Section& section : reader.image.sections) {
    const bool rela = section.name == ".rela.dyn";
    const bool rel = section.name == ".rel.dyn";
    if ((!rela && !rel) || !section.has_file_data) {
      continue;
    }
    const std::uint64_t entry_size = (wide ? 8U : 4U) * (rela ? 3U : 2U);
    const std::uint64_t count = section.file_size / entry_size;
    for (std::uint64_t i = 0; i < count; ++i) {
      if (out.places.size() >= kMaxRelocations) {
        out.truncated = true;
        break;
      }
      const std::uint64_t at = section.file_offset + i * entry_size;
      const auto place = reader.word_at_file(at);
      const auto info = reader.word_at_file(at + reader.pointer);
      if (!place || !info) {
        out.truncated = true;
        break;
      }
      const std::uint64_t type = wide ? (*info & 0xffffffffU) : (*info & 0xffU);
      if (relative != 0 && type == relative) {
        if (rela) {
          const auto addend = reader.word_at_file(at + 2U * reader.pointer);
          if (!addend) {
            out.truncated = true;
            break;
          }
          out.places[*place] = *addend;
        } else {
          out.places[*place] = reader.word_at(*place);
        }
      } else if (type != 0) {
        out.places[*place] = std::nullopt;  // symbolic: the value comes from another image
      }
    }
  }
  return out;
}

struct Range {
  std::uint64_t address = 0;
  std::uint64_t size = 0;
};

void read_array(const Reader& reader, const Relocations& relocations, Range range,
                std::set<std::uint64_t>& starts, std::size_t& unreadable) {
  if (range.size == 0) {
    return;
  }
  if (range.size % reader.pointer != 0) {
    ++unreadable;
    return;
  }
  const std::uint64_t count = range.size / reader.pointer;
  if (count > kInitFiniMaxEntries) {
    ++unreadable;
    return;
  }
  for (std::uint64_t i = 0; i < count; ++i) {
    const std::uint64_t place = range.address + i * reader.pointer;
    std::optional<std::uint64_t> value;
    if (const auto it = relocations.places.find(place); it != relocations.places.end()) {
      if (!it->second) {
        continue;  // a symbolic relocation: not a start in this image
      }
      value = it->second;
    } else {
      value = reader.word_at(place);
      if (!value) {
        ++unreadable;
        continue;
      }
    }
    // 0 and -1 are the terminators and placeholders of .ctors-style arrays, not functions.
    const std::uint64_t all_ones = reader.pointer == 8 ? ~std::uint64_t{0} : 0xffffffffU;
    if (*value != 0 && *value != all_ones) {
      starts.insert(*value);
    }
  }
}

}  // namespace

InitFiniStarts read_init_fini_of_image(const BinaryImage& image, std::span<const std::byte> file) {
  InitFiniStarts out;
  if (image.format != BinaryFormat::Elf) {
    return out;
  }
  Reader reader{image, ByteReader(file), image.bits == 32 ? 4U : 8U};
  const Relocations relocations = read_relocations(reader);
  if (relocations.truncated) {
    ++out.unreadable;
  }
  std::set<std::uint64_t> starts;

  // The dynamic tags.
  for (const Section& section : image.sections) {
    if (section.name != ".dynamic" || !section.has_file_data) {
      continue;
    }
    std::map<std::uint64_t, std::uint64_t> tags;
    const std::uint64_t entry_size = 2U * reader.pointer;
    bool ended = false;
    for (std::uint64_t i = 0; i < kMaxDynamicEntries && (i + 1) * entry_size <= section.file_size;
         ++i) {
      const auto tag = reader.word_at_file(section.file_offset + i * entry_size);
      const auto value = reader.word_at_file(section.file_offset + i * entry_size + reader.pointer);
      if (!tag || !value) {
        break;
      }
      if (*tag == kDtNull) {
        ended = true;
        break;
      }
      tags.emplace(*tag, *value);
    }
    if (!ended) {
      ++out.unreadable;  // cut short: a later entry may name another array
    }
    for (const std::uint64_t tag : {kDtInit, kDtFini}) {
      if (const auto it = tags.find(tag); it != tags.end() && it->second != 0) {
        starts.insert(it->second);
      }
    }
    for (const auto& [array, size] :
         {std::pair{kDtInitArray, kDtInitArraySize}, std::pair{kDtFiniArray, kDtFiniArraySize},
          std::pair{kDtPreinitArray, kDtPreinitArraySize}}) {
      const auto at = tags.find(array);
      if (at == tags.end()) {
        continue;
      }
      const auto bytes = tags.find(size);
      if (bytes == tags.end()) {
        ++out.unreadable;  // an array without its size
        continue;
      }
      read_array(reader, relocations, Range{at->second, bytes->second}, starts, out.unreadable);
    }
    break;
  }

  // The sections, which a static image has without a dynamic table.
  for (const Section& section : image.sections) {
    if ((section.name == ".init" || section.name == ".fini") && section.virtual_size != 0) {
      starts.insert(section.address);
    } else if ((section.name == ".init_array" || section.name == ".fini_array" ||
                section.name == ".preinit_array") &&
               section.has_file_data) {
      read_array(reader, relocations, Range{section.address, section.virtual_size}, starts,
                 out.unreadable);
    }
  }
  out.starts.assign(starts.begin(), starts.end());
  return out;
}

}  // namespace donkey
