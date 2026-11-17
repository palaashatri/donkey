#include "donkey/binary/elf_versions.h"

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

constexpr std::uint64_t kEntrySize = 16;          // Elf64_Verneed and Elf64_Vernaux
constexpr std::uint64_t kMaxNameLength = 4096;    // longest version or file name read
constexpr std::uint16_t kFirstNeedIndex = 2;      // 0: local, 1: global (unversioned)
constexpr std::uint16_t kHiddenBit = 0x8000;      // VERSYM_HIDDEN, ignored for imports

Result<std::string> name_at(const ByteReader& strings, std::uint32_t offset,
                            std::uint64_t entry) {
  auto text = strings.c_string(offset, kMaxNameLength);
  if (!text) {
    return make_error<std::string>(Status::InvalidInput, "elf.version_needs.name",
                                   "a version need names a string outside .dynstr", entry);
  }
  return std::string(text.value());
}

const Section* section_named(const BinaryImage& image, const char* name) {
  for (const Section& section : image.sections) {
    if (section.name == name && section.has_file_data) {
      return &section;
    }
  }
  return nullptr;
}

}  // namespace

Result<ElfVersionNeeds> read_version_needs(std::span<const std::byte> section,
                                           std::span<const std::byte> strings,
                                           std::size_t max_entries) {
  ElfVersionNeeds needs;
  const ByteReader reader(section);
  const ByteReader names(strings);
  std::set<std::uint64_t> seen;  // offsets of the entries read, so a loop is refused
  std::uint64_t at = 0;
  bool more = !section.empty();
  while (more) {
    if (needs.files + needs.entries >= max_entries) {
      return make_error<ElfVersionNeeds>(Status::ResourceLimit, "elf.version_needs.limit",
                                         "the version needs exceed the entry limit", at);
    }
    if (!seen.insert(at).second) {
      return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.loop",
                                         "the version needs loop back to an entry", at);
    }
    const auto count = reader.u16(at + 2, Endian::Little);
    const auto file_name = reader.u32(at + 4, Endian::Little);
    const auto aux = reader.u32(at + 8, Endian::Little);
    const auto next = reader.u32(at + 12, Endian::Little);
    if (!count || !file_name || !aux || !next) {
      return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.truncated",
                                         "a version need runs past its section", at);
    }
    auto file = name_at(names, file_name.value(), at);
    if (!file) {
      return Result<ElfVersionNeeds>(file.diagnostic());
    }
    ++needs.files;
    std::uint64_t entry = at + aux.value();
    for (std::uint32_t i = 0; i < count.value(); ++i) {
      if (needs.files + needs.entries >= max_entries) {
        return make_error<ElfVersionNeeds>(Status::ResourceLimit, "elf.version_needs.limit",
                                           "the version needs exceed the entry limit", entry);
      }
      if (entry < at || !seen.insert(entry).second) {
        return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.loop",
                                           "a version need's entries loop", entry);
      }
      const auto other = reader.u16(entry + 6, Endian::Little);
      const auto name = reader.u32(entry + 8, Endian::Little);
      const auto entry_next = reader.u32(entry + 12, Endian::Little);
      if (!other || !name || !entry_next || entry + kEntrySize > section.size()) {
        return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.truncated",
                                           "a version need entry runs past its section", entry);
      }
      const auto index = static_cast<std::uint16_t>(other.value() & ~kHiddenBit);
      if (index < kFirstNeedIndex) {
        return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.index",
                                           "a version need uses a reserved index", entry);
      }
      auto version = name_at(names, name.value(), entry);
      if (!version) {
        return Result<ElfVersionNeeds>(version.diagnostic());
      }
      if (!needs.by_index.emplace(index, ElfVersionNeed{file.value(), std::move(version.value())})
               .second) {
        return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.duplicate",
                                           "two version needs use one index", entry);
      }
      ++needs.entries;
      if (entry_next.value() == 0) {
        if (i + 1 != count.value()) {
          return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.count",
                                             "a version need has fewer entries than it says",
                                             entry);
        }
        break;
      }
      entry += entry_next.value();
    }
    more = next.value() != 0;
    at += next.value();
  }
  return needs;
}

Result<std::map<std::string, ElfVersionNeed>> read_import_versions(
    const BinaryImage& image, std::span<const std::byte> data) {
  std::map<std::string, ElfVersionNeed> imports;
  if (image.format != BinaryFormat::Elf || image.bits != 64) {
    return imports;
  }
  const Section* versym = section_named(image, ".gnu.version");
  const Section* verneed = section_named(image, ".gnu.version_r");
  const Section* dynstr = section_named(image, ".dynstr");
  if (versym == nullptr || verneed == nullptr || dynstr == nullptr) {
    return imports;
  }
  const ByteReader file(data);
  auto need_bytes = file.slice(verneed->file_offset, verneed->file_size);
  auto string_bytes = file.slice(dynstr->file_offset, dynstr->file_size);
  if (!need_bytes || !string_bytes) {
    return make_error<std::map<std::string, ElfVersionNeed>>(
        Status::InvalidInput, "elf.version_needs.truncated",
        "the version need or string table lies outside the file", verneed->file_offset);
  }
  auto needs = read_version_needs(need_bytes.value(), string_bytes.value());
  if (!needs) {
    return Result<std::map<std::string, ElfVersionNeed>>(needs.diagnostic());
  }
  std::set<std::string> imported;
  for (const Symbol& symbol : image.symbols) {
    if (symbol.imported) {
      imported.insert(symbol.name);
    }
  }
  const std::vector<std::string> names = binary::detail::dynamic_symbol_names(image, data);
  std::set<std::string> conflicting;
  for (std::size_t index = 0; index < names.size(); ++index) {
    if (imported.count(names[index]) == 0) {
      continue;
    }
    const auto value = file.u16(versym->file_offset + index * 2, Endian::Little);
    if (!value || index * 2 + 2 > versym->file_size) {
      break;
    }
    const auto version = static_cast<std::uint16_t>(value.value() & ~kHiddenBit);
    const auto need = needs.value().by_index.find(version);
    if (version < kFirstNeedIndex || need == needs.value().by_index.end()) {
      continue;
    }
    const auto [it, added] = imports.emplace(names[index], need->second);
    if (!added && (it->second.file != need->second.file ||
                   it->second.version != need->second.version)) {
      conflicting.insert(names[index]);
    }
  }
  for (const std::string& name : conflicting) {
    imports.erase(name);
  }
  return imports;
}

}  // namespace donkey
