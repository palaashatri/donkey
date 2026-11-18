#include "donkey/binary/elf_versions.h"

#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/link.h"
#include "elf_dynamic.h"

namespace donkey {
namespace {

constexpr std::uint64_t kEntrySize = 16;        // Elf64_Verneed and Elf64_Vernaux
constexpr std::uint64_t kMaxNameLength = 4096;  // longest version or file name read
constexpr std::uint16_t kFirstNeedIndex = 2;    // 0: local, 1: global (unversioned)
constexpr std::uint16_t kHiddenBit = 0x8000;    // VERSYM_HIDDEN / VER_NDX hidden flag

Result<std::string> name_at(const ByteReader& strings, std::uint32_t offset, std::uint64_t entry) {
  auto text = strings.c_string(offset, kMaxNameLength);
  if (!text) {
    return make_error<std::string>(Status::InvalidInput, "elf.version_needs.name",
                                   "a version need names a string outside .dynstr", entry);
  }
  return std::string(text.value());
}

/// The 16-byte records read so far, as [start, end) ranges keyed by start. A record that overlaps
/// one already read (the same start, or any byte in common) is refused, so a table cannot loop or
/// make two records share bytes.
class RecordRanges {
 public:
  [[nodiscard]] bool add(std::uint64_t start) {
    const std::uint64_t end = start + kEntrySize;
    const auto after = ranges_.lower_bound(start);
    if (after != ranges_.end() && after->first < end) {
      return false;
    }
    if (after != ranges_.begin() && std::prev(after)->second > start) {
      return false;
    }
    ranges_.emplace(start, end);
    return true;
  }

 private:
  std::map<std::uint64_t, std::uint64_t> ranges_;
};

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
  RecordRanges seen;  // the records read, so a loop or an overlap is refused
  std::uint64_t at = 0;
  bool more = !section.empty();
  while (more) {
    if (needs.files + needs.entries >= max_entries) {
      return make_error<ElfVersionNeeds>(Status::ResourceLimit, "elf.version_needs.limit",
                                         "the version needs exceed the entry limit", at);
    }
    if (!seen.add(at)) {
      return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.loop",
                                         "a version need overlaps or loops back to a record", at);
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
      if (entry < at || !seen.add(entry)) {
        return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.loop",
                                           "a version need's entries overlap or loop", entry);
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
      const bool hidden = (other.value() & kHiddenBit) != 0;
      if (!needs.by_index
               .emplace(index, ElfVersionNeed{file.value(), std::move(version.value()), hidden})
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
      if (i + 1 == count.value()) {
        // The last entry the count allows must end the chain: a link past it points at bytes
        // no entry accounts for.
        return make_error<ElfVersionNeeds>(Status::InvalidInput, "elf.version_needs.count",
                                           "a version need's last entry links to another", entry);
      }
      entry += entry_next.value();
    }
    more = next.value() != 0;
    at += next.value();
  }
  return needs;
}

Result<std::vector<ElfImportReference>> read_import_references(const BinaryImage& image,
                                                               std::span<const std::byte> data) {
  std::vector<ElfImportReference> references;
  if (image.format != BinaryFormat::Elf || image.bits != 64) {
    return references;
  }
  // Each dynamic symbol's own definedness decides whether it is an import: a name can be both
  // defined and imported by different symbols.
  const std::vector<std::string> names = binary::detail::dynamic_symbol_names(image, data);
  const std::vector<bool> undefined = binary::detail::dynamic_symbol_undefined(image, data);
  const Section* versym = section_named(image, ".gnu.version");
  const Section* verneed = section_named(image, ".gnu.version_r");
  const Section* dynstr = section_named(image, ".dynstr");
  const ByteReader file(data);
  ElfVersionNeeds needs;
  // The loader reads versions through DT_VERSYM and DT_VERNEED. When it would read them and the
  // sections are missing, an import's version index cannot be resolved here: it is unresolved,
  // never taken as unversioned.
  const ElfLibraryNames dynamic = read_library_names(image, data);
  const bool symbols_lost = dynamic.version_symbols && versym == nullptr;
  const bool versioned = versym != nullptr;
  if (versioned && verneed != nullptr && dynstr != nullptr) {
    auto need_bytes = file.slice(verneed->file_offset, verneed->file_size);
    auto string_bytes = file.slice(dynstr->file_offset, dynstr->file_size);
    if (!need_bytes || !string_bytes) {
      return make_error<std::vector<ElfImportReference>>(
          Status::InvalidInput, "elf.version_needs.truncated",
          "the version need or string table lies outside the file", verneed->file_offset);
    }
    auto read = read_version_needs(need_bytes.value(), string_bytes.value());
    if (!read) {
      return Result<std::vector<ElfImportReference>>(read.diagnostic());
    }
    needs = std::move(read.value());
  }
  for (std::size_t index = 0; index < names.size(); ++index) {
    if (index >= undefined.size() || !undefined[index] || names[index].empty()) {
      continue;
    }
    ElfImportReference reference;
    reference.name = names[index];
    if (symbols_lost) {
      reference.unresolved = true;
    } else if (versioned) {
      if (index * 2 + 2 > versym->file_size) {
        return make_error<std::vector<ElfImportReference>>(
            Status::InvalidInput, "elf.version_symbols.truncated",
            "the symbol version table ends before an imported symbol's entry", versym->file_offset);
      }
      const auto value = file.u16(versym->file_offset + index * 2, Endian::Little);
      if (!value) {
        return make_error<std::vector<ElfImportReference>>(
            Status::InvalidInput, "elf.version_symbols.truncated",
            "the symbol version table lies outside the file", versym->file_offset);
      }
      const auto version = static_cast<std::uint16_t>(value.value() & ~kHiddenBit);
      if (version >= kFirstNeedIndex) {
        const auto need = needs.by_index.find(version);
        if (need == needs.by_index.end()) {
          reference.unresolved = true;
        } else {
          reference.version = need->second.version;
          reference.file = need->second.file;
          reference.hidden = need->second.hidden;
        }
      }
    }
    references.push_back(std::move(reference));
  }
  return references;
}

Result<std::map<std::string, ElfVersionNeed>> read_import_versions(
    const BinaryImage& image, std::span<const std::byte> data) {
  std::map<std::string, ElfVersionNeed> imports;
  if (image.format != BinaryFormat::Elf || image.bits != 64 ||
      section_named(image, ".gnu.version") == nullptr ||
      section_named(image, ".gnu.version_r") == nullptr ||
      section_named(image, ".dynstr") == nullptr) {
    return imports;
  }
  auto references = read_import_references(image, data);
  if (!references) {
    return Result<std::map<std::string, ElfVersionNeed>>(references.diagnostic());
  }
  std::set<std::string> conflicting;
  for (const ElfImportReference& reference : references.value()) {
    if (reference.version.empty()) {
      // An unversioned (or unresolved) import of a name another import has a version for: which
      // library provides it is not known, so the name carries no version evidence.
      conflicting.insert(reference.name);
      continue;
    }
    const ElfVersionNeed need{reference.file, reference.version};
    const auto [it, added] = imports.emplace(reference.name, need);
    if (!added && (it->second.file != need.file || it->second.version != need.version)) {
      conflicting.insert(reference.name);
    }
  }
  for (const std::string& name : conflicting) {
    imports.erase(name);
  }
  return imports;
}

}  // namespace donkey
