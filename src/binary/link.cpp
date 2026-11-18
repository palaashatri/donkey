#include "donkey/binary/link.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>

#include "donkey/binary/byte_reader.h"

namespace donkey {
namespace {

constexpr std::uint64_t kDtNull = 0;
constexpr std::uint64_t kDtNeeded = 1;
constexpr std::uint64_t kDtSoname = 14;
constexpr std::uint64_t kDtRpath = 15;
constexpr std::uint64_t kDtRunpath = 29;
constexpr std::size_t kMaxDynamicEntries = 4096;
constexpr std::uint64_t kMaxNameLength = 4096;

std::string lowercase(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return text;
}

/// The last component of a path, with either separator.
std::string file_name_of(const std::string& path) {
  const auto cut = path.find_last_of("/\\");
  return cut == std::string::npos ? path : path.substr(cut + 1);
}

/// The exported symbol of `image` with `name` and a non-zero address, or null.
const Symbol* find_export(const BinaryImage& image, const std::string& name) {
  for (const Symbol& symbol : image.symbols) {
    if (symbol.exported && !symbol.imported && symbol.address != 0 && symbol.name == name) {
      return &symbol;
    }
  }
  return nullptr;
}

/// Whether `provider` is one of the libraries the import `symbol` of `importer` names.
bool names_library(const BinaryImage& importer, const Symbol& symbol,
                   const ElfLibraryNames& importer_names, const BinaryImage& provider,
                   const ElfLibraryNames& provider_names, const std::string& provider_file) {
  if (!symbol.module.empty()) {  // PE: the DLL the import is taken from, by its file name
    return lowercase(symbol.module) == lowercase(provider_file);
  }
  if (importer.format == BinaryFormat::Elf) {  // ELF: DT_NEEDED, against soname or file name
    if (provider.format != BinaryFormat::Elf) {
      return false;
    }
    return std::find(importer_names.needed.begin(), importer_names.needed.end(),
                     provider_names.soname) != importer_names.needed.end() ||
           std::find(importer_names.needed.begin(), importer_names.needed.end(), provider_file) !=
               importer_names.needed.end();
  }
  return true;  // other formats name no library per import: the name alone decides
}

}  // namespace

namespace {

constexpr std::uint64_t kDtStrtab = 5;
constexpr std::uint64_t kDtStrsz = 10;
constexpr std::uint64_t kDtFlags1 = 0x6ffffffb;
constexpr std::uint64_t kDtVersym = 0x6ffffff0;
constexpr std::uint64_t kDtVerdef = 0x6ffffffc;
constexpr std::uint64_t kDtVerneed = 0x6ffffffe;
constexpr std::uint64_t kDf1Nodeflib = 0x800;
constexpr std::uint32_t kPtDynamic = 2;
constexpr std::size_t kMaxProgramHeaders = 65'535;

/// The file range of the PT_DYNAMIC program header, the table the loader reads. `found` stays false
/// when the image has none; `readable` is false when the program headers cannot be read.
struct DynamicRange {
  bool found = false;
  bool readable = true;
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
};

DynamicRange program_dynamic(const BinaryImage& image, const ByteReader& reader) {
  DynamicRange out;
  const bool wide = image.bits == 64;
  const Endian endian = image.endian;
  std::uint64_t phoff = 0;
  if (wide) {
    const auto value = reader.u64(32, endian);
    if (!value) {
      out.readable = false;
      return out;
    }
    phoff = value.value();
  } else {
    const auto value = reader.u32(28, endian);
    if (!value) {
      out.readable = false;
      return out;
    }
    phoff = value.value();
  }
  const auto phentsize = reader.u16(wide ? 54 : 42, endian);
  const auto phnum = reader.u16(wide ? 56 : 44, endian);
  if (!phentsize || !phnum) {
    out.readable = false;
    return out;
  }
  const std::uint64_t entry_size = phentsize.value();
  if (phnum.value() == 0) {
    return out;
  }
  if (entry_size < (wide ? 56U : 32U) || phnum.value() > kMaxProgramHeaders) {
    out.readable = false;
    return out;
  }
  for (std::uint64_t i = 0; i < phnum.value(); ++i) {
    const std::uint64_t at = phoff + i * entry_size;
    const auto type = reader.u32(at, endian);
    if (!type) {
      out.readable = false;
      return out;
    }
    if (type.value() != kPtDynamic) {
      continue;
    }
    if (wide) {
      const auto offset = reader.u64(at + 8, endian);
      const auto size = reader.u64(at + 32, endian);
      if (!offset || !size) {
        out.readable = false;
        return out;
      }
      out.offset = offset.value();
      out.size = size.value();
    } else {
      const auto offset = reader.u32(at + 4, endian);
      const auto size = reader.u32(at + 16, endian);
      if (!offset || !size) {
        out.readable = false;
        return out;
      }
      out.offset = offset.value();
      out.size = size.value();
    }
    out.found = true;
    return out;
  }
  return out;
}

}  // namespace

ElfLibraryNames read_library_names(const BinaryImage& image, std::span<const std::byte> data) {
  ElfLibraryNames names;
  if (image.format != BinaryFormat::Elf) {
    return names;
  }
  const ByteReader reader(data);
  const Endian endian = image.endian;
  // The loader reads PT_DYNAMIC and finds its strings through DT_STRTAB; section names are only a
  // fallback for an image without program headers (a relocatable object reads no libraries).
  const DynamicRange program = program_dynamic(image, reader);
  std::uint64_t table_offset = 0;
  std::uint64_t table_size = 0;
  if (!program.readable) {
    names.complete = false;
    return names;
  }
  bool from_program = false;
  const Section* strings_section = nullptr;
  if (program.found) {
    table_offset = program.offset;
    table_size = program.size;
    from_program = true;
  } else {
    const Section* dynamic = nullptr;
    for (const Section& section : image.sections) {
      if (section.name == ".dynamic") {
        dynamic = &section;
      } else if (section.name == ".dynstr") {
        strings_section = &section;
      }
    }
    if (dynamic == nullptr) {
      return names;  // not dynamically linked: nothing is needed
    }
    if (strings_section == nullptr || !dynamic->has_file_data || !strings_section->has_file_data) {
      names.complete = false;
      return names;
    }
    table_offset = dynamic->file_offset;
    table_size = dynamic->file_size;
  }
  names.dynamic = true;
  const bool wide = image.bits == 64;
  const std::uint64_t entry_size = wide ? 16 : 8;
  struct Entry {
    std::uint64_t tag;
    std::uint64_t value;
  };
  std::vector<Entry> entries;
  bool ended = false;
  for (std::size_t i = 0; i < kMaxDynamicEntries; ++i) {
    if (i * entry_size + entry_size > table_size) {
      break;
    }
    const std::uint64_t at = table_offset + i * entry_size;
    Entry entry{};
    if (wide) {
      const auto t = reader.u64(at, endian);
      const auto v = reader.u64(at + 8, endian);
      if (!t || !v) {
        break;
      }
      entry = {t.value(), v.value()};
    } else {
      const auto t = reader.u32(at, endian);
      const auto v = reader.u32(at + 4, endian);
      if (!t || !v) {
        break;
      }
      entry = {t.value(), v.value()};
    }
    if (entry.tag == kDtNull) {
      ended = true;
      break;
    }
    entries.push_back(entry);
  }
  if (!ended) {
    // Cut short by the file, the table's size or the entry limit: a later entry may name another
    // library or a search directory.
    names.complete = false;
  }
  std::uint64_t strings_offset = 0;
  std::uint64_t strings_size = 0;
  if (from_program) {
    std::optional<std::uint64_t> address;
    for (const Entry& entry : entries) {
      if (entry.tag == kDtStrtab) {
        address = entry.value;
      } else if (entry.tag == kDtStrsz) {
        strings_size = entry.value;
      }
    }
    if (!address) {
      names.complete = false;
      return names;
    }
    const auto offset = image.va_to_file_offset(*address);
    if (!offset) {
      names.complete = false;
      return names;
    }
    strings_offset = offset.value();
  } else {
    strings_offset = strings_section->file_offset;
    strings_size = strings_section->file_size;
  }
  for (const Entry& entry : entries) {
    switch (entry.tag) {
      case kDtFlags1:
        names.nodeflib = (entry.value & kDf1Nodeflib) != 0;
        continue;
      case kDtVersym:
        names.version_symbols = true;
        continue;
      case kDtVerdef:
        names.version_definitions = true;
        continue;
      case kDtVerneed:
        names.version_needs = true;
        continue;
      case kDtNeeded:
      case kDtSoname:
      case kDtRpath:
      case kDtRunpath:
        break;
      default:
        continue;
    }
    std::optional<std::string_view> text;
    if (entry.value < strings_size) {
      const auto read =
          reader.c_string(strings_offset + entry.value,
                          std::min<std::uint64_t>(kMaxNameLength, strings_size - entry.value));
      if (read) {
        text = read.value();
      }
    }
    if (!text) {
      names.complete = false;  // a name the loader would read and this reader cannot
      continue;
    }
    if (entry.tag == kDtSoname) {
      names.soname = std::string(*text);
    } else if (entry.tag == kDtRpath) {
      names.rpath = std::string(*text);
      names.has_rpath = true;
    } else if (entry.tag == kDtRunpath) {
      names.runpath = std::string(*text);
      names.has_runpath = true;
    } else {
      names.needed.emplace_back(*text);
    }
  }
  return names;
}

LinkResult resolve_imports(std::span<const LinkInput> inputs) {
  std::vector<ElfLibraryNames> names(inputs.size());
  std::vector<std::string> file_names(inputs.size());
  for (std::size_t i = 0; i < inputs.size(); ++i) {
    if (inputs[i].image == nullptr) {
      continue;
    }
    names[i] = read_library_names(*inputs[i].image, inputs[i].data);
    file_names[i] = file_name_of(inputs[i].image->path);
  }
  LinkResult result;
  for (std::size_t importer = 0; importer < inputs.size(); ++importer) {
    const BinaryImage* image = inputs[importer].image;
    if (image == nullptr) {
      continue;
    }
    for (const Symbol& symbol : image->symbols) {
      if (!symbol.imported || symbol.name.empty()) {
        continue;
      }
      ImportBinding binding;
      binding.importer = importer;
      binding.name = symbol.name;
      for (std::size_t provider = 0; provider < inputs.size(); ++provider) {
        const BinaryImage* candidate = inputs[provider].image;
        if (provider == importer || candidate == nullptr) {
          continue;
        }
        if (!names_library(*image, symbol, names[importer], *candidate, names[provider],
                           file_names[provider])) {
          continue;
        }
        const Symbol* export_symbol = find_export(*candidate, symbol.name);
        if (export_symbol == nullptr) {
          continue;
        }
        binding.provider = provider;
        binding.address = export_symbol->address;
        binding.library =
            names[provider].soname.empty() ? file_names[provider] : names[provider].soname;
        break;
      }
      if (binding.provider == kUnboundImport) {
        ++result.unbound;
      }
      result.bindings.push_back(std::move(binding));
    }
  }
  return result;
}

}  // namespace donkey
