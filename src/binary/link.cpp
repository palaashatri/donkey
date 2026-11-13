#include "donkey/binary/link.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

#include "donkey/binary/byte_reader.h"

namespace donkey {
namespace {

constexpr std::uint64_t kDtNull = 0;
constexpr std::uint64_t kDtNeeded = 1;
constexpr std::uint64_t kDtSoname = 14;
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

ElfLibraryNames read_library_names(const BinaryImage& image, std::span<const std::byte> data) {
  ElfLibraryNames names;
  if (image.format != BinaryFormat::Elf) {
    return names;
  }
  const Section* dynamic = nullptr;
  const Section* strings = nullptr;
  for (const Section& section : image.sections) {
    if (section.name == ".dynamic") {
      dynamic = &section;
    } else if (section.name == ".dynstr") {
      strings = &section;
    }
  }
  if (dynamic == nullptr || strings == nullptr || !dynamic->has_file_data ||
      !strings->has_file_data) {
    return names;
  }
  const ByteReader reader(data);
  const bool wide = image.bits == 64;
  const std::uint64_t entry_size = wide ? 16 : 8;
  for (std::size_t i = 0; i < kMaxDynamicEntries; ++i) {
    const std::uint64_t at = dynamic->file_offset + i * entry_size;
    if (i * entry_size + entry_size > dynamic->file_size) {
      break;
    }
    std::uint64_t tag = 0;
    std::uint64_t value = 0;
    if (wide) {
      const auto t = reader.u64(at, Endian::Little);
      const auto v = reader.u64(at + 8, Endian::Little);
      if (!t || !v) {
        break;
      }
      tag = t.value();
      value = v.value();
    } else {
      const auto t = reader.u32(at, Endian::Little);
      const auto v = reader.u32(at + 4, Endian::Little);
      if (!t || !v) {
        break;
      }
      tag = t.value();
      value = v.value();
    }
    if (tag == kDtNull) {
      break;
    }
    if (tag != kDtNeeded && tag != kDtSoname) {
      continue;
    }
    const auto text = reader.c_string(strings->file_offset + value, kMaxNameLength);
    if (!text) {
      continue;
    }
    if (tag == kDtSoname) {
      names.soname = std::string(text.value());
    } else {
      names.needed.emplace_back(text.value());
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
