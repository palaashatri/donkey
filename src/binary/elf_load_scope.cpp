#include "donkey/binary/elf_load_scope.h"

#include <algorithm>
#include <deque>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <system_error>
#include <unordered_map>
#include <utility>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/link.h"

namespace donkey {

namespace {

namespace fs = std::filesystem;

constexpr std::uint16_t kHiddenBit = 0x8000;
constexpr std::uint16_t kVersionIndexMask = 0x7fff;
constexpr std::uint16_t kVerFlagBase = 1;
constexpr std::size_t kMaxVersionDefinitions = 65'536;
constexpr std::size_t kMaxDynamicSymbols = std::size_t{1} << 20;
constexpr std::size_t kMaxConfFiles = 256;
constexpr std::uint64_t kMaxNameLength = 4096;

/// One defining entry of a library's dynamic symbol table, with what lookup needs of it.
struct Definition {
  std::uint16_t versym = 1;  ///< 1 (global) when the library has no .gnu.version
};

struct ParsedLibrary {
  BinaryImage image;
  std::vector<std::byte> data;
};

struct LoadedLibrary {
  bool readable = false;
  bool has_versym = false;
  /// Definitions by name (several for a name defined in several versions).
  std::unordered_map<std::string, std::vector<Definition>> definitions;
  /// The version name of each non-base version definition index.
  std::unordered_map<std::uint16_t, std::string> versions;
};

const Section* section_named(const BinaryImage& image, const char* name) {
  for (const Section& section : image.sections) {
    if (section.name == name && section.has_file_data) {
      return &section;
    }
  }
  return nullptr;
}

/// The dynamic definitions and version definitions of a 64-bit little-endian ELF library. A table
/// that cannot be read leaves the library unreadable, so lookups through it are Unknown.
LoadedLibrary read_definitions(const BinaryImage& image, std::span<const std::byte> data) {
  LoadedLibrary out;
  const Section* dynsym = section_named(image, ".dynsym");
  const Section* dynstr = section_named(image, ".dynstr");
  if (dynsym == nullptr || dynstr == nullptr) {
    return out;
  }
  const ByteReader file(data);
  const Section* versym = section_named(image, ".gnu.version");
  const Section* verdef = section_named(image, ".gnu.version_d");
  out.has_versym = versym != nullptr;
  if (verdef != nullptr) {
    // Elf64_Verdef: vd_version, vd_flags, vd_ndx, vd_cnt (u16), vd_hash, vd_aux, vd_next (u32);
    // Elf64_Verdaux: vda_name, vda_next (u32).
    std::uint64_t at = 0;
    std::set<std::uint64_t> seen;
    for (std::size_t count = 0; count < kMaxVersionDefinitions; ++count) {
      if (at + 20 > verdef->file_size || !seen.insert(at).second) {
        return out;
      }
      const auto flags = file.u16(verdef->file_offset + at + 2, Endian::Little);
      const auto index = file.u16(verdef->file_offset + at + 4, Endian::Little);
      const auto aux = file.u32(verdef->file_offset + at + 12, Endian::Little);
      const auto next = file.u32(verdef->file_offset + at + 16, Endian::Little);
      if (!flags || !index || !aux || !next || at + aux.value() + 8 > verdef->file_size) {
        return out;
      }
      const auto name_offset = file.u32(verdef->file_offset + at + aux.value(), Endian::Little);
      if (!name_offset || name_offset.value() >= dynstr->file_size) {
        return out;
      }
      const auto name = file.c_string(dynstr->file_offset + name_offset.value(), kMaxNameLength);
      if (!name) {
        return out;
      }
      if ((flags.value() & kVerFlagBase) == 0) {
        out.versions[index.value()] = std::string(name.value());
      }
      if (next.value() == 0) {
        break;
      }
      at += next.value();
    }
  }
  const std::uint64_t count = dynsym->file_size / 24;
  if (count > kMaxDynamicSymbols) {
    return out;
  }
  for (std::uint64_t index = 1; index < count; ++index) {
    const std::uint64_t entry = dynsym->file_offset + index * 24;
    const auto name_offset = file.u32(entry, Endian::Little);
    const auto info = file.u8(entry + 4);
    const auto other = file.u8(entry + 5);
    const auto shndx = file.u16(entry + 6, Endian::Little);
    if (!name_offset || !info || !other || !shndx) {
      return out;
    }
    const unsigned binding = info.value() >> 4U;
    const unsigned type = info.value() & 0xFU;
    const unsigned visibility = other.value() & 0x3U;
    // Defined, global, weak or unique, visible to other objects, and not a section, file or TLS
    // symbol: the definitions a lookup can return.
    if (shndx.value() == 0 || (binding != 1 && binding != 2 && binding != 10) ||
        (visibility != 0 && visibility != 3) || type == 3 || type == 4 || type == 6) {
      continue;
    }
    if (name_offset.value() >= dynstr->file_size) {
      return out;
    }
    const auto name = file.c_string(dynstr->file_offset + name_offset.value(), kMaxNameLength);
    if (!name) {
      return out;
    }
    Definition definition;
    if (versym != nullptr) {
      if (index * 2 + 2 > versym->file_size) {
        return out;
      }
      const auto value = file.u16(versym->file_offset + index * 2, Endian::Little);
      if (!value) {
        return out;
      }
      definition.versym = value.value();
    }
    out.definitions[std::string(name.value())].push_back(definition);
  }
  out.readable = true;
  return out;
}

std::string multiarch_triplet(Architecture architecture) {
  switch (architecture) {
    case Architecture::X86_64:
      return "x86_64-linux-gnu";
    case Architecture::AArch64:
      return "aarch64-linux-gnu";
    default:
      return std::string();
  }
}

std::vector<std::string> split_paths(const std::string& text) {
  std::vector<std::string> out;
  std::string current;
  for (const char c : text) {
    if (c == ':' || c == ';') {
      if (!current.empty()) {
        out.push_back(current);
      }
      current.clear();
    } else {
      current += c;
    }
  }
  if (!current.empty()) {
    out.push_back(current);
  }
  return out;
}

std::optional<std::vector<std::byte>> read_file(const fs::path& path) {
  std::error_code error;
  if (!fs::is_regular_file(path, error)) {
    return std::nullopt;
  }
  const auto size = fs::file_size(path, error);
  if (error || size > kMaxScopeLibraryBytes) {
    return std::nullopt;
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return std::nullopt;
  }
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (static_cast<std::uint64_t>(in.gcount()) != size) {
    return std::nullopt;
  }
  return bytes;
}

}  // namespace

struct ElfLoadScope::Impl {
  std::vector<ElfScopeLibrary> libraries;
  std::vector<LoadedLibrary> loaded;  // parallel to libraries; [0] is the executable
};

ElfLoadScope::ElfLoadScope() : impl_(std::make_unique<Impl>()) {}
ElfLoadScope::~ElfLoadScope() = default;
ElfLoadScope::ElfLoadScope(ElfLoadScope&&) noexcept = default;
ElfLoadScope& ElfLoadScope::operator=(ElfLoadScope&&) noexcept = default;

const std::vector<ElfScopeLibrary>& ElfLoadScope::libraries() const {
  return impl_->libraries;
}

ElfLoadScope ElfLoadScope::from_images(std::span<const Input> inputs) {
  ElfLoadScope scope;
  for (const Input& input : inputs) {
    ElfScopeLibrary library;
    library.name = input.name;
    LoadedLibrary loaded;
    if (input.image != nullptr) {
      library.path = input.image->path;
      if (input.image->format == BinaryFormat::Elf && input.image->bits == 64) {
        library.soname = read_library_names(*input.image, input.data).soname;
        loaded = read_definitions(*input.image, input.data);
      }
    }
    scope.impl_->libraries.push_back(std::move(library));
    scope.impl_->loaded.push_back(std::move(loaded));
  }
  return scope;
}

ElfLoadScope ElfLoadScope::build(const BinaryImage& image, std::span<const std::byte> data,
                                 const ElfLibrarySearch& search) {
  ElfLoadScope scope;
  Impl& impl = *scope.impl_;
  // The executable is the first object of the global scope.
  ElfScopeLibrary self;
  self.path = image.path;
  impl.libraries.push_back(self);
  impl.loaded.push_back(read_definitions(image, data));
  if (image.format != BinaryFormat::Elf || image.bits != 64) {
    return scope;
  }
  const auto rooted = [&](const std::string& directory) {
    if (search.sysroot.empty() || directory.empty() || directory.front() != '/') {
      return fs::path(directory);
    }
    return fs::path(search.sysroot) / fs::path(directory).relative_path();
  };
  const auto expand_origin = [](std::string directory, const std::string& object_path) {
    const std::string origin = fs::path(object_path).parent_path().string();
    for (const std::string token : {"${ORIGIN}", "$ORIGIN"}) {
      for (std::size_t at = directory.find(token); at != std::string::npos;
           at = directory.find(token)) {
        directory.replace(at, token.size(), origin);
      }
    }
    return directory;
  };
  // The directories of /etc/ld.so.conf (with its `include` lines), under the sysroot.
  std::vector<std::string> conf_directories;
  if (search.system_directories) {
    std::deque<fs::path> pending{rooted("/etc/ld.so.conf")};
    std::size_t files = 0;
    while (!pending.empty() && files < kMaxConfFiles) {
      const fs::path conf = pending.front();
      pending.pop_front();
      ++files;
      std::ifstream in(conf);
      std::string line;
      while (in && std::getline(in, line)) {
        line = line.substr(0, line.find('#'));
        std::istringstream words(line);
        std::string first;
        if (!(words >> first)) {
          continue;
        }
        if (first == "include") {
          std::string pattern;
          while (words >> pattern) {
            // `include /etc/ld.so.conf.d/*.conf`: a directory and a `*.suffix` file pattern.
            const fs::path glob =
                pattern.front() == '/' ? rooted(pattern) : conf.parent_path() / pattern;
            const std::string leaf = glob.filename().string();
            const std::string suffix =
                leaf.size() > 1 && leaf.front() == '*' ? leaf.substr(1) : std::string();
            std::error_code error;
            std::vector<fs::path> matches;
            if (leaf.find('*') == std::string::npos) {
              matches.push_back(glob);
            } else if (fs::is_directory(glob.parent_path(), error)) {
              for (const auto& item : fs::directory_iterator(glob.parent_path(), error)) {
                const std::string file = item.path().filename().string();
                if (file.size() >= suffix.size() &&
                    file.compare(file.size() - suffix.size(), suffix.size(), suffix) == 0) {
                  matches.push_back(item.path());
                }
              }
            }
            std::sort(matches.begin(), matches.end());
            pending.insert(pending.end(), matches.begin(), matches.end());
          }
        } else {
          conf_directories.push_back(first);
        }
      }
    }
  }
  std::vector<std::string> defaults;
  if (search.system_directories) {
    const std::string triplet = multiarch_triplet(image.architecture);
    if (!triplet.empty()) {
      defaults.push_back("/lib/" + triplet);
      defaults.push_back("/usr/lib/" + triplet);
    }
    for (const char* directory : {"/lib64", "/usr/lib64", "/lib", "/usr/lib"}) {
      defaults.emplace_back(directory);
    }
  }
  const ElfLibraryNames own = read_library_names(image, data);
  // Finds `name` as the object `requester` (with its names) asks for it.
  const auto find = [&](const std::string& name, const ElfLibraryNames& requester,
                        const std::string& requester_path,
                        std::optional<ParsedLibrary>& found) -> std::string {
    std::vector<fs::path> candidates;
    if (name.find('/') != std::string::npos) {
      if (name.front() == '/') {
        candidates.push_back(rooted(name));
      }
    } else {
      std::vector<fs::path> directories;
      if (!requester.has_runpath) {
        for (const std::string& d : split_paths(requester.rpath)) {
          directories.push_back(rooted(expand_origin(d, requester_path)));
        }
        if (!own.has_runpath && &requester != &own) {
          for (const std::string& d : split_paths(own.rpath)) {
            directories.push_back(rooted(expand_origin(d, image.path)));
          }
        }
      }
      for (const std::string& d : search.paths) {
        directories.emplace_back(d);  // a directory of this machine, not under the sysroot
      }
      for (const std::string& d : split_paths(requester.runpath)) {
        directories.push_back(rooted(expand_origin(d, requester_path)));
      }
      for (const std::string& d : conf_directories) {
        directories.push_back(rooted(d));
      }
      for (const std::string& d : defaults) {
        directories.push_back(rooted(d));
      }
      for (const fs::path& directory : directories) {
        candidates.push_back(directory / name);
      }
    }
    for (const fs::path& candidate : candidates) {
      auto bytes = read_file(candidate);
      if (!bytes) {
        continue;
      }
      auto parsed = parse_binary(*bytes, candidate.string());
      if (!parsed || parsed.value().format != BinaryFormat::Elf ||
          parsed.value().architecture != image.architecture || parsed.value().bits != image.bits) {
        continue;  // another class or machine: the loader goes on looking
      }
      found = ParsedLibrary{std::move(parsed.value()), std::move(*bytes)};
      return candidate.string();
    }
    return std::string();
  };
  // Breadth first, each soname once: ld.so.preload, then the executable's DT_NEEDED, then theirs.
  struct Pending {
    std::string name;
    ElfLibraryNames requester;
    std::string requester_path;
    bool preloaded = false;
  };
  std::deque<Pending> queue;
  if (search.system_directories) {
    std::ifstream preload(rooted("/etc/ld.so.preload"));
    std::string word;
    while (preload && preload >> word) {
      queue.push_back({word, own, image.path, true});
    }
  }
  for (const std::string& name : own.needed) {
    queue.push_back({name, own, image.path, false});
  }
  std::set<std::string> seen;
  while (!queue.empty() && impl.libraries.size() <= kMaxScopeLibraries) {
    Pending next = std::move(queue.front());
    queue.pop_front();
    if (!seen.insert(next.name).second) {
      continue;
    }
    ElfScopeLibrary library;
    library.name = next.name;
    library.preloaded = next.preloaded;
    std::optional<ParsedLibrary> found;
    library.path = find(next.name, next.requester, next.requester_path, found);
    LoadedLibrary loaded;
    if (found.has_value()) {
      const ElfLibraryNames names = read_library_names(found->image, found->data);
      library.soname = names.soname;
      if (!names.soname.empty()) {
        seen.insert(names.soname);
      }
      loaded = read_definitions(found->image, found->data);
      for (const std::string& needed : names.needed) {
        queue.push_back({needed, names, library.path, false});
      }
    }
    impl.libraries.push_back(std::move(library));
    impl.loaded.push_back(std::move(loaded));
  }
  if (!queue.empty()) {
    // More libraries than the limit: what follows is not known.
    ElfScopeLibrary rest;
    rest.name = "(more libraries than the limit)";
    impl.libraries.push_back(rest);
    impl.loaded.emplace_back();
  }
  return scope;
}

ElfBinding ElfLoadScope::lookup(const std::string& name, const std::string& version) const {
  ElfBinding out;
  for (std::size_t index = 0; index < impl_->libraries.size(); ++index) {
    const LoadedLibrary& loaded = impl_->loaded[index];
    if (!loaded.readable) {
      if (index == 0) {
        continue;  // an executable without a dynamic symbol table defines nothing for others
      }
      out.outcome = ElfBinding::Outcome::Unknown;
      out.reason = impl_->libraries[index].path.empty()
                       ? impl_->libraries[index].name + " was not found"
                       : impl_->libraries[index].path + " could not be read";
      return out;
    }
    const auto found = loaded.definitions.find(name);
    if (found == loaded.definitions.end()) {
      continue;
    }
    bool accepted = false;
    std::size_t visible_versioned = 0;
    for (const Definition& definition : found->second) {
      const std::uint16_t index_bits = definition.versym & kVersionIndexMask;
      const bool hidden = (definition.versym & kHiddenBit) != 0;
      if (!loaded.has_versym) {
        accepted = true;
        break;
      }
      const auto named = loaded.versions.find(index_bits);
      if (!version.empty()) {
        // glibc check_match, versioned reference: the same version, or a definition whose index
        // has no version of its own (0 or 1, or the base) and that is not hidden.
        if (named != loaded.versions.end() ? named->second == version : !hidden) {
          accepted = true;
          break;
        }
      } else {
        // Unversioned reference: an index below 3, or else the only non-hidden versioned one.
        if (index_bits < 3) {
          accepted = true;
          break;
        }
        if (!hidden) {
          ++visible_versioned;
        }
      }
    }
    if (accepted || (version.empty() && visible_versioned == 1)) {
      out.outcome = ElfBinding::Outcome::Bound;
      out.library = index;
      return out;
    }
  }
  out.outcome = ElfBinding::Outcome::NotDefined;
  return out;
}

}  // namespace donkey
