#include "donkey/binary/elf_load_scope.h"

#include <algorithm>
#include <deque>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
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
constexpr std::uint64_t kMaxNameLength = 4096;
constexpr std::size_t kMaxSymlinkHops = 40;  // glibc's and Linux's MAXSYMLINKS
constexpr std::uint64_t kMaxPreloadBytes = std::uint64_t{1} << 20;
constexpr std::size_t kMaxHwcapsDirectories = 256;
constexpr std::size_t kMaxLegacyDepth = 3;
constexpr std::size_t kMaxCacheEntries = std::size_t{1} << 20;

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
  /// Why a lookup cannot go past this library, when it is not readable.
  std::string problem = "could not be read";
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
/// that cannot be read, or that the dynamic table names and the sections do not hold, leaves the
/// library unreadable, so lookups through it are Unknown.
LoadedLibrary read_definitions(const BinaryImage& image, std::span<const std::byte> data,
                               const ElfLibraryNames& names) {
  LoadedLibrary out;
  if (!names.complete) {
    out.problem = "its dynamic table could not be read in full";
    return out;
  }
  const Section* dynsym = section_named(image, ".dynsym");
  const Section* dynstr = section_named(image, ".dynstr");
  if (dynsym == nullptr || dynstr == nullptr) {
    out.problem = "its dynamic symbol table could not be found";
    return out;
  }
  const ByteReader file(data);
  const Section* versym = section_named(image, ".gnu.version");
  const Section* verdef = section_named(image, ".gnu.version_d");
  if ((names.version_symbols && versym == nullptr) ||
      (names.version_definitions && verdef == nullptr)) {
    out.problem = "its symbol versions could not be found";
    return out;
  }
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

/// e_machine of the architectures a scope is built for; 0 for others.
std::uint16_t elf_machine(Architecture architecture) {
  switch (architecture) {
    case Architecture::X86_64:
      return 62;
    case Architecture::AArch64:
      return 183;
    default:
      return 0;
  }
}

/// glibc's _DL_CACHE_DEFAULT_ID: FLAG_ELF_LIBC6 with the machine's 64-bit library flag.
std::int32_t cache_id(Architecture architecture) {
  switch (architecture) {
    case Architecture::X86_64:
      return 0x0303;
    case Architecture::AArch64:
      return 0x0a03;
    default:
      return -1;
  }
}

/// DT_RPATH and DT_RUNPATH split as the loader splits them: on `:` only, an empty entry kept (the
/// loader reads it as its working directory). A wholly empty string names no directory.
std::vector<std::string> split_search_path(const std::string& text) {
  std::vector<std::string> out;
  if (text.empty()) {
    return out;
  }
  std::string current;
  for (const char c : text) {
    if (c == ':') {
      out.push_back(current);
      current.clear();
    } else {
      current += c;
    }
  }
  out.push_back(current);
  return out;
}

/// A path as the loader of the target sees it (`host` false: absolute, under the sysroot) or a path
/// of this machine (`host` true).
struct LoaderPath {
  bool host = false;
  std::string path;
};

/// A search directory, or the reason no search can be proven past it.
struct SearchStep {
  enum class Kind : std::uint8_t { Directory, Unknowable, Cache, Defaults };
  Kind kind = Kind::Directory;
  LoaderPath directory;
  std::string reason;
};

bool identifier_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/// The length of the dynamic string token `name` at `at` (`$NAME` or `${NAME}`), or 0.
std::size_t token_at(const std::string& text, std::size_t at, const std::string& name) {
  if (text.compare(at, 1, "$") != 0) {
    return 0;
  }
  if (text.compare(at + 1, name.size() + 2, "{" + name + "}") == 0) {
    return name.size() + 3;
  }
  if (text.compare(at + 1, name.size(), name) == 0 &&
      (at + 1 + name.size() >= text.size() || !identifier_char(text[at + 1 + name.size()]))) {
    return name.size() + 1;
  }
  return 0;
}

/// Expands the dynamic string tokens of a search directory or DT_NEEDED path `text` of an object
/// whose directory is `origin`. Each token of the original text expands once (the inserted text is
/// not scanned again). Returns the reason it cannot be resolved instead: a working-directory path,
/// `$LIB` or `$PLATFORM` (their values belong to the target's loader), or `$ORIGIN` anywhere but at
/// the start.
std::optional<LoaderPath> expand_tokens(const std::string& text, const LoaderPath& origin,
                                        std::string& reason) {
  if (text.empty()) {
    reason = "an empty search directory, which the loader takes as its working directory";
    return std::nullopt;
  }
  std::string out;
  bool origin_first = false;
  for (std::size_t at = 0; at < text.size();) {
    if (const std::size_t length = token_at(text, at, "ORIGIN"); length != 0) {
      if (at != 0) {
        reason = "'" + text + "' uses $ORIGIN after the start of the path";
        return std::nullopt;
      }
      origin_first = true;
      out += origin.path;
      at += length;
      continue;
    }
    if (token_at(text, at, "LIB") != 0 || token_at(text, at, "PLATFORM") != 0) {
      reason = "'" + text + "' uses $LIB or $PLATFORM, whose values belong to the target's loader";
      return std::nullopt;
    }
    out += text[at];
    ++at;
  }
  if (origin_first) {
    return LoaderPath{origin.host, out};
  }
  if (out.front() != '/') {
    reason = "'" + text + "' is relative to the loader's working directory";
    return std::nullopt;
  }
  return LoaderPath{false, out};
}

/// A file looked for: found (at `host`), absent (the loader goes on), or not known.
struct Resolved {
  enum class State : std::uint8_t { Found, Missing, Unknown };
  State state = State::Missing;
  fs::path host;
  std::string reason;
};

std::vector<std::string> path_components(const std::string& path) {
  std::vector<std::string> out;
  std::string current;
  for (const char c : path) {
    if (c == '/') {
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

/// The file of this machine that the target path `location` names: under the sysroot each
/// symbolic link is followed inside the sysroot (an absolute target restarts at the sysroot), so a
/// link cannot reach a file of this machine. A path of this machine is used as it is.
Resolved resolve(const LoaderPath& location, const std::string& sysroot) {
  Resolved out;
  if (location.host || sysroot.empty()) {
    std::error_code error;
    const fs::path path(location.path);
    const fs::file_status status = fs::status(path, error);
    if (status.type() == fs::file_type::not_found) {
      return out;
    }
    if (error) {
      out.state = Resolved::State::Unknown;
      out.reason = location.path + " could not be examined";
      return out;
    }
    out.state = Resolved::State::Found;
    out.host = path;
    return out;
  }
  const fs::path root(sysroot);
  std::deque<std::string> todo;
  for (std::string& part : path_components(location.path)) {
    todo.push_back(std::move(part));
  }
  std::vector<std::string> done;
  std::size_t hops = 0;
  while (!todo.empty()) {
    const std::string part = todo.front();
    todo.pop_front();
    if (part == ".") {
      continue;
    }
    if (part == "..") {
      if (!done.empty()) {
        done.pop_back();  // `..` at the root stays at the root, as in the target
      }
      continue;
    }
    fs::path host = root;
    for (const std::string& item : done) {
      host /= item;
    }
    host /= part;
    std::error_code error;
    const fs::file_status status = fs::symlink_status(host, error);
    if (status.type() == fs::file_type::not_found) {
      return out;
    }
    if (error) {
      out.state = Resolved::State::Unknown;
      out.reason = host.generic_string() + " could not be examined";
      return out;
    }
    if (status.type() != fs::file_type::symlink) {
      done.push_back(part);
      continue;
    }
    if (++hops > kMaxSymlinkHops) {
      out.state = Resolved::State::Unknown;
      out.reason = location.path + " passes through too many symbolic links";
      return out;
    }
    const fs::path target = fs::read_symlink(host, error);
    if (error) {
      out.state = Resolved::State::Unknown;
      out.reason = host.generic_string() + " is a link that could not be read";
      return out;
    }
    const std::string text = target.generic_string();
    if (!text.empty() && text.front() == '/') {
      done.clear();
    }
    std::vector<std::string> parts = path_components(text);
    todo.insert(todo.begin(), parts.begin(), parts.end());
  }
  fs::path host = root;
  for (const std::string& item : done) {
    host /= item;
  }
  out.state = Resolved::State::Found;
  out.host = host;
  return out;
}

/// The path of this machine a location is reported as: under the sysroot as spelled, `/` between.
std::string spelled(const LoaderPath& location, const std::string& sysroot) {
  if (location.host || sysroot.empty()) {
    return fs::path(location.path).generic_string();
  }
  return (fs::path(sysroot) / fs::path(location.path).relative_path()).generic_string();
}

/// A file read whole, refused, or absent.
struct FileBytes {
  enum class State : std::uint8_t { Read, Missing, Refused };
  State state = State::Missing;
  std::vector<std::byte> bytes;
};

FileBytes read_file(const fs::path& path, std::uint64_t limit) {
  FileBytes out;
  std::error_code error;
  if (!fs::is_regular_file(path, error)) {
    return out;  // absent, or a directory or device the loader cannot map either
  }
  out.state = FileBytes::State::Refused;
  const auto size = fs::file_size(path, error);
  if (error || size > limit) {
    return out;
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return out;
  }
  out.bytes.resize(static_cast<std::size_t>(size));
  in.read(reinterpret_cast<char*>(out.bytes.data()), static_cast<std::streamsize>(size));
  if (static_cast<std::uint64_t>(in.gcount()) != size) {
    out.bytes.clear();
    return out;
  }
  out.state = FileBytes::State::Read;
  return out;
}

/// Whether the loader would take a file with this ELF header for `image`'s class, byte order,
/// machine and OS ABI (glibc's open_verify skips any other file and goes on searching).
bool header_matches(std::span<const std::byte> bytes, const BinaryImage& image) {
  constexpr std::size_t kHeader = 64;
  if (bytes.size() < kHeader) {
    return false;
  }
  const auto u8 = [&](std::size_t at) { return static_cast<unsigned>(bytes[at]); };
  if (u8(0) != 0x7f || u8(1) != 'E' || u8(2) != 'L' || u8(3) != 'F') {
    return false;
  }
  const unsigned elf_class = image.bits == 64 ? 2U : 1U;
  const unsigned data = image.endian == Endian::Little ? 1U : 2U;
  const unsigned os_abi = u8(7);
  const unsigned machine =
      image.endian == Endian::Little ? u8(18) | (u8(19) << 8U) : (u8(18) << 8U) | u8(19);
  return u8(4) == elf_class && u8(5) == data && (os_abi == 0 || os_abi == 3) &&
         machine == elf_machine(image.architecture);
}

/// A candidate file looked at: the loader takes it, skips it, or this reader cannot tell.
struct Probe {
  enum class State : std::uint8_t { Taken, Skipped, Unknown };
  State state = State::Skipped;
  std::optional<ParsedLibrary> library;
  std::string reason;
};

Probe probe(const fs::path& host, const BinaryImage& image) {
  Probe out;
  FileBytes file = read_file(host, kMaxScopeLibraryBytes);
  if (file.state == FileBytes::State::Missing) {
    return out;
  }
  if (file.state == FileBytes::State::Refused) {
    out.state = Probe::State::Unknown;
    out.reason = host.generic_string() + " could not be read";
    return out;
  }
  if (!header_matches(file.bytes, image)) {
    return out;  // another class, byte order or machine: the loader goes on looking
  }
  auto parsed = parse_binary(file.bytes, host.generic_string());
  if (!parsed || parsed.value().format != BinaryFormat::Elf ||
      parsed.value().architecture != image.architecture || parsed.value().bits != image.bits) {
    // The loader would take this file; this reader cannot.
    out.state = Probe::State::Unknown;
    out.reason = host.generic_string() + " could not be parsed";
    return out;
  }
  out.state = Probe::State::Taken;
  out.library = ParsedLibrary{std::move(parsed.value()), std::move(file.bytes)};
  return out;
}

/// The legacy hardware-capability subdirectories glibc before 2.37 searched before a directory
/// (`tls`, the platform and the important capability names of x86-64 and AArch64).
constexpr const char* kLegacyHwcaps[] = {"tls",  "x86_64", "haswell", "xeon_phi", "avx512_1",
                                         "sse2", "i686",   "i586",    "aarch64"};

LoaderPath joined(const LoaderPath& directory, const std::string& part) {
  return LoaderPath{directory.host,
                    directory.path + (directory.path.ends_with('/') ? "" : "/") + part};
}

/// Whether the loader could open `path`, resolved as every target path is (links followed inside
/// the sysroot): empty when it is absent, else why it may be taken.
std::string may_exist(const LoaderPath& path, const std::string& sysroot) {
  const Resolved where = resolve(path, sysroot);
  switch (where.state) {
    case Resolved::State::Missing:
      return std::string();
    case Resolved::State::Unknown:
      return where.reason;
    case Resolved::State::Found:
      break;
  }
  return spelled(path, sysroot) + " may be chosen instead, depending on the target's processor";
}

/// The directory `path` names, resolved inside the sysroot, if it is one.
std::optional<fs::path> directory_at(const LoaderPath& path, const std::string& sysroot) {
  const Resolved where = resolve(path, sysroot);
  std::error_code error;
  if (where.state != Resolved::State::Found || !fs::is_directory(where.host, error)) {
    return std::nullopt;
  }
  return where.host;
}

std::string legacy_override(const LoaderPath& directory, const std::string& name,
                            const std::string& sysroot, std::size_t depth) {
  if (depth == kMaxLegacyDepth) {
    return std::string();
  }
  for (const char* sub : kLegacyHwcaps) {
    const LoaderPath inner = joined(directory, sub);
    if (!directory_at(inner, sysroot)) {
      continue;
    }
    if (std::string why = may_exist(joined(inner, name), sysroot); !why.empty()) {
      return why;
    }
    if (std::string why = legacy_override(inner, name, sysroot, depth + 1); !why.empty()) {
      return why;
    }
  }
  return std::string();
}

/// Why a copy of `name` that the loader tries before `directory` itself might be taken instead, or
/// empty: a `glibc-hwcaps/<level>` subdirectory or a legacy capability subdirectory holding it.
/// Which of them the loader takes depends on the target's processor, which is not known. Every
/// path is resolved as the library's own is, so a link under a sysroot is followed inside it.
std::string hardware_override(const LoaderPath& directory, const std::string& name,
                              const std::string& sysroot) {
  const LoaderPath hwcaps = joined(directory, "glibc-hwcaps");
  if (const auto listed = directory_at(hwcaps, sysroot)) {
    std::error_code error;
    fs::directory_iterator it(*listed, error);
    std::size_t count = 0;
    for (; !error && it != fs::directory_iterator(); it.increment(error)) {
      if (++count > kMaxHwcapsDirectories) {
        return spelled(hwcaps, sysroot) + " has too many entries to examine";
      }
      const LoaderPath level = joined(hwcaps, it->path().filename().string());
      if (std::string why = may_exist(joined(level, name), sysroot); !why.empty()) {
        return why;
      }
    }
    if (error) {
      return spelled(hwcaps, sysroot) + " could not be listed";
    }
  }
  return legacy_override(directory, name, sysroot, 0);
}

/// glibc's ld.so.cache of the target, as the search uses it.
struct LoaderCache {
  enum class State : std::uint8_t { Absent, Read, Refused };
  State state = State::Absent;
  std::string reason;
  std::vector<ElfLoaderCacheEntry> entries;
};

}  // namespace

Result<std::vector<ElfLoaderCacheEntry>> read_loader_cache(std::span<const std::byte> bytes) {
  using Entries = std::vector<ElfLoaderCacheEntry>;
  const ByteReader reader(bytes);
  constexpr std::string_view kOldMagic = "ld.so-1.7.0";
  constexpr std::string_view kNewMagic = "glibc-ld.so.cache1.1";
  constexpr std::uint64_t kNewHeader = 48;
  constexpr std::uint64_t kNewEntry = 24;
  constexpr std::uint64_t kOldEntry = 12;
  const auto starts = [&](std::uint64_t at, std::string_view text) {
    if (at > bytes.size() || bytes.size() - at < text.size()) {
      return false;
    }
    for (std::size_t i = 0; i < text.size(); ++i) {
      if (static_cast<char>(bytes[at + i]) != text[i]) {
        return false;
      }
    }
    return true;
  };
  std::uint64_t base = 0;
  if (starts(0, kOldMagic)) {
    // struct cache_file: the magic, nlibs at 12, then 12-byte entries; the new table follows,
    // aligned to 8.
    const auto old_count = reader.u32(12, Endian::Little);
    if (!old_count || old_count.value() > kMaxCacheEntries) {
      return make_error<Entries>(Status::InvalidInput, "ld_cache.truncated",
                                 "the old ld.so.cache table is cut short", 12);
    }
    base = (16 + old_count.value() * kOldEntry + 7) & ~std::uint64_t{7};
  }
  if (!starts(base, kNewMagic)) {
    return make_error<Entries>(Status::Unsupported, "ld_cache.format",
                               "not a glibc-ld.so.cache1.1 file", base);
  }
  const auto count = reader.u32(base + 20, Endian::Little);
  const auto flags = reader.u8(base + 28);
  if (!count || !flags) {
    return make_error<Entries>(Status::InvalidInput, "ld_cache.truncated",
                               "the ld.so.cache header is cut short", base);
  }
  if (flags.value() != 0 && flags.value() != 2) {
    return make_error<Entries>(Status::Unsupported, "ld_cache.endian",
                               "the ld.so.cache is not little-endian", base + 28);
  }
  if (count.value() > kMaxCacheEntries ||
      base + kNewHeader + count.value() * kNewEntry > bytes.size()) {
    return make_error<Entries>(Status::InvalidInput, "ld_cache.truncated",
                               "the ld.so.cache entries run past the file", base);
  }
  Entries entries;
  entries.reserve(count.value());
  for (std::uint64_t i = 0; i < count.value(); ++i) {
    const std::uint64_t at = base + kNewHeader + i * kNewEntry;
    const auto entry_flags = reader.u32(at, Endian::Little);
    const auto key = reader.u32(at + 4, Endian::Little);
    const auto value = reader.u32(at + 8, Endian::Little);
    const auto hwcap = reader.u64(at + 16, Endian::Little);
    if (!entry_flags || !key || !value || !hwcap) {
      return make_error<Entries>(Status::InvalidInput, "ld_cache.truncated",
                                 "an ld.so.cache entry runs past the file", at);
    }
    const auto name = reader.c_string(base + key.value(), kMaxNameLength);
    const auto path = reader.c_string(base + value.value(), kMaxNameLength);
    if (!name || !path) {
      return make_error<Entries>(Status::InvalidInput, "ld_cache.name",
                                 "an ld.so.cache entry names a string outside the file", at);
    }
    entries.push_back(ElfLoaderCacheEntry{std::string(name.value()), std::string(path.value()),
                                          static_cast<std::int32_t>(entry_flags.value()),
                                          hwcap.value()});
  }
  return entries;
}

struct ElfLoadScope::Impl {
  std::vector<ElfScopeLibrary> libraries;
  std::vector<LoadedLibrary> loaded;  // parallel to libraries; [0] is the executable
  bool executable_dynamic = true;     // false: the executable defines nothing for others
  std::size_t image_index = 0;        // where the image the scope was built for is
  bool image_first = false;           // DT_SYMBOLIC: the image is looked up before the scope
  // What a walk leaves for a later one (a shared library's local scope): every name, soname and
  // file it loaded, the executable's DT_RPATH (empty when it has DT_RUNPATH) with its $ORIGIN, and
  // whether another object has a DT_RPATH it could pass on to a library it loads.
  std::set<std::string> seen;
  std::string executable_rpath;
  LoaderPath executable_origin;
  bool other_rpath = false;
};

/// What the program's global scope passes on to a shared library's local scope.
struct ElfLoadScope::Inherited {
  std::size_t max_libraries = 0;  // what is left of the shared budget
  std::set<std::string> loaded;   // names, sonames and files already loaded
  std::string executable_rpath;
  LoaderPath executable_origin;
  bool unknown_rpath = false;  // the object that calls dlopen may pass on a DT_RPATH
};

ElfLoadScope::ElfLoadScope() : impl_(std::make_unique<Impl>()) {}
ElfLoadScope::~ElfLoadScope() = default;
ElfLoadScope::ElfLoadScope(ElfLoadScope&&) noexcept = default;
ElfLoadScope& ElfLoadScope::operator=(ElfLoadScope&&) noexcept = default;

const std::vector<ElfScopeLibrary>& ElfLoadScope::libraries() const {
  return impl_->libraries;
}

std::size_t ElfLoadScope::image_index() const {
  return impl_->image_index;
}

ElfLoadScope ElfLoadScope::from_images(std::span<const Input> inputs) {
  ElfLoadScope scope;
  for (std::size_t i = 0; i < inputs.size(); ++i) {
    const Input& input = inputs[i];
    ElfScopeLibrary library;
    library.name = input.name;
    LoadedLibrary loaded;
    loaded.problem = input.name + " was not found";
    if (input.image != nullptr) {
      library.path = fs::path(input.image->path).generic_string();
      loaded.problem = library.path + " could not be read";
      if (input.image->format == BinaryFormat::Elf && input.image->bits == 64) {
        const ElfLibraryNames names = read_library_names(*input.image, input.data);
        library.soname = names.soname;
        loaded = read_definitions(*input.image, input.data, names);
        if (i == 0) {
          scope.impl_->executable_dynamic = names.dynamic || !names.complete;
        }
      }
    } else if (i == 0) {
      scope.impl_->executable_dynamic = false;
    }
    scope.impl_->libraries.push_back(std::move(library));
    scope.impl_->loaded.push_back(std::move(loaded));
  }
  return scope;
}

namespace {

constexpr std::uint16_t kEtDyn = 3;

/// The ELF header's e_type, or 0 when the header cannot be read.
std::uint16_t elf_type(const BinaryImage& image, std::span<const std::byte> data) {
  if (data.size() < 18) {
    return 0;
  }
  const auto lo = std::to_integer<std::uint16_t>(data[16]);
  const auto hi = std::to_integer<std::uint16_t>(data[17]);
  return image.endian == Endian::Big ? static_cast<std::uint16_t>((lo << 8) | hi)
                                     : static_cast<std::uint16_t>((hi << 8) | lo);
}

/// A shared library: ET_DYN without DF_1_PIE. Its references bind in the scope of the program that
/// loads it.
bool is_shared_library(const BinaryImage& image, std::span<const std::byte> data,
                       const ElfLibraryNames& names) {
  return elf_type(image, data) == kEtDyn && !names.pie;
}

}  // namespace

ElfLoadScope ElfLoadScope::build(const BinaryImage& image, std::span<const std::byte> data,
                                 const ElfLibrarySearch& search) {
  const ElfLibraryNames own = read_library_names(image, data);
  // The program is named, not inferred: an image that is its own `program` is analysed as the
  // program, whatever its flags (a position-independent executable linked before DF_1_PIE has
  // none). Only an unnamed ET_DYN without DF_1_PIE is taken for a shared library.
  bool own_program = search.program_image == &image;
  if (!own_program && !search.program.empty() && !image.path.empty()) {
    std::error_code error;
    own_program = fs::equivalent(fs::path(search.program), fs::path(image.path), error) && !error;
  }
  if (image.format != BinaryFormat::Elf || image.bits != 64 || own_program ||
      !is_shared_library(image, data, own)) {
    return build_root(image, data, search, nullptr);
  }
  // A shared library: the program's global scope, then the library's local scope.
  ElfLoadScope scope;
  Impl& impl = *scope.impl_;
  const auto unknown_program = [&](std::string problem) {
    ElfScopeLibrary program;
    program.name = "(the program that loads this library)";
    program.path = search.program;
    LoadedLibrary loaded;
    loaded.problem = std::move(problem);
    impl.libraries.push_back(std::move(program));
    impl.loaded.push_back(std::move(loaded));
    ElfScopeLibrary self;
    self.path = fs::path(image.path).generic_string();
    impl.libraries.push_back(std::move(self));
    impl.loaded.emplace_back();
    impl.image_index = 1;
    return std::move(scope);
  };
  if (search.program.empty()) {
    return unknown_program(
        "a shared library's references bind first in the scope of the program that loads it, "
        "and no program was given");
  }
  if (std::min(search.library_limit, kMaxScopeLibraries) == 0) {
    // No room even for the program: it is not opened.
    return unknown_program("the scope has more libraries than the limit");
  }
  // The program: the image the caller already holds, or the file `program` names.
  FileBytes file;
  std::optional<BinaryImage> parsed_program;
  const BinaryImage* program = search.program_image;
  std::span<const std::byte> program_data = search.program_data;
  if (program == nullptr) {
    file = read_file(fs::path(search.program), kMaxScopeLibraryBytes);
    if (file.state != FileBytes::State::Read) {
      return unknown_program(search.program + " could not be read");
    }
    auto parsed = parse_binary(file.bytes, search.program);
    if (!parsed) {
      return unknown_program(search.program + " is not an ELF program of the library's machine");
    }
    parsed_program = std::move(parsed.value());
    program = &*parsed_program;
    program_data = file.bytes;
  }
  if (program->format != BinaryFormat::Elf || program->architecture != image.architecture ||
      program->bits != image.bits) {
    return unknown_program(search.program + " is not an ELF program of the library's machine");
  }
  // The program is what the caller names: glibc runs an ET_DYN without DF_1_PIE as a program too
  // (an executable linked before the flag existed, or `ld.so lib.so`), so its flags are not
  // checked.
  ElfLibrarySearch global_search = search;
  global_search.program.clear();
  global_search.program_image = nullptr;
  global_search.program_data = {};
  ElfLoadScope global = build_root(*program, program_data, global_search, nullptr);
  Inherited inherited;
  const std::size_t limit = std::min(search.library_limit, kMaxScopeLibraries);
  inherited.max_libraries =
      global.impl_->libraries.size() >= limit ? 0 : limit - global.impl_->libraries.size();
  inherited.loaded = global.impl_->seen;
  inherited.executable_rpath = global.impl_->executable_rpath;
  inherited.executable_origin = global.impl_->executable_origin;
  inherited.unknown_rpath = global.impl_->other_rpath;
  if (inherited.max_libraries == 0) {
    // The program's scope took the whole limit: the library itself is past it. It stays in the
    // scope by name, unread, so a lookup that reaches it is not known rather than bound to it.
    impl = std::move(*global.impl_);
    ElfScopeLibrary self;
    self.path = fs::path(image.path).generic_string();
    LoadedLibrary loaded;
    loaded.problem = "the scope has more libraries than the limit";
    impl.image_index = impl.libraries.size();
    impl.image_first = own.symbolic;  // DT_SYMBOLIC: the unread library still comes first
    impl.libraries.push_back(std::move(self));
    impl.loaded.push_back(std::move(loaded));
    return scope;
  }
  ElfLoadScope local = build_root(image, data, global_search, &inherited);
  impl = std::move(*global.impl_);
  impl.image_index = impl.libraries.size();
  impl.image_first = own.symbolic;
  for (std::size_t i = 0; i < local.impl_->libraries.size(); ++i) {
    impl.libraries.push_back(std::move(local.impl_->libraries[i]));
    impl.loaded.push_back(std::move(local.impl_->loaded[i]));
  }
  return scope;
}

ElfLoadScope ElfLoadScope::build_root(const BinaryImage& image, std::span<const std::byte> data,
                                      const ElfLibrarySearch& search, const Inherited* inherited) {
  // ld.so.preload belongs to the global scope: a library's local scope does not read it.
  const bool preload = inherited == nullptr;
  const std::size_t max_libraries = inherited != nullptr
                                        ? inherited->max_libraries
                                        : std::min(search.library_limit, kMaxScopeLibraries);
  ElfLoadScope scope;
  Impl& impl = *scope.impl_;
  const std::string& sysroot = search.sysroot;
  // Each object of the scope with what the search needs of it: its dynamic names, its directory
  // (for $ORIGIN) and the object that loaded it (for inherited DT_RPATH).
  std::vector<ElfLibraryNames> names_of;
  std::vector<LoaderPath> origin_of;
  std::vector<std::size_t> loader_of;
  constexpr std::size_t kNoLoader = static_cast<std::size_t>(-1);

  // The executable is the first object of the global scope.
  ElfScopeLibrary self;
  self.path = fs::path(image.path).generic_string();
  if (max_libraries == 0) {
    // A limit of 0 leaves no room even for the root: it is in the scope by name, unread.
    LoadedLibrary loaded;
    loaded.problem = "the scope has more libraries than the limit";
    impl.libraries.push_back(std::move(self));
    impl.loaded.push_back(std::move(loaded));
    return scope;
  }
  const ElfLibraryNames own = read_library_names(image, data);
  impl.executable_dynamic = own.dynamic || !own.complete;
  impl.libraries.push_back(self);
  impl.loaded.push_back(read_definitions(image, data, own));
  if (image.format != BinaryFormat::Elf || image.bits != 64 ||
      elf_machine(image.architecture) == 0) {
    return scope;
  }
  {
    // $ORIGIN of the executable: its directory, as a path of the target when it lies under the
    // sysroot, else as a path of this machine.
    std::error_code error;
    const fs::path absolute = fs::absolute(fs::path(image.path), error);
    const fs::path directory = absolute.parent_path();
    LoaderPath origin{true, directory.generic_string()};
    if (!sysroot.empty()) {
      const fs::path root = fs::weakly_canonical(fs::absolute(fs::path(sysroot), error), error);
      const fs::path here = fs::weakly_canonical(directory, error);
      const fs::path relative = here.lexically_relative(root);
      const std::string text = relative.generic_string();
      if (!error && !relative.empty() && text != ".." && text.rfind("../", 0) != 0) {
        origin = LoaderPath{false, text == "." ? "/" : "/" + text};
      }
    }
    names_of.push_back(own);
    origin_of.push_back(origin);
    loader_of.push_back(kNoLoader);
    if (inherited == nullptr && !own.has_runpath) {
      impl.executable_rpath = own.rpath;
      impl.executable_origin = origin;
    }
  }
  if (!own.complete) {
    impl.loaded[0].readable = false;
    impl.loaded[0].problem = "the executable's dynamic table could not be read in full";
    return scope;
  }

  LoaderCache cache;
  if (search.system_directories) {
    const Resolved where = resolve(LoaderPath{false, "/etc/ld.so.cache"}, sysroot);
    if (where.state == Resolved::State::Unknown) {
      cache.state = LoaderCache::State::Refused;
      cache.reason = where.reason;
    } else if (where.state == Resolved::State::Found) {
      FileBytes file = read_file(where.host, kMaxLoaderCacheBytes);
      if (file.state == FileBytes::State::Refused) {
        cache.state = LoaderCache::State::Refused;
        cache.reason = where.host.generic_string() + " could not be read";
      } else if (file.state == FileBytes::State::Read) {
        auto entries = read_loader_cache(file.bytes);
        if (entries) {
          cache.state = LoaderCache::State::Read;
          cache.entries = std::move(entries.value());
        } else {
          cache.state = LoaderCache::State::Refused;
          cache.reason = where.host.generic_string() + ": " + entries.diagnostic().message;
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

  struct Search {
    Probe::State state = Probe::State::Skipped;
    std::optional<ParsedLibrary> library;
    LoaderPath location;  ///< where the file was found, as the loader names it
    std::string reason;
  };
  // Looks in one directory, as the loader does: its hardware-capability subdirectories first.
  const auto look_in = [&](const LoaderPath& directory, const std::string& name) -> Search {
    Search out;
    const Resolved where = resolve(directory, sysroot);
    if (where.state == Resolved::State::Missing) {
      return out;
    }
    if (where.state == Resolved::State::Unknown) {
      out.state = Probe::State::Unknown;
      out.reason = where.reason;
      return out;
    }
    if (std::string why = hardware_override(directory, name, sysroot); !why.empty()) {
      out.state = Probe::State::Unknown;
      out.reason = std::move(why);
      return out;
    }
    const LoaderPath file = joined(directory, name);
    const Resolved file_where = resolve(file, sysroot);
    if (file_where.state == Resolved::State::Missing) {
      return out;
    }
    if (file_where.state == Resolved::State::Unknown) {
      out.state = Probe::State::Unknown;
      out.reason = file_where.reason;
      return out;
    }
    Probe found = probe(file_where.host, image);
    out.state = found.state;
    out.reason = std::move(found.reason);
    out.library = std::move(found.library);
    out.location = file;
    return out;
  };
  // Finds `name` as the object `requester` asks for it (glibc's _dl_map_object).
  const auto find = [&](const std::string& raw_name, std::size_t requester) -> Search {
    Search out;
    const ElfLibraryNames& asking = names_of[requester];
    if (raw_name.find('/') != std::string::npos || raw_name.find('$') != std::string::npos) {
      // A path (after its tokens expand) is opened as it is, without a search.
      std::string why;
      const auto expanded = expand_tokens(raw_name, origin_of[requester], why);
      if (!expanded) {
        out.state = Probe::State::Unknown;
        out.reason = why;
        return out;
      }
      if (expanded->path.find('/') != std::string::npos) {
        const Resolved where = resolve(*expanded, sysroot);
        if (where.state == Resolved::State::Missing) {
          return out;
        }
        if (where.state == Resolved::State::Unknown) {
          out.state = Probe::State::Unknown;
          out.reason = where.reason;
          return out;
        }
        Probe found = probe(where.host, image);
        out.state = found.state;
        out.reason = std::move(found.reason);
        out.library = std::move(found.library);
        out.location = *expanded;
        return out;
      }
    }
    const std::string& name = raw_name;
    std::vector<SearchStep> steps;
    const auto add_entries = [&](const std::string& list, std::size_t object) {
      for (const std::string& entry : split_search_path(list)) {
        SearchStep step;
        std::string why;
        const auto directory = expand_tokens(entry, origin_of[object], why);
        if (directory) {
          step.directory = *directory;
        } else {
          step.kind = SearchStep::Kind::Unknowable;
          step.reason = why;
        }
        steps.push_back(std::move(step));
      }
    };
    if (!asking.has_runpath) {
      // DT_RPATH of the requester, then of each object that loaded it, up to the executable. An
      // object with DT_RUNPATH has no DT_RPATH for the loader.
      for (std::size_t object = requester; object != kNoLoader; object = loader_of[object]) {
        if (!names_of[object].has_runpath) {
          add_entries(names_of[object].rpath, object);
        }
      }
      if (inherited != nullptr) {
        // A library's local scope: the object that called dlopen loaded it, and its DT_RPATH
        // (and its loaders') comes next. That object is not known; when one of the program's
        // libraries has a DT_RPATH to pass on, the search is not known either. Then glibc tries
        // the executable's own DT_RPATH.
        if (inherited->unknown_rpath) {
          SearchStep step;
          step.kind = SearchStep::Kind::Unknowable;
          step.reason =
              "the object that loads the library with dlopen is not known, and a "
              "library of the program's scope has a DT_RPATH it would pass on";
          steps.push_back(std::move(step));
        }
        for (const std::string& entry : split_search_path(inherited->executable_rpath)) {
          SearchStep step;
          std::string why;
          const auto directory = expand_tokens(entry, inherited->executable_origin, why);
          if (directory) {
            step.directory = *directory;
          } else {
            step.kind = SearchStep::Kind::Unknowable;
            step.reason = why;
          }
          steps.push_back(std::move(step));
        }
      }
    }
    for (const std::string& directory : search.paths) {
      SearchStep step;
      step.directory = LoaderPath{true, directory};
      steps.push_back(std::move(step));
    }
    add_entries(asking.runpath, requester);
    if (!asking.nodeflib) {
      steps.push_back(SearchStep{SearchStep::Kind::Cache, {}, {}});
      steps.push_back(SearchStep{SearchStep::Kind::Defaults, {}, {}});
    }
    for (const SearchStep& step : steps) {
      switch (step.kind) {
        case SearchStep::Kind::Unknowable:
          out.state = Probe::State::Unknown;
          out.reason = step.reason;
          return out;
        case SearchStep::Kind::Directory: {
          Search found = look_in(step.directory, name);
          if (found.state != Probe::State::Skipped) {
            return found;
          }
          break;
        }
        case SearchStep::Kind::Cache: {
          if (cache.state == LoaderCache::State::Refused) {
            out.state = Probe::State::Unknown;
            out.reason = cache.reason;
            return out;
          }
          std::optional<std::string> chosen;
          for (const ElfLoaderCacheEntry& entry : cache.entries) {
            if (entry.name != name ||
                (entry.flags != 1 && entry.flags != cache_id(image.architecture))) {
              continue;
            }
            if (entry.hwcap != 0) {
              out.state = Probe::State::Unknown;
              out.reason = "ld.so.cache has an entry of " + name +
                           " for particular hardware, chosen by the target's processor";
              return out;
            }
            if (chosen && *chosen != entry.path) {
              out.state = Probe::State::Unknown;
              out.reason = "ld.so.cache has two entries of " + name;
              return out;
            }
            chosen = entry.path;
          }
          if (chosen) {
            if (chosen->empty() || chosen->front() != '/') {
              out.state = Probe::State::Unknown;
              out.reason = "ld.so.cache names " + name + " by a relative path";
              return out;
            }
            const LoaderPath file{false, *chosen};
            const Resolved where = resolve(file, sysroot);
            if (where.state == Resolved::State::Unknown) {
              out.state = Probe::State::Unknown;
              out.reason = where.reason;
              return out;
            }
            if (where.state == Resolved::State::Found) {
              Probe found = probe(where.host, image);
              if (found.state != Probe::State::Skipped) {
                out.state = found.state;
                out.reason = std::move(found.reason);
                out.library = std::move(found.library);
                out.location = file;
                return out;
              }
            }
          }
          break;  // not in the cache, or the cached file is unusable: the default directories
        }
        case SearchStep::Kind::Defaults: {
          // Which default directories the target's loader searches, and in which order, is set
          // when glibc is built. A name found in two of them as two different files is not known.
          std::optional<Search> first;
          fs::path first_host;
          for (const std::string& directory : defaults) {
            Search found = look_in(LoaderPath{false, directory}, name);
            if (found.state == Probe::State::Unknown) {
              return found;
            }
            if (found.state != Probe::State::Taken) {
              continue;
            }
            const fs::path host = resolve(found.location, sysroot).host;
            if (!first) {
              first = std::move(found);
              first_host = host;
              continue;
            }
            std::error_code error;
            if (!fs::equivalent(first_host, host, error) || error) {
              out.state = Probe::State::Unknown;
              out.reason = name + " is in two default directories as different files, and which " +
                           "the loader searches first depends on how its glibc was built";
              return out;
            }
          }
          if (first) {
            return std::move(*first);
          }
          break;
        }
      }
    }
    return out;  // not found anywhere
  };

  // Breadth first, each library once: ld.so.preload, then the executable's DT_NEEDED, then theirs.
  struct Pending {
    std::string name;
    std::size_t requester = 0;
    bool preloaded = false;
  };
  std::deque<Pending> queue;
  bool overflow = false;
  const auto enqueue = [&](Pending pending) {
    // Once one library is left out, every later one is too: a library queued after the omission
    // would otherwise take a place in the scope before the one left out.
    if (overflow || queue.size() >= search.queue_limit) {
      overflow = true;
      return;
    }
    queue.push_back(std::move(pending));
  };
  if (search.system_directories && preload) {
    // ld.so.preload: names separated by white space or `:`, `#` to the end of a line a comment.
    const Resolved where = resolve(LoaderPath{false, "/etc/ld.so.preload"}, sysroot);
    std::optional<std::string> problem;
    if (where.state == Resolved::State::Unknown) {
      problem = where.reason;
    } else if (where.state == Resolved::State::Found) {
      FileBytes file = read_file(where.host, kMaxPreloadBytes);
      if (file.state == FileBytes::State::Refused) {
        problem = where.host.generic_string() + " could not be read";
      } else if (file.state == FileBytes::State::Read) {
        std::string word;
        bool comment = false;
        for (const std::byte b : file.bytes) {
          const char c = static_cast<char>(b);
          if (comment) {
            comment = c != '\n';
            continue;
          }
          if (c == '#') {
            comment = true;
          }
          if (c == '#' || c == ' ' || c == '\t' || c == '\n' || c == ':') {
            if (!word.empty()) {
              enqueue({word, 0, true});
            }
            word.clear();
          } else {
            word += c;
          }
        }
        if (!word.empty()) {
          enqueue({word, 0, true});
        }
      }
    }
    if (problem) {
      ElfScopeLibrary library;
      library.name = "/etc/ld.so.preload";
      LoadedLibrary loaded;
      loaded.problem = *problem;
      impl.libraries.push_back(std::move(library));
      impl.loaded.push_back(std::move(loaded));
      return scope;
    }
  }
  for (const std::string& name : own.needed) {
    enqueue({name, 0, false});
  }
  // Names, sonames and files already in the scope. A library's local scope starts with what the
  // program's global scope loaded: glibc gives a needed name that matches one of them that object.
  std::set<std::string> seen;
  if (inherited != nullptr) {
    seen = inherited->loaded;
  }
  while (!queue.empty() && impl.libraries.size() < max_libraries) {
    Pending next = std::move(queue.front());
    queue.pop_front();
    if (seen.contains(next.name)) {
      continue;
    }
    seen.insert(next.name);
    ElfScopeLibrary library;
    library.name = next.name;
    library.preloaded = next.preloaded;
    Search found = find(next.name, next.requester);
    LoadedLibrary loaded;
    ElfLibraryNames names;
    LoaderPath origin;
    if (found.state == Probe::State::Taken && found.library.has_value()) {
      library.path = spelled(found.location, sysroot);
      std::error_code error;
      const fs::path real = fs::canonical(resolve(found.location, sysroot).host, error);
      const std::string identity = error ? library.path : "file:" + real.generic_string();
      if (seen.contains(identity)) {
        continue;  // the same file under another name: the loader loads it once
      }
      seen.insert(identity);
      names = read_library_names(found.library->image, found.library->data);
      library.soname = names.soname;
      if (!names.soname.empty()) {
        seen.insert(names.soname);
      }
      loaded = read_definitions(found.library->image, found.library->data, names);
      if (!loaded.readable) {
        loaded.problem = library.path + ": " + loaded.problem;
      }
      const std::string& where = found.location.path;
      const auto cut = where.find_last_of('/');
      origin = LoaderPath{found.location.host, cut == 0 ? "/" : where.substr(0, cut)};
    } else if (found.state == Probe::State::Unknown) {
      loaded.problem = next.name + ": " + found.reason;
    } else {
      loaded.problem = next.name + " was not found";
    }
    const std::size_t index = impl.libraries.size();
    impl.libraries.push_back(std::move(library));
    impl.loaded.push_back(std::move(loaded));
    names_of.push_back(names);
    origin_of.push_back(origin);
    loader_of.push_back(next.requester);
    if (impl.loaded[index].readable) {
      // A library whose dynamic table was not read in full is not readable, and the lookup stops
      // there: its missing needs would come after it.
      for (const std::string& needed : names.needed) {
        enqueue({needed, index, false});
      }
    }
  }
  if (!queue.empty() || overflow) {
    // More libraries than the limits: what follows is not known.
    ElfScopeLibrary rest;
    rest.name = "(more libraries than the limit)";
    LoadedLibrary loaded;
    loaded.problem = "the scope has more libraries than the limit";
    impl.libraries.push_back(rest);
    impl.loaded.push_back(std::move(loaded));
  }
  impl.seen = std::move(seen);
  for (std::size_t object = 1; object < names_of.size(); ++object) {
    if (!names_of[object].has_runpath && !names_of[object].rpath.empty()) {
      impl.other_rpath = true;
    }
  }
  return scope;
}

ElfBinding ElfLoadScope::lookup(const std::string& name, const std::string& version,
                                bool hidden_need) const {
  ElfBinding out;
  // DT_SYMBOLIC: the image itself first, then the scope in order (where it is not looked up again).
  std::vector<std::size_t> order;
  if (impl_->image_first && impl_->image_index < impl_->libraries.size()) {
    order.push_back(impl_->image_index);
  }
  for (std::size_t index = 0; index < impl_->libraries.size(); ++index) {
    if (order.empty() || index != order.front()) {
      order.push_back(index);
    }
  }
  for (const std::size_t index : order) {
    const LoadedLibrary& loaded = impl_->loaded[index];
    if (!loaded.readable) {
      if (index == 0 && !impl_->executable_dynamic) {
        continue;  // an executable that is not dynamically linked defines nothing for others
      }
      out.outcome = ElfBinding::Outcome::Unknown;
      // Index 0 is the executable, unless a library's program is not known (that entry is named).
      const bool executable = index == 0 && impl_->libraries[0].name.empty();
      out.reason = executable ? "the executable: " + loaded.problem : loaded.problem;
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
        // glibc check_match, versioned reference: the same version, or (for a need that is not
        // hidden) a definition whose index has no version of its own and that is not hidden.
        if (named != loaded.versions.end() ? named->second == version : !hidden && !hidden_need) {
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
