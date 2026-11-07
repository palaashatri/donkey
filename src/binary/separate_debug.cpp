#include "donkey/binary/separate_debug.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/image.h"

namespace donkey {
namespace {

constexpr std::uint32_t kNtGnuBuildId = 3;

std::optional<std::span<const std::byte>> section_bytes(const BinaryImage& image,
                                                        std::span<const std::byte> data,
                                                        const std::string& name) {
  for (const Section& section : image.sections) {
    if (section.name != name) {
      continue;
    }
    if (!section.has_file_data || section.file_offset > data.size() ||
        section.file_size > data.size() - section.file_offset) {
      return std::nullopt;
    }
    return data.subspan(static_cast<std::size_t>(section.file_offset),
                        static_cast<std::size_t>(section.file_size));
  }
  return std::nullopt;
}

std::string hex(std::span<const std::byte> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::byte value : bytes) {
    const auto byte = static_cast<std::uint8_t>(value);
    out.push_back(kDigits[byte >> 4U]);
    out.push_back(kDigits[byte & 0xfU]);
  }
  return out;
}

std::string trim_nul(std::string_view text) {
  const std::size_t end = text.find('\0');
  return std::string(end == std::string_view::npos ? text : text.substr(0, end));
}

Diagnostic diagnostic(const char* code, std::string message) {
  return Diagnostic::make(Status::InvalidInput, std::string("debug.") + code, std::move(message),
                          std::nullopt);
}

/// The contents of a file, or nothing when it cannot be read.
std::optional<std::vector<std::byte>> read_file(const std::filesystem::path& path) {
  std::error_code error;
  if (!std::filesystem::is_regular_file(path, error) || error) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return std::nullopt;
  }
  const std::vector<char> raw((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes;
  bytes.reserve(raw.size());
  for (const char c : raw) {
    bytes.push_back(static_cast<std::byte>(c));
  }
  return bytes;
}

}  // namespace

std::uint32_t gnu_crc32(std::span<const std::byte> bytes) noexcept {
  std::uint32_t crc = 0xffffffffU;
  for (const std::byte value : bytes) {
    crc ^= static_cast<std::uint8_t>(value);
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1U) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
  }
  return ~crc;
}

std::string build_id_hex(const BinaryImage& image, std::span<const std::byte> data) {
  const auto notes = section_bytes(image, data, ".note.gnu.build-id");
  if (!notes) {
    return {};
  }
  const ByteReader reader(*notes);
  const auto name_size = reader.u32(0, image.endian);
  const auto desc_size = reader.u32(4, image.endian);
  const auto type = reader.u32(8, image.endian);
  if (!name_size || !desc_size || !type || type.value() != kNtGnuBuildId) {
    return {};
  }
  const std::uint64_t desc_at = 12 + ((name_size.value() + 3U) & ~3U);
  const auto desc = reader.slice(desc_at, desc_size.value());
  return desc ? hex(desc.value()) : std::string();
}

namespace {

/// The `.gnu_debuglink` section: the debug file's name and the CRC-32 of its contents.
struct DebugLink {
  bool present = false;
  std::string name;
  std::uint32_t crc = 0;
};

DebugLink read_debug_link(const BinaryImage& image, std::span<const std::byte> data) {
  DebugLink link;
  if (const auto bytes = section_bytes(image, data, ".gnu_debuglink"); bytes) {
    const std::string name =
        trim_nul(std::string_view(reinterpret_cast<const char*>(bytes->data()), bytes->size()));
    // The name is NUL-terminated and padded to 4 bytes; the CRC-32 follows it.
    const std::uint64_t crc_at = (name.size() + 1 + 3U) & ~std::uint64_t{3};
    const ByteReader reader(*bytes);
    const auto crc = reader.u32(crc_at, image.endian);
    if (!name.empty() && crc) {
      link.present = true;
      link.name = name;
      link.crc = crc.value();
    }
  }
  return link;
}

}  // namespace

Result<std::string> check_separate_debug_file(const BinaryImage& image,
                                              std::span<const std::byte> data,
                                              const std::string& debug_path) {
  const DebugLink link = read_debug_link(image, data);
  const std::string build_id = build_id_hex(image, data);
  if (image.uuid.empty() && build_id.empty() && !link.present) {
    return Result<std::string>(diagnostic("no_link", "the binary names no separate debug file"));
  }
  const auto bytes = read_file(debug_path);
  if (!bytes) {
    return Result<std::string>(diagnostic("not_found", "the named debug file cannot be read"));
  }
  // The same rules as the search: the UUID for a Mach-O, else the build-id, else the CRC-32.
  if (!image.uuid.empty()) {
    auto candidate = parse_binary(*bytes, debug_path);
    if (!candidate || candidate.value().uuid != image.uuid) {
      return Result<std::string>(diagnostic("uuid", "the named file has another Mach-O UUID"));
    }
    return debug_path;
  }
  if (!build_id.empty()) {
    auto candidate = parse_binary(*bytes, debug_path);
    if (!candidate || build_id_hex(candidate.value(), *bytes) != build_id) {
      return Result<std::string>(diagnostic("build_id", "the named file has another build-id"));
    }
    return debug_path;
  }
  if (gnu_crc32(*bytes) != link.crc) {
    return Result<std::string>(diagnostic("crc", "the named file has another CRC-32"));
  }
  return debug_path;
}

Result<std::string> find_separate_debug_file(const BinaryImage& image,
                                             std::span<const std::byte> data,
                                             const std::string& binary_path,
                                             const SeparateDebugOptions& options) {
  const std::string build_id = build_id_hex(image, data);
  const DebugLink link = read_debug_link(image, data);
  const bool has_link = link.present;
  const std::string& link_name = link.name;
  const std::uint32_t link_crc = link.crc;
  if (build_id.empty() && !has_link && image.uuid.empty()) {
    return Result<std::string>(diagnostic("no_link", "the binary names no separate debug file"));
  }

  // How a candidate is checked: by build-id, by the debuglink CRC-32, or by Mach-O UUID.
  enum class Check { BuildId, Link, Uuid };
  // The candidates, in the order the tools use them: the Mach-O .dSYM bundle beside the binary,
  // then the build-id tree, then the debuglink beside the binary, in its .debug subdirectory,
  // and under each debug directory.
  std::vector<std::pair<std::filesystem::path, Check>> candidates;
  if (!image.uuid.empty()) {
    candidates.emplace_back(std::filesystem::path(binary_path + ".dSYM") / "Contents" /
                                "Resources" / "DWARF" /
                                std::filesystem::path(binary_path).filename(),
                            Check::Uuid);
  }
  for (const std::string& directory : options.debug_directories) {
    if (build_id.size() > 2) {
      candidates.emplace_back(std::filesystem::path(directory) / ".build-id" /
                                  build_id.substr(0, 2) / (build_id.substr(2) + ".debug"),
                              Check::BuildId);
    }
  }
  if (has_link) {
    const std::filesystem::path binary = std::filesystem::path(binary_path).parent_path();
    candidates.emplace_back(binary / link_name, Check::Link);
    candidates.emplace_back(binary / ".debug" / link_name, Check::Link);
    for (const std::string& directory : options.debug_directories) {
      candidates.emplace_back(std::filesystem::path(directory) / binary.relative_path() / link_name,
                              Check::Link);
    }
  }

  // The first candidate that matches wins. One that exists but names a different file is
  // skipped, and reported if nothing matches: it is never used.
  std::optional<Diagnostic> mismatch;
  for (const auto& [path, check] : candidates) {
    const auto bytes = read_file(path);
    if (!bytes) {
      continue;
    }
    if (check == Check::Link) {
      if (gnu_crc32(*bytes) != link_crc) {
        if (!mismatch) {
          mismatch = diagnostic("crc", "a file named by the debuglink has another CRC-32");
        }
        continue;
      }
      return path.string();
    }
    auto candidate = parse_binary(*bytes, path.string());
    if (check == Check::Uuid) {
      if (!candidate || candidate.value().uuid != image.uuid) {
        if (!mismatch) {
          mismatch = diagnostic("uuid", "a .dSYM file has another Mach-O UUID");
        }
        continue;
      }
      return path.string();
    }
    if (!candidate || build_id_hex(candidate.value(), *bytes) != build_id) {
      if (!mismatch) {
        mismatch = diagnostic("build_id", "a file at the build-id path has another build-id");
      }
      continue;
    }
    return path.string();
  }
  if (mismatch) {
    return Result<std::string>(*mismatch);
  }
  return Result<std::string>(diagnostic("not_found", "no separate debug file matches the binary"));
}

}  // namespace donkey
