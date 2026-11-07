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

Result<std::string> find_separate_debug_file(const BinaryImage& image,
                                             std::span<const std::byte> data,
                                             const std::string& binary_path,
                                             const SeparateDebugOptions& options) {
  const std::string build_id = build_id_hex(image, data);
  std::string link_name;
  std::uint32_t link_crc = 0;
  bool has_link = false;
  if (const auto link = section_bytes(image, data, ".gnu_debuglink"); link) {
    const std::string name =
        trim_nul(std::string_view(reinterpret_cast<const char*>(link->data()), link->size()));
    // The name is NUL-terminated and padded to 4 bytes; the CRC-32 follows it.
    const std::uint64_t crc_at = (name.size() + 1 + 3U) & ~std::uint64_t{3};
    const ByteReader reader(*link);
    const auto crc = reader.u32(crc_at, image.endian);
    if (!name.empty() && crc) {
      link_name = name;
      link_crc = crc.value();
      has_link = true;
    }
  }
  if (build_id.empty() && !has_link) {
    return Result<std::string>(diagnostic("no_link", "the binary names no separate debug file"));
  }

  // The candidates, in the order gdb uses them: the build-id tree first, then the debuglink
  // beside the binary, in its .debug subdirectory, and under each debug directory.
  std::vector<std::pair<std::filesystem::path, bool>> candidates;  // path, checked by build-id
  for (const std::string& directory : options.debug_directories) {
    if (build_id.size() > 2) {
      candidates.emplace_back(std::filesystem::path(directory) / ".build-id" /
                                  build_id.substr(0, 2) / (build_id.substr(2) + ".debug"),
                              true);
    }
  }
  if (has_link) {
    const std::filesystem::path binary = std::filesystem::path(binary_path).parent_path();
    candidates.emplace_back(binary / link_name, false);
    candidates.emplace_back(binary / ".debug" / link_name, false);
    for (const std::string& directory : options.debug_directories) {
      candidates.emplace_back(std::filesystem::path(directory) / binary.relative_path() / link_name,
                              false);
    }
  }

  // The first candidate that matches wins. One that exists but names a different file is
  // skipped, and reported if nothing matches: it is never used.
  std::optional<Diagnostic> mismatch;
  for (const auto& [path, by_build_id] : candidates) {
    const auto bytes = read_file(path);
    if (!bytes) {
      continue;
    }
    if (by_build_id) {
      auto candidate = parse_binary(*bytes, path.string());
      if (!candidate || build_id_hex(candidate.value(), *bytes) != build_id) {
        if (!mismatch) {
          mismatch = diagnostic("build_id", "a file at the build-id path has another build-id");
        }
        continue;
      }
      return path.string();
    }
    if (gnu_crc32(*bytes) != link_crc) {
      if (!mismatch) {
        mismatch = diagnostic("crc", "a file named by the debuglink has another CRC-32");
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
