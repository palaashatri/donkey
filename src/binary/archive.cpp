#include "donkey/binary/archive.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

#include "donkey/binary/byte_reader.h"

namespace donkey {
namespace {

constexpr std::string_view kMagic = "!<arch>\n";
constexpr std::uint64_t kHeaderSize = 60;

char char_at(std::span<const std::byte> bytes, std::size_t index) {
  return static_cast<char>(bytes[index]);
}

std::string_view view_of(std::span<const std::byte> bytes, std::size_t offset, std::size_t length) {
  return std::string_view(reinterpret_cast<const char*>(bytes.data() + offset), length);
}

std::string_view trim_trailing_spaces(std::string_view text) {
  while (!text.empty() && text.back() == ' ') {
    text.remove_suffix(1);
  }
  return text;
}

/// A number written in `base` in a fixed-width header field, padded with spaces. A blank
/// field is 0; anything else that is not a number that fits in 64 bits is nullopt.
std::optional<std::uint64_t> parse_number(std::string_view field, unsigned base) {
  const std::string_view text = trim_trailing_spaces(field);
  if (text.empty()) {
    return 0;
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    unsigned digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<unsigned>(c - '0');
    } else {
      return std::nullopt;
    }
    if (digit >= base) {
      return std::nullopt;
    }
    const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
    if (value > (limit - digit) / base) {
      return std::nullopt;
    }
    value = value * base + digit;
  }
  return value;
}

/// The GNU name table entry at `start`, which runs to a newline and ends with a slash.
std::optional<std::string> long_name_at(std::span<const std::byte> table, std::uint64_t start) {
  if (start >= table.size()) {
    return std::nullopt;
  }
  const std::uint64_t limit = std::min<std::uint64_t>(table.size(), start + kMaxArchiveNameBytes);
  for (std::uint64_t i = start; i < limit; ++i) {
    if (char_at(table, i) == '\n') {
      std::uint64_t end = i;
      if (end > start && char_at(table, end - 1) == '/') {
        --end;
      }
      return std::string(view_of(table, start, end - start));
    }
  }
  return std::nullopt;
}

}  // namespace

const char* archive_member_kind_name(ArchiveMemberKind kind) noexcept {
  switch (kind) {
    case ArchiveMemberKind::Object:
      return "object";
    case ArchiveMemberKind::SymbolTable:
      return "symbol-table";
    case ArchiveMemberKind::LongNames:
      return "long-names";
  }
  return "unknown";
}

Result<ArchiveIndex> read_archive(std::span<const std::byte> data, const ArchiveOptions& options) {
  const ByteReader reader(data);
  const std::uint64_t total = reader.size();
  if (total < kMagic.size() || view_of(data, 0, kMagic.size()) != kMagic) {
    return make_error<ArchiveIndex>(Status::InvalidInput, "archive.bad_magic",
                                    "the file does not start with !<arch>");
  }

  ArchiveIndex index;
  std::span<const std::byte> long_names;
  bool have_long_names = false;
  std::uint64_t offset = kMagic.size();

  const auto stop = [&index](std::string note) {
    index.partial = true;
    index.note = std::move(note);
  };

  while (offset < total) {
    if (index.members.size() >= options.max_members) {
      stop("the member limit was reached");
      break;
    }
    if (total - offset < kHeaderSize) {
      stop("a member header is truncated");
      break;
    }
    const std::span<const std::byte> header = data.subspan(offset, kHeaderSize);
    if (char_at(header, 58) != '`' || char_at(header, 59) != '\n') {
      stop("a member header has a bad terminator");
      break;
    }
    const std::optional<std::uint64_t> header_size = parse_number(view_of(header, 48, 10), 10);
    if (!header_size) {
      stop("a member size is not a number");
      break;
    }
    const std::uint64_t body = offset + kHeaderSize;
    if (*header_size > total - body) {
      stop("a member's data runs past the end of the archive");
      break;
    }

    ArchiveMember member;
    member.modified = parse_number(view_of(header, 16, 12), 10).value_or(0);
    member.mode = static_cast<std::uint32_t>(parse_number(view_of(header, 40, 8), 8).value_or(0));
    member.size = *header_size;
    member.offset = body;

    const std::string_view raw = trim_trailing_spaces(view_of(header, 0, 16));
    if (raw == "/" || raw == "/SYM64/") {
      member.kind = ArchiveMemberKind::SymbolTable;
      member.name = std::string(raw);
    } else if (raw == "//") {
      member.kind = ArchiveMemberKind::LongNames;
      member.name = "//";
      if (!have_long_names) {
        long_names = data.subspan(body, *header_size);
        have_long_names = true;
      }
    } else if (raw.size() > 3 && raw.substr(0, 3) == "#1/") {
      // BSD: the member's name is the first `length` bytes of its data.
      const std::optional<std::uint64_t> length = parse_number(raw.substr(3), 10);
      if (!length || *length > kMaxArchiveNameBytes || *length > *header_size) {
        stop("a BSD member name does not fit in its member");
        break;
      }
      std::string name(view_of(data, body, static_cast<std::size_t>(*length)));
      while (!name.empty() && name.back() == '\0') {
        name.pop_back();
      }
      member.name = sanitize_name(name);
      member.offset = body + *length;
      member.size = *header_size - *length;
    } else if (raw.size() >= 2 && raw.front() == '/' &&
               parse_number(raw.substr(1), 10).has_value()) {
      // GNU: `/<n>` is the entry at offset n of the `//` table, if one was read.
      const std::uint64_t entry = *parse_number(raw.substr(1), 10);
      std::optional<std::string> resolved;
      if (have_long_names) {
        resolved = long_name_at(long_names, entry);
      }
      member.name = sanitize_name(resolved.value_or(std::string(raw)));
    } else {
      // System V: a name ends with a slash.
      std::string name(raw);
      if (!name.empty() && name.back() == '/') {
        name.pop_back();
      }
      member.name = sanitize_name(name);
    }

    if (member.kind == ArchiveMemberKind::Object && member.name.empty()) {
      member.name = "<unnamed>";
    }
    index.members.push_back(std::move(member));
    // Members are padded to an even length.
    offset = body + *header_size + (*header_size & 1U);
  }
  return index;
}

}  // namespace donkey
