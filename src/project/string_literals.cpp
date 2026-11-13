#include "donkey/project/string_literals.h"

#include <cstdio>

namespace donkey {
namespace {

/// The C literal of the bytes before their first NUL, with the escapes described in the header.
std::string c_literal(std::span<const std::byte> bytes) {
  std::string out = "\"";
  for (const std::byte value : bytes) {
    const auto byte = static_cast<unsigned char>(std::to_integer<std::uint8_t>(value));
    if (byte == '"' || byte == '\\') {
      out.push_back('\\');
      out.push_back(static_cast<char>(byte));
    } else if (byte == '\n') {
      out += "\\n";
    } else if (byte == '\t') {
      out += "\\t";
    } else if (byte >= 0x20 && byte <= 0x7e) {
      out.push_back(static_cast<char>(byte));
    } else {
      char escape[8];
      std::snprintf(escape, sizeof(escape), "\\%03o", static_cast<unsigned>(byte));
      out += escape;
    }
  }
  out.push_back('"');
  return out;
}

}  // namespace

std::map<std::uint64_t, std::string> string_literals(const std::vector<Annotation>& annotations,
                                                     const BinaryImage& image,
                                                     std::span<const std::byte> file) {
  std::map<std::uint64_t, std::string> literals;
  for (const Annotation& annotation : annotations) {
    if (annotation.kind != AnnotationKind::DataRange) {
      continue;
    }
    std::uint64_t element_size = 0;
    std::uint64_t count = 0;
    StringEncoding encoding = StringEncoding::None;
    if (!parse_data_extent(annotation.text, element_size, count, encoding) ||
        encoding != StringEncoding::Bytes || count == 0) {
      continue;
    }
    auto offset = image.va_to_file_offset(annotation.address);
    if (!offset || offset.value() > file.size() || count > file.size() - offset.value()) {
      continue;
    }
    const auto range =
        file.subspan(static_cast<std::size_t>(offset.value()), static_cast<std::size_t>(count));
    std::size_t terminator = 0;
    while (terminator < range.size() && range[terminator] != std::byte{0}) {
      ++terminator;
    }
    if (terminator == range.size()) {
      continue;  // no terminator inside the range: not a string the range defines
    }
    literals[annotation.address] = c_literal(range.first(terminator));
  }
  return literals;
}

}  // namespace donkey
