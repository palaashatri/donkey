#include "donkey/binary/function_starts.h"

#include <string>

#include "donkey/core/checked.h"

namespace donkey {

namespace {

Diagnostic starts_error(std::string code, std::string message, std::uint64_t offset) {
  return Diagnostic::make(Status::InvalidInput, std::move(code), std::move(message), offset);
}

}  // namespace

Result<std::vector<std::uint64_t>> read_function_starts(std::span<const std::byte> table,
                                                        std::uint64_t text_address,
                                                        std::uint64_t text_size, bool thumb,
                                                        std::size_t max_entries) {
  std::vector<std::uint64_t> starts;
  std::uint64_t address = text_address;
  std::size_t at = 0;
  while (at < table.size()) {
    const std::size_t begin = at;
    std::uint64_t delta = 0;
    unsigned shift = 0;
    bool done = false;
    while (at < table.size()) {
      const auto byte = std::to_integer<std::uint64_t>(table[at++]);
      if (shift == 63 && (byte & 0x7EU) != 0) {
        return starts_error("function_starts.bad_uleb128",
                            "a ULEB128 delta does not fit in 64 bits", begin);
      }
      delta |= (byte & 0x7FU) << shift;
      if ((byte & 0x80U) == 0) {
        done = true;
        break;
      }
      shift += 7;
      if (shift > 63) {
        return starts_error("function_starts.bad_uleb128",
                            "a ULEB128 delta is longer than 10 bytes", begin);
      }
    }
    if (!done) {
      // The data ends inside a delta: nothing after the last whole one is a start.
      return starts_error("function_starts.bad_uleb128", "the table ends inside a ULEB128 delta",
                          begin);
    }
    if (delta == 0) {
      break;  // the end of the list; the rest is padding
    }
    const std::uint64_t offset_in_text = address - text_address;
    if (delta > text_size || offset_in_text > text_size - delta) {
      return starts_error("function_starts.outside_text",
                          "a function start lies outside the __TEXT segment", begin);
    }
    address += delta;
    if (starts.size() >= max_entries) {
      return Result<std::vector<std::uint64_t>>(
          Diagnostic::make(Status::ResourceLimit, "function_starts.too_many",
                           "the table lists more function starts than the limit", begin));
    }
    starts.push_back(thumb ? (address & ~std::uint64_t{1}) : address);
  }
  return starts;
}

Result<std::vector<std::uint64_t>> read_function_starts_of_image(const BinaryImage& image,
                                                                 std::span<const std::byte> file,
                                                                 std::size_t max_entries) {
  if (image.format != BinaryFormat::MachO || image.function_starts_size == 0) {
    return std::vector<std::uint64_t>{};
  }
  if (!checked::in_range(image.function_starts_offset, image.function_starts_size, file.size())) {
    return starts_error("function_starts.outside_file",
                        "the LC_FUNCTION_STARTS table lies outside the file",
                        image.function_starts_offset);
  }
  const Segment* text = nullptr;
  for (const Segment& segment : image.segments) {
    if (segment.name == "__TEXT") {
      text = &segment;
      break;
    }
  }
  if (text == nullptr) {
    return starts_error("function_starts.no_text",
                        "the image has LC_FUNCTION_STARTS but no __TEXT segment",
                        image.function_starts_offset);
  }
  const auto table = file.subspan(static_cast<std::size_t>(image.function_starts_offset),
                                  static_cast<std::size_t>(image.function_starts_size));
  return read_function_starts(table, text->virtual_address, text->virtual_size,
                              image.architecture == Architecture::Arm, max_entries);
}

}  // namespace donkey
