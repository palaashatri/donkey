#include "donkey/binary/unwind_info.h"

#include <limits>
#include <string>

#include "donkey/core/checked.h"

namespace donkey {

namespace {

constexpr std::uint64_t kHeaderSize = 28;      // seven uint32 fields
constexpr std::uint64_t kIndexEntrySize = 12;  // functionOffset, pages offset, LSDA offset
constexpr std::uint32_t kRegularPage = 2;
constexpr std::uint32_t kCompressedPage = 3;

Diagnostic unwind_error(std::string code, std::string message, std::uint64_t offset) {
  return Diagnostic::make(Status::InvalidInput, std::move(code), std::move(message), offset);
}

/// True when `count` items of `item_size` bytes from `offset` lie inside a section of `size`.
bool array_fits(std::uint64_t offset, std::uint64_t count, std::uint64_t item_size,
                std::uint64_t size) {
  return count <= std::numeric_limits<std::uint64_t>::max() / item_size &&
         checked::in_range(offset, count * item_size, size);
}

}  // namespace

Result<UnwindInfo> read_unwind_info(std::span<const std::byte> section, std::uint64_t image_base,
                                    Endian endian, std::size_t max_entries) {
  const ByteReader reader(section);
  const std::uint64_t size = reader.size();
  if (size < kHeaderSize) {
    return unwind_error("unwind_info.bad_header", "__unwind_info is shorter than its header", 0);
  }
  // Every read below is inside the section: the header was checked above, and each array, page
  // and entry is checked before it is read.
  auto field = [&](std::uint64_t at) -> std::uint32_t {
    auto read = reader.u32(at, endian);
    return read ? read.value() : 0;
  };
  auto half = [&](std::uint64_t at) -> std::uint64_t {
    auto read = reader.u16(at, endian);
    return read ? read.value() : 0;
  };
  if (field(0) != 1) {
    return unwind_error("unwind_info.bad_header", "__unwind_info is not version 1", 0);
  }
  const std::uint64_t common_offset = field(4);
  const std::uint64_t common_count = field(8);
  const std::uint64_t personality_offset = field(12);
  const std::uint64_t personality_count = field(16);
  const std::uint64_t index_offset = field(20);
  const std::uint64_t index_count = field(24);
  if (!array_fits(common_offset, common_count, 4, size) ||
      !array_fits(personality_offset, personality_count, 4, size) ||
      !array_fits(index_offset, index_count, kIndexEntrySize, size)) {
    return unwind_error("unwind_info.outside_section",
                        "an array of the __unwind_info header lies outside the section", 4);
  }
  UnwindInfo out;
  if (index_count == 0) {
    return out;
  }
  auto index_function = [&](std::uint64_t i) {
    return static_cast<std::uint64_t>(field(index_offset + i * kIndexEntrySize));
  };
  auto index_pages = [&](std::uint64_t i) {
    return static_cast<std::uint64_t>(field(index_offset + i * kIndexEntrySize + 4));
  };
  // The final index entry is a sentinel: its function offset ends the covered range, and it has
  // no page. Every other entry has one.
  if (index_pages(index_count - 1) != 0) {
    return unwind_error("unwind_info.bad_index", "the __unwind_info index has no final sentinel",
                        index_offset + (index_count - 1) * kIndexEntrySize);
  }
  const std::uint64_t last_function = index_function(index_count - 1);
  if (image_base > std::numeric_limits<std::uint64_t>::max() - last_function) {
    return unwind_error("unwind_info.bad_index",
                        "the __unwind_info range wraps past the top of the address space",
                        index_offset + (index_count - 1) * kIndexEntrySize);
  }
  out.end = image_base + last_function;
  bool have_previous = false;
  std::uint64_t previous = 0;
  for (std::uint64_t i = 0; i + 1 < index_count; ++i) {
    const std::uint64_t entry_at = index_offset + i * kIndexEntrySize;
    const std::uint64_t first = index_function(i);
    const std::uint64_t limit = index_function(i + 1);
    const std::uint64_t page = index_pages(i);
    if (limit < first) {
      return unwind_error("unwind_info.bad_index",
                          "the __unwind_info index function offsets decrease", entry_at);
    }
    if (page == 0) {
      return unwind_error("unwind_info.bad_index",
                          "an __unwind_info index entry before the sentinel has no page", entry_at);
    }
    if (!checked::in_range(page, 8, size)) {
      return unwind_error("unwind_info.outside_section",
                          "an __unwind_info page lies outside the section", page);
    }
    const std::uint32_t kind = field(page);
    const std::uint64_t entries_offset = half(page + 4);
    const std::uint64_t entry_count = half(page + 6);
    std::uint64_t encodings_offset = 0;
    std::uint64_t encodings_count = 0;
    std::uint64_t entry_size = 0;
    if (kind == kRegularPage) {
      entry_size = 8;
    } else if (kind == kCompressedPage) {
      if (!checked::in_range(page, 12, size)) {
        return unwind_error("unwind_info.outside_section",
                            "an __unwind_info page lies outside the section", page);
      }
      entry_size = 4;
      encodings_offset = half(page + 8);
      encodings_count = half(page + 10);
      if (!array_fits(page + encodings_offset, encodings_count, 4, size)) {
        return unwind_error("unwind_info.outside_section",
                            "the encodings of an __unwind_info page lie outside the section", page);
      }
    } else {
      return unwind_error("unwind_info.bad_page",
                          "an __unwind_info page is neither regular nor compressed", page);
    }
    if (!array_fits(page + entries_offset, entry_count, entry_size, size)) {
      return unwind_error("unwind_info.outside_section",
                          "the entries of an __unwind_info page lie outside the section", page);
    }
    // The arrays follow the page header (8 bytes for a regular page, 12 for a compressed one) and
    // do not overlap each other: entries read from the header or from the encodings are not
    // entries.
    const std::uint64_t header_size = kind == kRegularPage ? 8 : 12;
    if ((entry_count != 0 && entries_offset < header_size) ||
        (encodings_count != 0 && encodings_offset < header_size)) {
      return unwind_error("unwind_info.bad_page",
                          "an __unwind_info page's array overlaps the page header", page);
    }
    if (entry_count != 0 && encodings_count != 0 &&
        entries_offset < encodings_offset + encodings_count * 4 &&
        encodings_offset < entries_offset + entry_count * entry_size) {
      return unwind_error("unwind_info.bad_page",
                          "an __unwind_info page's entries overlap its encodings", page);
    }
    for (std::uint64_t e = 0; e < entry_count; ++e) {
      const std::uint64_t at = page + entries_offset + e * entry_size;
      const std::uint32_t word = field(at);
      std::uint64_t function = 0;
      std::uint32_t encoding = 0;
      if (kind == kRegularPage) {
        function = word;
        encoding = field(at + 4);
      } else {
        // A 24-bit offset from the index entry's function offset and an 8-bit encoding index:
        // the common encodings first, then the page's own.
        function = first + (word & 0x00FFFFFFU);
        const std::uint64_t which = word >> 24;
        if (which < common_count) {
          encoding = field(common_offset + which * 4);
        } else if (which - common_count < encodings_count) {
          encoding = field(page + encodings_offset + (which - common_count) * 4);
        } else {
          return unwind_error("unwind_info.bad_encoding_index",
                              "an __unwind_info entry names an encoding that does not exist", at);
        }
      }
      if (function < first || function >= limit) {
        return unwind_error("unwind_info.bad_page",
                            "an __unwind_info entry lies outside its index entry's range", at);
      }
      // function < limit <= last_function, so the addition was checked with the sentinel.
      const std::uint64_t start = image_base + function;
      if (have_previous && start <= previous) {
        return unwind_error("unwind_info.unsorted",
                            "__unwind_info entries are not in ascending order", at);
      }
      if (out.entries.size() >= max_entries) {
        return Result<UnwindInfo>(
            Diagnostic::make(Status::ResourceLimit, "unwind_info.too_many",
                             "__unwind_info lists more entries than the limit", at));
      }
      out.entries.push_back(UnwindInfoEntry{start, encoding});
      previous = start;
      have_previous = true;
    }
  }
  return out;
}

std::vector<std::uint64_t> unwind_function_starts(const UnwindInfo& info) {
  std::vector<std::uint64_t> starts;
  for (const UnwindInfoEntry& entry : info.entries) {
    if ((entry.encoding & kUnwindIsNotFunctionStart) == 0) {
      starts.push_back(entry.start);
    }
  }
  return starts;
}

Result<UnwindInfo> read_unwind_info_of_image(const BinaryImage& image,
                                             std::span<const std::byte> file,
                                             std::size_t max_entries) {
  if (image.format != BinaryFormat::MachO) {
    return UnwindInfo{};
  }
  const Section* found = nullptr;
  for (const Section& section : image.sections) {
    if (section.name == "__TEXT,__unwind_info" && section.has_file_data) {
      found = &section;
      break;
    }
  }
  if (found == nullptr) {
    return UnwindInfo{};
  }
  if (!checked::in_range(found->file_offset, found->file_size, file.size())) {
    return unwind_error("unwind_info.outside_file", "__unwind_info lies outside the file",
                        found->file_offset);
  }
  const Segment* text = nullptr;
  for (const Segment& segment : image.segments) {
    if (segment.name == "__TEXT") {
      text = &segment;
      break;
    }
  }
  if (text == nullptr) {
    return unwind_error("unwind_info.no_text", "the image has __unwind_info but no __TEXT segment",
                        found->file_offset);
  }
  const auto bytes = file.subspan(static_cast<std::size_t>(found->file_offset),
                                  static_cast<std::size_t>(found->file_size));
  return read_unwind_info(bytes, text->virtual_address, image.endian, max_entries);
}

}  // namespace donkey
