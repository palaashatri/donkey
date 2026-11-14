#include "donkey/binary/eh_frame.h"

#include <map>
#include <optional>
#include <string>

namespace donkey {
namespace {

// DW_EH_PE pointer encodings (the Linux Standard Base, "Exception Frames").
constexpr std::uint8_t kPeOmit = 0xff;
constexpr std::uint8_t kPeIndirect = 0x80;
constexpr std::uint8_t kPeFormat = 0x0f;
constexpr std::uint8_t kPeApplication = 0x70;
constexpr std::uint8_t kPeAbsptr = 0x00;
constexpr std::uint8_t kPeUleb128 = 0x01;
constexpr std::uint8_t kPeUdata2 = 0x02;
constexpr std::uint8_t kPeUdata4 = 0x03;
constexpr std::uint8_t kPeUdata8 = 0x04;
constexpr std::uint8_t kPeSleb128 = 0x09;
constexpr std::uint8_t kPeSdata2 = 0x0a;
constexpr std::uint8_t kPeSdata4 = 0x0b;
constexpr std::uint8_t kPeSdata8 = 0x0c;
constexpr std::uint8_t kPeAppPcrel = 0x10;

constexpr std::size_t kMaxLebBytes = 10;  // enough for any 64-bit value
constexpr std::size_t kMaxAugmentation = 32;

/// A bounds-checked cursor over one record. Once a read fails the cursor stays failed.
class Cursor {
 public:
  Cursor(const ByteReader& reader, std::uint64_t pos, std::uint64_t end, Endian endian)
      : reader_(reader), pos_(pos), end_(end), endian_(endian) {}

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] std::uint64_t pos() const noexcept { return pos_; }
  [[nodiscard]] std::uint64_t end() const noexcept { return end_; }
  [[nodiscard]] Endian endian() const noexcept { return endian_; }
  [[nodiscard]] bool at_end() const noexcept { return pos_ >= end_; }

  void fail() noexcept { ok_ = false; }
  void seek(std::uint64_t pos) noexcept {
    if (pos > end_) {
      ok_ = false;
      return;
    }
    pos_ = pos;
  }
  void skip(std::uint64_t count) noexcept {
    if (!ok_ || count > end_ - pos_) {
      ok_ = false;
      return;
    }
    pos_ += count;
  }

  std::uint8_t u8() {
    if (!ok_ || pos_ >= end_) {
      ok_ = false;
      return 0;
    }
    const auto value = reader_.u8(pos_);
    if (!value) {
      ok_ = false;
      return 0;
    }
    pos_ += 1;
    return value.value();
  }

  /// An unsigned value of `size` bytes (1, 2, 4 or 8) in the record's byte order.
  std::uint64_t unsigned_of(unsigned size) {
    if (!ok_ || size > end_ - pos_) {
      ok_ = false;
      return 0;
    }
    std::uint64_t value = 0;
    switch (size) {
      case 1:
        value = u8();
        break;
      case 2: {
        const auto v = reader_.u16(pos_, endian_);
        ok_ = ok_ && v.has_value();
        value = ok_ ? v.value() : 0;
        break;
      }
      case 4: {
        const auto v = reader_.u32(pos_, endian_);
        ok_ = ok_ && v.has_value();
        value = ok_ ? v.value() : 0;
        break;
      }
      case 8: {
        const auto v = reader_.u64(pos_, endian_);
        ok_ = ok_ && v.has_value();
        value = ok_ ? v.value() : 0;
        break;
      }
      default:
        ok_ = false;
        return 0;
    }
    if (ok_) {
      pos_ += size;
    }
    return value;
  }

  std::uint64_t uleb() {
    std::uint64_t value = 0;
    unsigned shift = 0;
    for (std::size_t n = 0; ok_; ++n) {
      const std::uint8_t byte = u8();
      if (!ok_) {
        return 0;
      }
      if (n >= kMaxLebBytes) {
        ok_ = false;
        return 0;
      }
      if (shift < 64) {
        value |= static_cast<std::uint64_t>(byte & 0x7FU) << shift;
      }
      shift += 7;
      if ((byte & 0x80U) == 0) {
        return value;
      }
    }
    return 0;
  }

  std::int64_t sleb() {
    std::uint64_t value = 0;
    unsigned shift = 0;
    std::uint8_t byte = 0;
    for (std::size_t n = 0; ok_; ++n) {
      byte = u8();
      if (!ok_) {
        return 0;
      }
      if (n >= kMaxLebBytes) {
        ok_ = false;
        return 0;
      }
      if (shift < 64) {
        value |= static_cast<std::uint64_t>(byte & 0x7FU) << shift;
      }
      shift += 7;
      if ((byte & 0x80U) == 0) {
        break;
      }
    }
    if (ok_ && shift < 64 && (byte & 0x40U) != 0) {
      value |= ~std::uint64_t{0} << shift;  // sign-extend
    }
    return static_cast<std::int64_t>(value);
  }

 private:
  const ByteReader& reader_;
  std::uint64_t pos_;
  std::uint64_t end_;
  Endian endian_;
  bool ok_ = true;
};

/// The part of a CIE an FDE needs: how its pointers are encoded and whether it has an
/// augmentation data block (the `z` form).
struct Cie {
  bool valid = false;
  std::uint8_t fde_encoding = kPeAbsptr;
  bool has_augmentation_data = false;
};

/// Skips one encoded value (a personality pointer, say) without decoding it. Returns false for a
/// form whose size this reader does not know.
bool skip_encoded(Cursor& cursor, std::uint8_t encoding, unsigned pointer_size) {
  switch (encoding & kPeFormat) {
    case kPeAbsptr:
      cursor.skip(pointer_size);
      break;
    case kPeUleb128:
      (void)cursor.uleb();
      break;
    case kPeSleb128:
      (void)cursor.sleb();
      break;
    case kPeUdata2:
    case kPeSdata2:
      cursor.skip(2);
      break;
    case kPeUdata4:
    case kPeSdata4:
      cursor.skip(4);
      break;
    case kPeUdata8:
    case kPeSdata8:
      cursor.skip(8);
      break;
    default:
      cursor.fail();
      break;
  }
  return cursor.ok();
}

/// One encoded pointer. `field_address` is the address of the field (section address plus its
/// offset), which pc-relative pointers are relative to. An indirect pointer, or an application
/// other than absolute and pc-relative, is refused: its value is not in this section.
std::optional<std::uint64_t> read_encoded(Cursor& cursor, std::uint8_t encoding,
                                          unsigned pointer_size, std::uint64_t section_address) {
  if (encoding == kPeOmit || (encoding & kPeIndirect) != 0) {
    cursor.fail();
    return std::nullopt;
  }
  const std::uint64_t field_address = section_address + cursor.pos();
  std::uint64_t value = 0;
  switch (encoding & kPeFormat) {
    case kPeAbsptr:
      if (pointer_size != 4 && pointer_size != 8) {
        cursor.fail();
        return std::nullopt;
      }
      value = cursor.unsigned_of(pointer_size);
      break;
    case kPeUleb128:
      value = cursor.uleb();
      break;
    case kPeSleb128:
      value = static_cast<std::uint64_t>(cursor.sleb());
      break;
    case kPeUdata2:
      value = cursor.unsigned_of(2);
      break;
    case kPeUdata4:
      value = cursor.unsigned_of(4);
      break;
    case kPeUdata8:
      value = cursor.unsigned_of(8);
      break;
    case kPeSdata2:
      value = static_cast<std::uint64_t>(static_cast<std::int16_t>(cursor.unsigned_of(2)));
      break;
    case kPeSdata4:
      value = static_cast<std::uint64_t>(static_cast<std::int32_t>(cursor.unsigned_of(4)));
      break;
    case kPeSdata8:
      value = cursor.unsigned_of(8);
      break;
    default:
      cursor.fail();
      return std::nullopt;
  }
  if (!cursor.ok()) {
    return std::nullopt;
  }
  switch (encoding & kPeApplication) {
    case 0:
      break;
    case kPeAppPcrel:
      value += field_address;
      break;
    default:  // textrel, datarel, funcrel and aligned need state this reader does not have
      cursor.fail();
      return std::nullopt;
  }
  return value;
}

/// Reads the CIE body after its id field. Only the augmentation data this reader needs is taken:
/// the FDE pointer encoding (`R`) and whether there is a block at all (`z`). Nothing else is
/// consumed, so an unknown augmentation letter makes the CIE invalid.
Cie parse_cie_body(Cursor& cursor, unsigned pointer_size) {
  Cie cie;
  const std::uint8_t version = cursor.u8();
  std::string augmentation;
  for (std::size_t n = 0; cursor.ok(); ++n) {
    const std::uint8_t letter = cursor.u8();
    if (!cursor.ok()) {
      break;
    }
    if (letter == 0) {
      break;
    }
    if (n >= kMaxAugmentation) {
      cursor.fail();
      break;
    }
    augmentation.push_back(static_cast<char>(letter));
  }
  if (!cursor.ok()) {
    return cie;
  }
  if (augmentation.find("eh") != std::string::npos) {
    cursor.skip(pointer_size);  // the old eh_data pointer
  }
  (void)cursor.uleb();  // code alignment factor
  (void)cursor.sleb();  // data alignment factor
  if (version == 1) {
    (void)cursor.u8();  // return address register, one byte in version 1
  } else {
    (void)cursor.uleb();
  }
  if (!cursor.ok()) {
    return cie;
  }
  if (augmentation.empty() || augmentation[0] != 'z') {
    cie.valid = cursor.ok();  // no augmentation data: the FDE encoding is the default
    return cie;
  }
  cie.has_augmentation_data = true;
  const std::uint64_t length = cursor.uleb();
  if (!cursor.ok() || length > cursor.end() - cursor.pos()) {
    return cie;
  }
  const std::uint64_t data_end = cursor.pos() + length;
  for (std::size_t i = 1; i < augmentation.size() && cursor.ok(); ++i) {
    switch (augmentation[i]) {
      case 'L':  // the LSDA pointer encoding of each FDE: one byte here
        (void)cursor.u8();
        break;
      case 'P': {  // the personality routine: its encoding, then the pointer
        const std::uint8_t encoding = cursor.u8();
        if (cursor.ok()) {
          (void)skip_encoded(cursor, encoding, pointer_size);
        }
        break;
      }
      case 'R':
        cie.fde_encoding = cursor.u8();
        break;
      case 'S':
      case 'B':
        break;  // no data
      default:
        cursor.fail();  // a letter whose data size is unknown
        break;
    }
  }
  if (!cursor.ok() || cursor.pos() > data_end) {
    cie.valid = false;
    return cie;
  }
  cursor.seek(data_end);
  cie.valid = cursor.ok();
  return cie;
}

/// The record header: its length (32- or 64-bit form) and the size of the id field after it.
struct RecordHeader {
  std::uint64_t length = 0;
  std::uint64_t body = 0;   // offset of the id field
  unsigned id_size = 4;     // 4 for the 32-bit form, 8 for the 64-bit form
  bool terminator = false;  // a zero length ends the section
};

std::optional<RecordHeader> read_header(const ByteReader& reader, std::uint64_t offset,
                                        Endian endian) {
  Cursor cursor(reader, offset, reader.size(), endian);
  RecordHeader header;
  const std::uint64_t length32 = cursor.unsigned_of(4);
  if (!cursor.ok()) {
    return std::nullopt;
  }
  if (length32 == 0) {
    header.terminator = true;
    return header;
  }
  if (length32 == 0xffffffffU) {
    header.length = cursor.unsigned_of(8);
    header.id_size = 8;
  } else {
    header.length = length32;
    header.id_size = 4;
  }
  if (!cursor.ok()) {
    return std::nullopt;
  }
  header.body = cursor.pos();
  return header;
}

/// Reads one CIE record at `offset`, caching the result. Returns an invalid CIE when the record
/// there is not a CIE or cannot be read.
class CieCache {
 public:
  CieCache(const ByteReader& reader, Endian endian, unsigned pointer_size)
      : reader_(reader), endian_(endian), pointer_size_(pointer_size) {}

  const Cie& at(std::uint64_t offset) {
    if (const auto found = cache_.find(offset); found != cache_.end()) {
      return found->second;
    }
    Cie cie = load(offset);
    return cache_.emplace(offset, cie).first->second;
  }

 private:
  Cie load(std::uint64_t offset) {
    const auto header = read_header(reader_, offset, endian_);
    if (!header || header->terminator || header->length > reader_.size() - header->body) {
      return Cie{};
    }
    const std::uint64_t end = header->body + header->length;
    Cursor id_cursor(reader_, header->body, end, endian_);
    const std::uint64_t id = id_cursor.unsigned_of(header->id_size);
    if (!id_cursor.ok() || id != 0) {
      return Cie{};  // not a CIE
    }
    Cursor cursor(reader_, id_cursor.pos(), end, endian_);
    return parse_cie_body(cursor, pointer_size_);
  }

  const ByteReader& reader_;
  Endian endian_;
  unsigned pointer_size_;
  std::map<std::uint64_t, Cie> cache_;
};

}  // namespace

Result<EhFrameReadResult> read_eh_frame(std::span<const std::byte> section,
                                        std::uint64_t section_address, unsigned pointer_size,
                                        Endian endian, std::size_t max_records) {
  if (pointer_size != 4 && pointer_size != 8) {
    return make_error<EhFrameReadResult>(Status::InvalidInput, "elf.eh_frame_pointer_size",
                                         "an .eh_frame pointer is 4 or 8 bytes");
  }
  const ByteReader reader(section);
  CieCache cies(reader, endian, pointer_size);
  EhFrameReadResult result;
  std::uint64_t offset = 0;
  while (offset < reader.size()) {
    if (result.records >= max_records) {
      result.truncated = true;
      break;
    }
    const auto header = read_header(reader, offset, endian);
    if (!header) {
      result.truncated = true;  // the length itself runs past the section
      break;
    }
    if (header->terminator) {
      break;
    }
    if (header->length > reader.size() - header->body) {
      result.truncated = true;  // the record runs past the section; nothing after it is aligned
      break;
    }
    const std::uint64_t end = header->body + header->length;
    ++result.records;

    Cursor id_cursor(reader, header->body, end, endian);
    const std::uint64_t id = id_cursor.unsigned_of(header->id_size);
    if (!id_cursor.ok()) {
      ++result.malformed_records;
      offset = end;
      continue;
    }
    if (id == 0) {
      // A CIE. Its record is parsed when an FDE names it, and cached; a CIE that is never
      // named by an FDE needs no reading here.
      (void)cies.at(offset);
      offset = end;
      continue;
    }
    // An FDE: the id is the distance back from the id field to its CIE.
    if (id > header->body) {
      ++result.malformed_records;
      offset = end;
      continue;
    }
    const Cie& cie = cies.at(header->body - id);
    if (!cie.valid) {
      ++result.malformed_records;
      offset = end;
      continue;
    }
    Cursor cursor(reader, id_cursor.pos(), end, endian);
    const auto pc_begin = read_encoded(cursor, cie.fde_encoding, pointer_size, section_address);
    const auto pc_range =
        read_encoded(cursor, static_cast<std::uint8_t>(cie.fde_encoding & kPeFormat), pointer_size,
                     section_address);
    if (!pc_begin || !pc_range) {
      ++result.malformed_records;
      offset = end;
      continue;
    }
    if (cie.has_augmentation_data) {
      const std::uint64_t data_length = cursor.uleb();
      if (!cursor.ok() || data_length > cursor.end() - cursor.pos()) {
        ++result.malformed_records;
        offset = end;
        continue;
      }
    }
    if (*pc_begin != 0 && *pc_range != 0) {
      result.functions.push_back(EhFrameFunction{*pc_begin, *pc_range});
    }
    offset = end;
  }
  return result;
}

Result<EhFrameReadResult> read_eh_frame_of_image(const BinaryImage& image,
                                                 std::span<const std::byte> file) {
  for (const Section& section : image.sections) {
    if (section.name != ".eh_frame" || !section.has_file_data) {
      continue;
    }
    if (section.file_offset > file.size() ||
        section.file_size > file.size() - section.file_offset) {
      return make_error<EhFrameReadResult>(Status::InvalidInput, "elf.eh_frame_bounds",
                                           ".eh_frame lies outside the file");
    }
    const auto bytes = file.subspan(section.file_offset, section.file_size);
    return read_eh_frame(bytes, section.address, image.bits == 32 ? 4U : 8U, image.endian);
  }
  return EhFrameReadResult{};
}

}  // namespace donkey
