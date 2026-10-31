// Bounded DWARF 2-5 reader: functions, parameters, global variables and
// types from .debug_info, with source files from .debug_line headers.
//
// Every read goes through Cursor, which never reads outside its section;
// a malformed unit records a diagnostic and stops that unit only.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>
#include <unordered_map>

#include "donkey/binary/debug_info.h"

namespace donkey {
namespace {

// ---- tags, attributes and forms used here ------------------------------

constexpr std::uint16_t kTagArrayType = 0x01;
constexpr std::uint16_t kTagClassType = 0x02;
constexpr std::uint16_t kTagEnumerationType = 0x04;
constexpr std::uint16_t kTagFormalParameter = 0x05;
constexpr std::uint16_t kTagMember = 0x0d;
constexpr std::uint16_t kTagPointerType = 0x0f;
constexpr std::uint16_t kTagReferenceType = 0x10;
constexpr std::uint16_t kTagStructureType = 0x13;
constexpr std::uint16_t kTagSubroutineType = 0x15;
constexpr std::uint16_t kTagTypedef = 0x16;
constexpr std::uint16_t kTagUnionType = 0x17;
constexpr std::uint16_t kTagUnspecifiedParameters = 0x18;
constexpr std::uint16_t kTagSubrangeType = 0x21;
constexpr std::uint16_t kTagBaseType = 0x24;
constexpr std::uint16_t kTagConstType = 0x26;
constexpr std::uint16_t kTagSubprogram = 0x2e;
constexpr std::uint16_t kTagVariable = 0x34;
constexpr std::uint16_t kTagVolatileType = 0x35;
constexpr std::uint16_t kTagRestrictType = 0x37;
constexpr std::uint16_t kTagUnspecifiedType = 0x3b;
constexpr std::uint16_t kTagRvalueReferenceType = 0x42;

constexpr std::uint16_t kAtLocation = 0x02;
constexpr std::uint16_t kAtName = 0x03;
constexpr std::uint16_t kAtByteSize = 0x0b;
constexpr std::uint16_t kAtStmtList = 0x10;
constexpr std::uint16_t kAtLowPc = 0x11;
constexpr std::uint16_t kAtHighPc = 0x12;
constexpr std::uint16_t kAtProducer = 0x25;
constexpr std::uint16_t kAtUpperBound = 0x2f;
constexpr std::uint16_t kAtAbstractOrigin = 0x31;
constexpr std::uint16_t kAtCount = 0x37;
constexpr std::uint16_t kAtDataMemberLocation = 0x38;
constexpr std::uint16_t kAtDeclFile = 0x3a;
constexpr std::uint16_t kAtDeclLine = 0x3b;
constexpr std::uint16_t kAtDeclaration = 0x3c;
constexpr std::uint16_t kAtExternal = 0x3f;
constexpr std::uint16_t kAtSpecification = 0x47;
constexpr std::uint16_t kAtType = 0x49;
constexpr std::uint16_t kAtLinkageName = 0x6e;
constexpr std::uint16_t kAtStrOffsetsBase = 0x72;
constexpr std::uint16_t kAtAddrBase = 0x73;
constexpr std::uint16_t kAtMipsLinkageName = 0x2007;

enum Form : std::uint16_t {
  kFormAddr = 0x01,
  kFormBlock2 = 0x03,
  kFormBlock4 = 0x04,
  kFormData2 = 0x05,
  kFormData4 = 0x06,
  kFormData8 = 0x07,
  kFormString = 0x08,
  kFormBlock = 0x09,
  kFormBlock1 = 0x0a,
  kFormData1 = 0x0b,
  kFormFlag = 0x0c,
  kFormSdata = 0x0d,
  kFormStrp = 0x0e,
  kFormUdata = 0x0f,
  kFormRefAddr = 0x10,
  kFormRef1 = 0x11,
  kFormRef2 = 0x12,
  kFormRef4 = 0x13,
  kFormRef8 = 0x14,
  kFormRefUdata = 0x15,
  kFormIndirect = 0x16,
  kFormSecOffset = 0x17,
  kFormExprloc = 0x18,
  kFormFlagPresent = 0x19,
  kFormStrx = 0x1a,
  kFormAddrx = 0x1b,
  kFormRefSup4 = 0x1c,
  kFormStrpSup = 0x1d,
  kFormData16 = 0x1e,
  kFormLineStrp = 0x1f,
  kFormRefSig8 = 0x20,
  kFormImplicitConst = 0x21,
  kFormLoclistx = 0x22,
  kFormRnglistx = 0x23,
  kFormRefSup8 = 0x24,
  kFormStrx1 = 0x25,
  kFormStrx2 = 0x26,
  kFormStrx3 = 0x27,
  kFormStrx4 = 0x28,
  kFormAddrx1 = 0x29,
  kFormAddrx2 = 0x2a,
  kFormAddrx3 = 0x2b,
  kFormAddrx4 = 0x2c,
  kFormGnuAddrIndex = 0x1f01,
  kFormGnuStrIndex = 0x1f02,
  kFormGnuRefAlt = 0x1f20,
  kFormGnuStrpAlt = 0x1f21,
};

constexpr std::size_t kMaxDepth = 256;
constexpr std::size_t kMaxAttributesPerAbbrev = 256;
constexpr std::size_t kMaxAbbrevsPerTable = 200000;
constexpr std::size_t kMaxNameLength = 1024;
constexpr std::size_t kMaxFilesPerLineTable = 100000;

using Bytes = std::span<const std::byte>;

/// Bounded little/big-endian reader over one section.
class Cursor {
 public:
  Cursor() = default;
  Cursor(Bytes bytes, bool big_endian) : bytes_(bytes), big_(big_endian) {}

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] std::uint64_t offset() const noexcept { return offset_; }
  [[nodiscard]] std::uint64_t size() const noexcept { return bytes_.size(); }
  [[nodiscard]] bool at_end() const noexcept { return !ok_ || offset_ >= bytes_.size(); }
  void seek(std::uint64_t offset) {
    if (offset > bytes_.size()) {
      ok_ = false;
      return;
    }
    offset_ = offset;
  }
  void skip(std::uint64_t count) {
    if (!ok_ || count > bytes_.size() - offset_) {
      ok_ = false;
      return;
    }
    offset_ += count;
  }
  std::uint64_t unsigned_bytes(std::size_t count) {
    if (!ok_ || count > 8 || count > bytes_.size() - offset_) {
      ok_ = false;
      return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < count; ++i) {
      const auto byte = static_cast<std::uint64_t>(bytes_[offset_ + i]);
      if (big_) {
        value = (value << 8U) | byte;
      } else {
        value |= byte << (8U * i);
      }
    }
    offset_ += count;
    return value;
  }
  std::uint8_t u8() { return static_cast<std::uint8_t>(unsigned_bytes(1)); }
  std::uint16_t u16() { return static_cast<std::uint16_t>(unsigned_bytes(2)); }
  std::uint32_t u32() { return static_cast<std::uint32_t>(unsigned_bytes(4)); }
  std::uint64_t u64() { return unsigned_bytes(8); }
  std::uint64_t uleb() {
    std::uint64_t value = 0;
    unsigned shift = 0;
    while (ok_) {
      const std::uint8_t byte = u8();
      if (shift < 64) {
        value |= static_cast<std::uint64_t>(byte & 0x7FU) << shift;
      }
      if ((byte & 0x80U) == 0) {
        return value;
      }
      shift += 7;
      if (shift > 70) {  // longer than any 64-bit value: malformed
        ok_ = false;
      }
    }
    return 0;
  }
  std::int64_t sleb() {
    std::int64_t value = 0;
    unsigned shift = 0;
    std::uint8_t byte = 0;
    do {
      byte = u8();
      if (!ok_) {
        return 0;
      }
      if (shift < 64) {
        value |= static_cast<std::int64_t>(static_cast<std::uint64_t>(byte & 0x7FU) << shift);
      }
      shift += 7;
      if (shift > 70) {
        ok_ = false;
        return 0;
      }
    } while ((byte & 0x80U) != 0);
    if (shift < 64 && (byte & 0x40U) != 0) {
      value |= static_cast<std::int64_t>(~0ULL << shift);
    }
    return value;
  }
  std::string_view cstr() {
    if (!ok_) {
      return {};
    }
    const std::uint64_t start = offset_;
    while (offset_ < bytes_.size() && bytes_[offset_] != std::byte{0}) {
      ++offset_;
    }
    if (offset_ >= bytes_.size()) {
      ok_ = false;
      return {};
    }
    const std::string_view text(reinterpret_cast<const char*>(bytes_.data() + start),
                                static_cast<std::size_t>(offset_ - start));
    ++offset_;  // NUL
    return text;
  }
  Bytes block(std::uint64_t length) {
    if (!ok_ || length > bytes_.size() - offset_) {
      ok_ = false;
      return {};
    }
    const Bytes out =
        bytes_.subspan(static_cast<std::size_t>(offset_), static_cast<std::size_t>(length));
    offset_ += length;
    return out;
  }

 private:
  Bytes bytes_;
  std::uint64_t offset_ = 0;
  bool big_ = false;
  bool ok_ = true;
};

std::string bounded_name(std::string_view text) {
  std::string out(text.substr(0, kMaxNameLength));
  for (char& c : out) {
    if (static_cast<unsigned char>(c) < 0x20) {
      c = '?';  // control characters never reach a UI or a JSON writer raw
    }
  }
  return out;
}

struct AbbrevAttr {
  std::uint16_t attribute = 0;
  std::uint16_t form = 0;
  std::int64_t implicit_const = 0;
};

struct Abbrev {
  std::uint16_t tag = 0;
  bool has_children = false;
  std::vector<AbbrevAttr> attributes;
};

using AbbrevTable = std::unordered_map<std::uint64_t, Abbrev>;

/// A decoded attribute value; strings and addresses given by index are
/// resolved later through the unit's bases.
struct Value {
  std::uint16_t form = 0;
  std::uint64_t u = 0;
  std::int64_t s = 0;
  std::string_view str;
  Bytes block;
  bool is_ref = false;  ///< u is a .debug_info offset (already made absolute)
};

struct Sections {
  Bytes info, abbrev, str, line_str, str_offsets, addr, line;
  bool big_endian = false;
};

struct Unit {
  std::uint64_t offset = 0;
  std::uint16_t version = 0;
  std::uint8_t address_size = 8;
  std::uint8_t offset_size = 4;
  std::uint64_t str_offsets_base = 0;
  bool has_str_offsets_base = false;
  std::uint64_t addr_base = 0;
  bool has_addr_base = false;
  std::vector<std::string> files;  ///< from the line table header
};

class Reader {
 public:
  Reader(const Sections& sections, const DebugInfoOptions& options, DebugInfo& out)
      : s_(sections), options_(options), out_(out) {}

  void run() {
    Cursor info(s_.info, s_.big_endian);
    while (!info.at_end()) {
      if (options_.cancellation_token.is_cancelled()) {
        diag(Status::Cancelled, "dwarf.cancelled", "reading debug information was cancelled",
             info.offset());
        break;
      }
      // PE sections are padded with zeros to the file alignment.
      if (only_zeros_from(info.offset())) {
        break;
      }
      if (!read_unit(info)) {
        break;
      }
    }
    // Units read before a stop are kept: resolve and sort them either way.
    resolve_references();
  }

  [[nodiscard]] bool only_zeros_from(std::uint64_t offset) const {
    for (std::uint64_t i = offset; i < s_.info.size(); ++i) {
      if (s_.info[static_cast<std::size_t>(i)] != std::byte{0}) {
        return false;
      }
    }
    return true;
  }

 private:
  void diag(Status status, std::string code, std::string message, std::uint64_t offset) {
    out_.partial = true;
    if (out_.diagnostics.size() < 64) {
      out_.diagnostics.push_back(
          Diagnostic::make(status, std::move(code), std::move(message), offset));
    }
  }

  const AbbrevTable* abbrevs_at(std::uint64_t offset) {
    if (auto it = abbrev_cache_.find(offset); it != abbrev_cache_.end()) {
      return &it->second;
    }
    Cursor c(s_.abbrev, s_.big_endian);
    c.seek(offset);
    AbbrevTable table;
    while (c.ok() && !c.at_end()) {
      const std::uint64_t code = c.uleb();
      if (code == 0 || !c.ok()) {
        break;
      }
      Abbrev abbrev;
      abbrev.tag = static_cast<std::uint16_t>(c.uleb());
      abbrev.has_children = c.u8() != 0;
      while (c.ok()) {
        AbbrevAttr attr;
        attr.attribute = static_cast<std::uint16_t>(c.uleb());
        attr.form = static_cast<std::uint16_t>(c.uleb());
        if (attr.attribute == 0 && attr.form == 0) {
          break;
        }
        if (attr.form == kFormImplicitConst) {
          attr.implicit_const = c.sleb();
        }
        if (abbrev.attributes.size() >= kMaxAttributesPerAbbrev) {
          return nullptr;
        }
        abbrev.attributes.push_back(attr);
      }
      if (table.size() >= kMaxAbbrevsPerTable) {
        return nullptr;
      }
      table.emplace(code, std::move(abbrev));
    }
    if (!c.ok()) {
      return nullptr;
    }
    return &abbrev_cache_.emplace(offset, std::move(table)).first->second;
  }

  /// Decode one attribute value. False on a malformed or unknown form.
  bool read_value(Cursor& c, const Unit& unit, std::uint16_t form, std::int64_t implicit, Value& v,
                  int indirection = 0) {
    v = Value{};
    v.form = form;
    switch (form) {
      case kFormAddr:
        v.u = c.unsigned_bytes(unit.address_size);
        break;
      case kFormData1:
      case kFormRef1:
      case kFormFlag:
      case kFormStrx1:
      case kFormAddrx1:
        v.u = c.u8();
        break;
      case kFormData2:
      case kFormRef2:
      case kFormStrx2:
      case kFormAddrx2:
        v.u = c.u16();
        break;
      case kFormStrx3:
      case kFormAddrx3:
        v.u = c.unsigned_bytes(3);
        break;
      case kFormData4:
      case kFormRef4:
      case kFormRefSup4:
      case kFormStrx4:
      case kFormAddrx4:
        v.u = c.u32();
        break;
      case kFormData8:
      case kFormRef8:
      case kFormRefSig8:
      case kFormRefSup8:
        v.u = c.u64();
        break;
      case kFormData16:
        v.block = c.block(16);
        break;
      case kFormSdata:
        v.s = c.sleb();
        v.u = static_cast<std::uint64_t>(v.s);
        break;
      case kFormUdata:
      case kFormRefUdata:
      case kFormStrx:
      case kFormAddrx:
      case kFormLoclistx:
      case kFormRnglistx:
      case kFormGnuAddrIndex:
      case kFormGnuStrIndex:
        v.u = c.uleb();
        break;
      case kFormString:
        v.str = c.cstr();
        break;
      case kFormStrp:
      case kFormLineStrp:
      case kFormSecOffset:
      case kFormStrpSup:
      case kFormGnuRefAlt:
      case kFormGnuStrpAlt:
        v.u = c.unsigned_bytes(unit.offset_size);
        break;
      case kFormRefAddr:
        v.u = c.unsigned_bytes(unit.version <= 2 ? unit.address_size : unit.offset_size);
        break;
      case kFormBlock1:
        v.block = c.block(c.u8());
        break;
      case kFormBlock2:
        v.block = c.block(c.u16());
        break;
      case kFormBlock4:
        v.block = c.block(c.u32());
        break;
      case kFormBlock:
      case kFormExprloc:
        v.block = c.block(c.uleb());
        break;
      case kFormFlagPresent:
        v.u = 1;
        break;
      case kFormImplicitConst:
        v.s = implicit;
        v.u = static_cast<std::uint64_t>(implicit);
        break;
      case kFormIndirect: {
        if (indirection > 0) {
          return false;
        }
        const auto real = static_cast<std::uint16_t>(c.uleb());
        return c.ok() && read_value(c, unit, real, implicit, v, indirection + 1);
      }
      default:
        return false;
    }
    if (form == kFormRef1 || form == kFormRef2 || form == kFormRef4 || form == kFormRef8 ||
        form == kFormRefUdata) {
      v.u += unit.offset;  // unit-relative -> .debug_info offset
      v.is_ref = true;
    } else if (form == kFormRefAddr) {
      v.is_ref = true;
    }
    return c.ok();
  }

  std::string string_of(const Value& v, const Unit& unit) const {
    auto from_section = [](Bytes section, std::uint64_t offset) -> std::string {
      if (offset >= section.size()) {
        return {};
      }
      Cursor c(section, false);
      c.seek(offset);
      return bounded_name(c.cstr());
    };
    switch (v.form) {
      case kFormString:
        return bounded_name(v.str);
      case kFormStrp:
        return from_section(s_.str, v.u);
      case kFormLineStrp:
        return from_section(s_.line_str, v.u);
      case kFormStrx:
      case kFormStrx1:
      case kFormStrx2:
      case kFormStrx3:
      case kFormStrx4:
      case kFormGnuStrIndex: {
        // DWARF 5 default: the table header is 8 (32-bit) or 16 (64-bit) bytes.
        const std::uint64_t base =
            unit.has_str_offsets_base ? unit.str_offsets_base : (unit.offset_size == 8 ? 16U : 8U);
        Cursor c(s_.str_offsets, s_.big_endian);
        if (v.u > (s_.str_offsets.size() / unit.offset_size)) {
          return {};
        }
        c.seek(base + v.u * unit.offset_size);
        const std::uint64_t offset = c.unsigned_bytes(unit.offset_size);
        return c.ok() ? from_section(s_.str, offset) : std::string();
      }
      default:
        return {};
    }
  }

  std::optional<std::uint64_t> address_of(const Value& v, const Unit& unit) const {
    switch (v.form) {
      case kFormAddr:
        return v.u;
      case kFormAddrx:
      case kFormAddrx1:
      case kFormAddrx2:
      case kFormAddrx3:
      case kFormAddrx4:
      case kFormGnuAddrIndex: {
        const std::uint64_t base = unit.has_addr_base ? unit.addr_base : 8U;
        if (v.u > s_.addr.size() / unit.address_size) {
          return std::nullopt;
        }
        Cursor c(s_.addr, s_.big_endian);
        c.seek(base + v.u * unit.address_size);
        const std::uint64_t address = c.unsigned_bytes(unit.address_size);
        if (!c.ok()) {
          return std::nullopt;
        }
        return address;
      }
      default:
        return std::nullopt;
    }
  }

  static bool is_constant_form(std::uint16_t form) {
    return form == kFormData1 || form == kFormData2 || form == kFormData4 || form == kFormData8 ||
           form == kFormUdata || form == kFormSdata || form == kFormImplicitConst;
  }

  /// DW_OP_addr / DW_OP_addrx at the start of a location expression.
  std::optional<std::uint64_t> static_location(const Value& v, const Unit& unit) const {
    if (v.block.empty()) {
      return std::nullopt;
    }
    Cursor c(v.block, s_.big_endian);
    const std::uint8_t op = c.u8();
    if (op == 0x03) {  // DW_OP_addr
      const std::uint64_t address = c.unsigned_bytes(unit.address_size);
      return c.ok() && c.at_end() ? std::optional<std::uint64_t>(address) : std::nullopt;
    }
    if (op == 0xa1 || op == 0xfb) {  // DW_OP_addrx, DW_OP_GNU_addr_index
      Value index;
      index.form = kFormAddrx;
      index.u = c.uleb();
      return c.ok() && c.at_end() ? address_of(index, unit) : std::nullopt;
    }
    return std::nullopt;
  }

  void read_line_files(Unit& unit, std::uint64_t offset, const std::string& comp_dir,
                       const std::string& unit_name) {
    Cursor c(s_.line, s_.big_endian);
    c.seek(offset);
    std::uint64_t length = c.u32();
    std::uint8_t offset_size = 4;
    if (length == 0xffffffffULL) {
      length = c.u64();
      offset_size = 8;
    }
    const std::uint16_t version = c.u16();
    if (!c.ok() || version < 2 || version > 5) {
      return;
    }
    Unit line_unit = unit;
    line_unit.offset_size = offset_size;
    if (version >= 5) {
      line_unit.address_size = c.u8();
      c.u8();  // segment selector size
    }
    c.unsigned_bytes(offset_size);  // header_length
    c.u8();                         // minimum_instruction_length
    if (version >= 4) {
      c.u8();  // maximum_operations_per_instruction
    }
    c.u8();  // default_is_stmt
    c.u8();  // line_base
    c.u8();  // line_range
    const std::uint8_t opcode_base = c.u8();
    for (int i = 1; i < opcode_base && c.ok(); ++i) {
      c.u8();
    }
    std::vector<std::string> directories;
    std::vector<std::string> files;
    if (version < 5) {
      directories.push_back(comp_dir);
      while (c.ok() && directories.size() < kMaxFilesPerLineTable) {
        const std::string_view dir = c.cstr();
        if (dir.empty()) {
          break;
        }
        directories.emplace_back(bounded_name(dir));
      }
      files.push_back(unit_name);  // index 0 is unused before DWARF 5
      while (c.ok() && files.size() < kMaxFilesPerLineTable) {
        const std::string_view name = c.cstr();
        if (name.empty()) {
          break;
        }
        const std::uint64_t dir = c.uleb();
        c.uleb();  // mtime
        c.uleb();  // length
        std::string path = bounded_name(name);
        if (!path.empty() && path.front() != '/' && dir < directories.size() &&
            !directories[dir].empty()) {
          path = directories[dir] + "/" + path;
        }
        files.push_back(std::move(path));
      }
    } else {
      auto read_entries = [&](std::vector<std::string>& names, std::vector<std::uint64_t>* dirs) {
        const std::uint8_t format_count = c.u8();
        std::vector<std::pair<std::uint64_t, std::uint16_t>> formats;
        for (int i = 0; i < format_count && c.ok(); ++i) {
          const std::uint64_t content = c.uleb();
          const auto form = static_cast<std::uint16_t>(c.uleb());
          formats.emplace_back(content, form);
        }
        const std::uint64_t count = c.uleb();
        if (count > kMaxFilesPerLineTable) {
          return false;
        }
        for (std::uint64_t i = 0; i < count && c.ok(); ++i) {
          std::string path;
          std::uint64_t dir = 0;
          for (const auto& [content, form] : formats) {
            Value v;
            if (!read_value(c, line_unit, form, 0, v)) {
              return false;
            }
            if (content == 1) {  // DW_LNCT_path
              path = string_of(v, unit);
            } else if (content == 2) {  // DW_LNCT_directory_index
              dir = v.u;
            }
          }
          names.push_back(std::move(path));
          if (dirs != nullptr) {
            dirs->push_back(dir);
          }
        }
        return c.ok();
      };
      std::vector<std::uint64_t> file_dirs;
      if (!read_entries(directories, nullptr) || !read_entries(files, &file_dirs)) {
        return;
      }
      for (std::size_t i = 0; i < files.size(); ++i) {
        if (!files[i].empty() && files[i].front() != '/' && file_dirs[i] < directories.size() &&
            !directories[file_dirs[i]].empty()) {
          files[i] = directories[file_dirs[i]] + "/" + files[i];
        }
      }
    }
    (void)length;
    unit.files = std::move(files);
  }

  struct Entry {
    std::uint64_t offset = 0;
    std::uint16_t tag = 0;
    std::string name;
    std::string linkage_name;
    std::optional<std::uint64_t> low_pc;
    std::optional<Value> high_pc;
    std::uint64_t type = 0;
    std::uint64_t byte_size = 0;
    std::uint64_t count = 0;
    std::optional<std::int64_t> upper_bound;
    std::uint64_t member_offset = 0;
    std::optional<std::uint64_t> location;
    std::uint64_t specification = 0;
    std::uint64_t abstract_origin = 0;
    std::uint64_t decl_file = 0;
    bool has_decl_file = false;
    std::uint32_t decl_line = 0;
    bool external = false;
    bool declaration = false;
  };

  bool read_unit(Cursor& info) {
    Unit unit;
    unit.offset = info.offset();
    std::uint64_t length = info.u32();
    if (length == 0xffffffffULL) {
      length = info.u64();
      unit.offset_size = 8;
    } else if (length >= 0xfffffff0ULL) {
      diag(Status::InvalidInput, "dwarf.bad_unit_length", "reserved unit length", unit.offset);
      return false;
    }
    const std::uint64_t contents = info.offset();
    if (!info.ok() || length > info.size() - contents) {
      diag(Status::InvalidInput, "dwarf.unit_out_of_bounds",
           "compile unit extends past .debug_info", unit.offset);
      return false;
    }
    const std::uint64_t unit_end = contents + length;
    unit.version = info.u16();
    std::uint64_t abbrev_offset = 0;
    if (unit.version >= 5) {
      const std::uint8_t unit_type = info.u8();
      unit.address_size = info.u8();
      abbrev_offset = info.unsigned_bytes(unit.offset_size);
      if (unit_type == 2 || unit_type == 6) {  // type units: signature + type offset
        info.skip(8 + unit.offset_size);
      } else if (unit_type == 4 || unit_type == 5) {  // skeleton / split: dwo id
        info.skip(8);
        if (unit_type == 4) {
          diag(Status::Unsupported, "dwarf.split_unsupported",
               "split DWARF: the entries are in a .dwo file, which is not read", unit.offset);
        }
      }
    } else if (unit.version >= 2) {
      abbrev_offset = info.unsigned_bytes(unit.offset_size);
      unit.address_size = info.u8();
    }
    if (!info.ok() || unit.version < 2 || unit.version > 5 ||
        (unit.address_size != 4 && unit.address_size != 8 && unit.address_size != 2)) {
      diag(Status::Unsupported, "dwarf.unsupported_unit",
           "unsupported DWARF version or address size", unit.offset);
      info.seek(unit_end);
      return info.ok();
    }
    const AbbrevTable* abbrevs = abbrevs_at(abbrev_offset);
    if (abbrevs == nullptr) {
      diag(Status::InvalidInput, "dwarf.bad_abbrev", "malformed abbreviation table", abbrev_offset);
      info.seek(unit_end);
      return info.ok();
    }
    ++out_.compile_units;
    out_.min_version =
        out_.min_version == 0 ? unit.version : std::min(out_.min_version, unit.version);
    out_.max_version = std::max(out_.max_version, unit.version);

    Cursor c(s_.info.first(static_cast<std::size_t>(unit_end)), s_.big_endian);
    c.seek(info.offset());
    std::vector<std::uint64_t> parents;  // DIE offsets of open entries with children
    std::vector<std::uint16_t> parent_tags;
    std::size_t depth = 0;
    bool first = true;
    std::string comp_dir;
    std::string unit_name;

    while (c.ok() && !c.at_end()) {
      const std::uint64_t die_offset = c.offset();
      const std::uint64_t code = c.uleb();
      if (!c.ok()) {
        break;
      }
      if (code == 0) {
        if (depth > 0) {
          --depth;
          parents.pop_back();
          parent_tags.pop_back();
        }
        continue;
      }
      if (++entries_ > options_.max_entries) {
        diag(Status::ResourceLimit, "dwarf.entry_limit", "too many debugging entries", die_offset);
        return false;
      }
      const auto it = abbrevs->find(code);
      if (it == abbrevs->end()) {
        diag(Status::InvalidInput, "dwarf.unknown_abbrev", "entry uses an undefined abbreviation",
             die_offset);
        break;
      }
      const Abbrev& abbrev = it->second;
      Entry e;
      e.offset = die_offset;
      e.tag = abbrev.tag;
      std::vector<std::pair<AbbrevAttr, Value>> deferred;  // CU strings before their base
      bool bad = false;
      for (const AbbrevAttr& attr : abbrev.attributes) {
        Value v;
        if (!read_value(c, unit, attr.form, attr.implicit_const, v)) {
          bad = true;
          break;
        }
        if (first) {
          deferred.emplace_back(attr, v);
          if (attr.attribute == kAtStrOffsetsBase) {
            unit.str_offsets_base = v.u;
            unit.has_str_offsets_base = true;
          } else if (attr.attribute == kAtAddrBase) {
            unit.addr_base = v.u;
            unit.has_addr_base = true;
          }
          continue;
        }
        apply(e, attr.attribute, v, unit);
      }
      if (bad) {
        diag(Status::InvalidInput, "dwarf.bad_attribute", "malformed or unsupported attribute form",
             die_offset);
        break;
      }
      if (first) {
        first = false;
        std::uint64_t stmt_list = 0;
        bool has_lines = false;
        for (const auto& [attr, v] : deferred) {
          apply(e, attr.attribute, v, unit);
          if (attr.attribute == 0x1b) {  // DW_AT_comp_dir
            comp_dir = string_of(v, unit);
          } else if (attr.attribute == kAtStmtList) {
            stmt_list = v.u;
            has_lines = true;
          } else if (attr.attribute == kAtProducer) {
            const std::string producer = string_of(v, unit);
            if (!producer.empty() && out_.producers.size() < 32 &&
                std::find(out_.producers.begin(), out_.producers.end(), producer) ==
                    out_.producers.end()) {
              out_.producers.push_back(producer);
            }
          }
        }
        unit_name = e.name;
        if (has_lines) {
          read_line_files(unit, stmt_list, comp_dir, unit_name);
        }
      }

      const std::uint16_t parent_tag = parent_tags.empty() ? 0 : parent_tags.back();
      const std::uint64_t parent = parents.empty() ? 0 : parents.back();
      record(e, unit, parent_tag, parent);

      if (abbrev.has_children) {
        if (++depth > kMaxDepth) {
          diag(Status::ResourceLimit, "dwarf.too_deep", "entries nested too deeply", die_offset);
          break;
        }
        parents.push_back(die_offset);
        parent_tags.push_back(e.tag);
      }
    }
    if (!c.ok()) {
      diag(Status::InvalidInput, "dwarf.truncated_unit", "compile unit ends inside an entry",
           unit.offset);
    }
    info.seek(unit_end);
    return info.ok();
  }

  void apply(Entry& e, std::uint16_t attribute, const Value& v, const Unit& unit) {
    switch (attribute) {
      case kAtName:
        e.name = string_of(v, unit);
        break;
      case kAtLinkageName:
      case kAtMipsLinkageName:
        e.linkage_name = string_of(v, unit);
        break;
      case kAtLowPc:
        e.low_pc = address_of(v, unit);
        break;
      case kAtHighPc:
        e.high_pc = v;
        break;
      case kAtType:
        if (v.is_ref) {
          e.type = v.u;
        }
        break;
      case kAtByteSize:
        if (is_constant_form(v.form)) {
          e.byte_size = v.u;
        }
        break;
      case kAtCount:
        if (is_constant_form(v.form)) {
          e.count = v.u;
        }
        break;
      case kAtUpperBound:
        if (is_constant_form(v.form)) {
          e.upper_bound = v.form == kFormSdata || v.form == kFormImplicitConst
                              ? v.s
                              : static_cast<std::int64_t>(v.u);
        }
        break;
      case kAtDataMemberLocation:
        if (is_constant_form(v.form)) {
          e.member_offset = v.u;
        } else if (!v.block.empty()) {
          Cursor c(v.block, s_.big_endian);
          if (c.u8() == 0x23) {  // DW_OP_plus_uconst
            e.member_offset = c.uleb();
          }
        }
        break;
      case kAtLocation:
        e.location = static_location(v, unit);
        break;
      case kAtSpecification:
        if (v.is_ref) {
          e.specification = v.u;
        }
        break;
      case kAtAbstractOrigin:
        if (v.is_ref) {
          e.abstract_origin = v.u;
        }
        break;
      case kAtDeclFile:
        e.decl_file = v.u;
        e.has_decl_file = true;
        break;
      case kAtDeclLine:
        e.decl_line = static_cast<std::uint32_t>(v.u);
        break;
      case kAtExternal:
        e.external = v.u != 0;
        break;
      case kAtDeclaration:
        e.declaration = v.u != 0;
        break;
      default:
        break;
    }
  }

  DebugProvenance provenance(const Entry& e, const Unit& unit) const {
    return DebugProvenance{"DWARF", unit.version, unit.offset, e.offset};
  }

  void record(const Entry& e, const Unit& unit, std::uint16_t parent_tag, std::uint64_t parent) {
    if (!e.name.empty()) {
      names_[e.offset] = e.name;
    }
    if (!e.linkage_name.empty()) {
      linkage_[e.offset] = e.linkage_name;
    }
    if (e.specification != 0) {
      links_[e.offset] = e.specification;
    } else if (e.abstract_origin != 0) {
      links_[e.offset] = e.abstract_origin;
    }
    if (e.type != 0) {
      die_types_[e.offset] = e.type;
    }
    const std::string file = e.has_decl_file && e.decl_file < unit.files.size()
                                 ? unit.files[e.decl_file]
                                 : std::string();
    if (!file.empty()) {
      sources_[e.offset] = {file, e.decl_line};
    }

    switch (e.tag) {
      case kTagSubprogram: {
        if (!e.low_pc.has_value() || e.declaration) {
          return;  // a declaration, or code given by ranges (not read yet)
        }
        if (out_.functions.size() >= options_.max_functions) {
          diag(Status::ResourceLimit, "dwarf.function_limit", "too many functions", e.offset);
          return;
        }
        DebugFunction f;
        f.address = *e.low_pc;
        if (e.high_pc.has_value()) {
          if (e.high_pc->form == kFormAddr || e.high_pc->form == kFormAddrx ||
              (e.high_pc->form >= kFormAddrx1 && e.high_pc->form <= kFormAddrx4)) {
            const auto end = address_of(*e.high_pc, unit);
            f.size = end.has_value() && *end > f.address ? *end - f.address : 0;
          } else {
            f.size = e.high_pc->u;
          }
        }
        f.name = e.name;
        f.linkage_name = e.linkage_name;
        f.return_type = e.type;
        f.external = e.external;
        f.file = file;
        f.line = e.decl_line;
        f.provenance = provenance(e, unit);
        function_index_[e.offset] = out_.functions.size();
        out_.functions.push_back(std::move(f));
        return;
      }
      case kTagFormalParameter:
        if (parent_tag == kTagSubprogram) {
          if (auto it = function_index_.find(parent); it != function_index_.end()) {
            out_.functions[it->second].parameters.push_back(DebugParameter{e.name, e.type});
            pending_parameters_.emplace_back(
                it->second, out_.functions[it->second].parameters.size() - 1, e.offset);
          }
        } else if (parent_tag == kTagSubroutineType) {
          if (auto it = out_.types.find(parent); it != out_.types.end()) {
            it->second.members.push_back(DebugMember{"", e.type, 0});
          }
        }
        return;
      case kTagUnspecifiedParameters:
        if (parent_tag == kTagSubprogram) {
          if (auto it = function_index_.find(parent); it != function_index_.end()) {
            out_.functions[it->second].variadic = true;
          }
        }
        return;
      case kTagVariable:
        if (e.location.has_value() && !e.declaration) {
          DebugVariable var;
          var.address = *e.location;
          var.name = e.name;
          var.type = e.type;
          var.file = file;
          var.line = e.decl_line;
          var.provenance = provenance(e, unit);
          variable_links_.emplace_back(out_.variables.size(), e.specification);
          out_.variables.push_back(std::move(var));
        }
        return;
      case kTagMember:
        if (auto it = out_.types.find(parent); it != out_.types.end()) {
          it->second.members.push_back(DebugMember{e.name, e.type, e.member_offset});
        }
        return;
      case kTagSubrangeType:
        if (auto it = out_.types.find(parent); it != out_.types.end() &&
                                               it->second.kind == DebugTypeKind::Array &&
                                               it->second.element_count == 0) {
          if (e.count != 0) {
            it->second.element_count = e.count;
          } else if (e.upper_bound.has_value() && *e.upper_bound >= 0) {
            it->second.element_count = static_cast<std::uint64_t>(*e.upper_bound) + 1;
          }
        }
        return;
      default:
        break;
    }

    DebugTypeKind kind = DebugTypeKind::Unspecified;
    switch (e.tag) {
      case kTagBaseType:
        kind = DebugTypeKind::Base;
        break;
      case kTagPointerType:
        kind = DebugTypeKind::Pointer;
        break;
      case kTagReferenceType:
      case kTagRvalueReferenceType:
        kind = DebugTypeKind::Reference;
        break;
      case kTagConstType:
        kind = DebugTypeKind::Const;
        break;
      case kTagVolatileType:
        kind = DebugTypeKind::Volatile;
        break;
      case kTagRestrictType:
        kind = DebugTypeKind::Restrict;
        break;
      case kTagTypedef:
        kind = DebugTypeKind::Typedef;
        break;
      case kTagStructureType:
        kind = DebugTypeKind::Struct;
        break;
      case kTagUnionType:
        kind = DebugTypeKind::Union;
        break;
      case kTagClassType:
        kind = DebugTypeKind::Class;
        break;
      case kTagEnumerationType:
        kind = DebugTypeKind::Enum;
        break;
      case kTagArrayType:
        kind = DebugTypeKind::Array;
        break;
      case kTagSubroutineType:
        kind = DebugTypeKind::Function;
        break;
      case kTagUnspecifiedType:
        kind = DebugTypeKind::Unspecified;
        break;
      default:
        return;
    }
    if (out_.types.size() >= options_.max_types) {
      diag(Status::ResourceLimit, "dwarf.type_limit", "too many types", e.offset);
      return;
    }
    DebugType type;
    type.kind = kind;
    type.name = e.name;
    type.byte_size = e.byte_size;
    type.target = e.type;
    type.provenance = provenance(e, unit);
    out_.types.emplace(e.offset, std::move(type));
  }

  /// Follow DW_AT_specification / DW_AT_abstract_origin for names and types
  /// that live on a declaration entry.
  std::string linked_name(std::uint64_t offset, const std::map<std::uint64_t, std::string>& map) {
    for (int hops = 0; hops < 8; ++hops) {
      if (auto it = map.find(offset); it != map.end()) {
        return it->second;
      }
      auto link = links_.find(offset);
      if (link == links_.end()) {
        break;
      }
      offset = link->second;
    }
    return {};
  }
  std::uint64_t linked_type(std::uint64_t offset) {
    for (int hops = 0; hops < 8; ++hops) {
      if (auto it = die_types_.find(offset); it != die_types_.end()) {
        return it->second;
      }
      auto link = links_.find(offset);
      if (link == links_.end()) {
        break;
      }
      offset = link->second;
    }
    return 0;
  }

  void resolve_references() {
    for (DebugFunction& f : out_.functions) {
      const std::uint64_t die = f.provenance.die_offset;
      if (f.name.empty()) {
        f.name = linked_name(die, names_);
      }
      if (f.linkage_name.empty()) {
        f.linkage_name = linked_name(die, linkage_);
      }
      if (f.return_type == 0) {
        f.return_type = linked_type(die);
      }
      if (f.file.empty()) {
        // An out-of-line copy of an inlined function: file and line are on
        // the abstract instance.
        std::uint64_t at = die;
        for (int hops = 0; hops < 8 && f.file.empty(); ++hops) {
          if (auto it = sources_.find(at); it != sources_.end()) {
            f.file = it->second.first;
            f.line = it->second.second;
          }
          auto link = links_.find(at);
          if (link == links_.end()) {
            break;
          }
          at = link->second;
        }
      }
    }
    for (const auto& [function, parameter, die] : pending_parameters_) {
      DebugParameter& p = out_.functions[function].parameters[parameter];
      if (p.name.empty()) {
        p.name = linked_name(die, names_);
      }
      if (p.type == 0) {
        p.type = linked_type(die);
      }
    }
    for (const auto& [index, specification] : variable_links_) {
      DebugVariable& v = out_.variables[index];
      if (v.name.empty() && specification != 0) {
        v.name = linked_name(specification, names_);
      }
      if (v.type == 0 && specification != 0) {
        v.type = linked_type(specification);
      }
    }
    // Inlined-only or unnamed entries carry no information for a reader.
    out_.functions.erase(std::remove_if(out_.functions.begin(), out_.functions.end(),
                                        [](const DebugFunction& f) { return f.name.empty(); }),
                         out_.functions.end());
    // Unnamed variables are string-literal storage and the like.
    out_.variables.erase(std::remove_if(out_.variables.begin(), out_.variables.end(),
                                        [](const DebugVariable& v) { return v.name.empty(); }),
                         out_.variables.end());
    std::stable_sort(
        out_.functions.begin(), out_.functions.end(),
        [](const DebugFunction& a, const DebugFunction& b) { return a.address < b.address; });
    std::stable_sort(
        out_.variables.begin(), out_.variables.end(),
        [](const DebugVariable& a, const DebugVariable& b) { return a.address < b.address; });
  }

  const Sections& s_;
  const DebugInfoOptions& options_;
  DebugInfo& out_;
  std::size_t entries_ = 0;
  std::map<std::uint64_t, AbbrevTable> abbrev_cache_;
  std::map<std::uint64_t, std::string> names_;
  std::map<std::uint64_t, std::string> linkage_;
  std::map<std::uint64_t, std::uint64_t> links_;
  std::map<std::uint64_t, std::uint64_t> die_types_;
  std::map<std::uint64_t, std::pair<std::string, std::uint32_t>> sources_;
  std::unordered_map<std::uint64_t, std::size_t> function_index_;
  std::vector<std::tuple<std::size_t, std::size_t, std::uint64_t>> pending_parameters_;
  std::vector<std::pair<std::size_t, std::uint64_t>> variable_links_;
};

const Section* find_section(const BinaryImage& image, std::string_view elf_name,
                            std::string_view macho_name) {
  for (const Section& section : image.sections) {
    if (section.name == elf_name || section.name == macho_name) {
      return &section;
    }
    // Mach-O sections are listed as "__DWARF,__debug_info" by some readers.
    const auto comma = section.name.find(',');
    if (comma != std::string::npos &&
        std::string_view(section.name).substr(comma + 1) == macho_name) {
      return &section;
    }
  }
  return nullptr;
}

}  // namespace

std::string DebugProvenance::label() const {
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%s %u @0x%llx", format.c_str(),
                static_cast<unsigned>(version), static_cast<unsigned long long>(die_offset));
  return buffer;
}

std::string DebugInfo::type_name(std::uint64_t type) const {
  std::string suffix;
  std::string prefix;
  for (int depth = 0; depth < 16; ++depth) {
    if (type == 0) {
      return prefix + "void" + suffix;
    }
    const auto it = types.find(type);
    if (it == types.end()) {
      return prefix + "<unknown type>" + suffix;
    }
    const DebugType& t = it->second;
    switch (t.kind) {
      case DebugTypeKind::Base:
      case DebugTypeKind::Typedef:
      case DebugTypeKind::Unspecified:
        if (!t.name.empty()) {
          return prefix + t.name + suffix;
        }
        if (t.kind == DebugTypeKind::Typedef) {
          type = t.target;
          continue;
        }
        return prefix + "<unnamed>" + suffix;
      case DebugTypeKind::Struct:
        return prefix + "struct " + (t.name.empty() ? "<anonymous>" : t.name) + suffix;
      case DebugTypeKind::Union:
        return prefix + "union " + (t.name.empty() ? "<anonymous>" : t.name) + suffix;
      case DebugTypeKind::Class:
        return prefix + "class " + (t.name.empty() ? "<anonymous>" : t.name) + suffix;
      case DebugTypeKind::Enum:
        return prefix + "enum " + (t.name.empty() ? "<anonymous>" : t.name) + suffix;
      case DebugTypeKind::Pointer:
        // "char **", not "char * *".
        suffix = suffix.rfind(" *", 0) == 0 ? " *" + suffix.substr(1) : " *" + suffix;
        break;
      case DebugTypeKind::Reference:
        suffix = " &" + suffix;
        break;
      case DebugTypeKind::Const:
        prefix += "const ";
        break;
      case DebugTypeKind::Volatile:
        prefix += "volatile ";
        break;
      case DebugTypeKind::Restrict:
        suffix = " restrict" + suffix;
        break;
      case DebugTypeKind::Array:
        suffix += t.element_count != 0 ? "[" + std::to_string(t.element_count) + "]" : "[]";
        break;
      case DebugTypeKind::Function:
        return prefix + "<function>" + suffix;
      case DebugTypeKind::Void:
        return prefix + "void" + suffix;
    }
    type = t.target;
  }
  return prefix + "<type too deep>" + suffix;
}

std::string DebugInfo::prototype(const DebugFunction& function) const {
  std::string text = type_name(function.return_type) + " " + function.name + "(";
  for (std::size_t i = 0; i < function.parameters.size(); ++i) {
    if (i != 0) {
      text += ", ";
    }
    text += type_name(function.parameters[i].type);
    if (!function.parameters[i].name.empty()) {
      text += " " + function.parameters[i].name;
    }
  }
  if (function.variadic) {
    text += function.parameters.empty() ? "..." : ", ...";
  } else if (function.parameters.empty()) {
    text += "void";
  }
  return text + ")";
}

const DebugFunction* DebugInfo::function_containing(std::uint64_t address) const {
  auto it = std::upper_bound(
      functions.begin(), functions.end(), address,
      [](std::uint64_t value, const DebugFunction& f) { return value < f.address; });
  while (it != functions.begin()) {
    --it;
    if (address == it->address || (it->size != 0 && address - it->address < it->size)) {
      return &*it;
    }
    if (it->size != 0) {
      break;
    }
  }
  return nullptr;
}

const DebugFunction* DebugInfo::function_at(std::uint64_t address) const {
  auto it = std::lower_bound(
      functions.begin(), functions.end(), address,
      [](const DebugFunction& f, std::uint64_t value) { return f.address < value; });
  return it != functions.end() && it->address == address ? &*it : nullptr;
}

Result<DebugInfo> read_debug_info(const BinaryImage& image, std::span<const std::byte> data,
                                  const DebugInfoOptions& options) {
  auto bytes_of = [&](const Section* section) -> std::optional<Bytes> {
    if (section == nullptr) {
      return Bytes{};
    }
    if (!section->has_file_data || section->file_offset > data.size() ||
        section->file_size > data.size() - section->file_offset) {
      return std::nullopt;
    }
    return data.subspan(static_cast<std::size_t>(section->file_offset),
                        static_cast<std::size_t>(section->file_size));
  };
  const Section* info = find_section(image, ".debug_info", "__debug_info");
  if (info == nullptr) {
    return make_error<DebugInfo>(Status::Unsupported, "dwarf.not_present",
                                 "the image has no .debug_info section");
  }
  const Section* named[] = {
      info,
      find_section(image, ".debug_abbrev", "__debug_abbrev"),
      find_section(image, ".debug_str", "__debug_str"),
      find_section(image, ".debug_line_str", "__debug_line_str"),
      find_section(image, ".debug_str_offsets", "__debug_str_offs"),
      find_section(image, ".debug_addr", "__debug_addr"),
      find_section(image, ".debug_line", "__debug_line"),
  };
  for (const Section* section : named) {
    if (section != nullptr && section->compressed) {
      return make_error<DebugInfo>(Status::Unsupported, "dwarf.compressed",
                                   "compressed debug sections (SHF_COMPRESSED) are not supported "
                                   "yet; decompress with objcopy --decompress-debug-sections");
    }
  }
  Sections sections;
  sections.big_endian = image.endian == Endian::Big;
  Bytes* targets[] = {&sections.info,        &sections.abbrev, &sections.str, &sections.line_str,
                      &sections.str_offsets, &sections.addr,   &sections.line};
  for (std::size_t i = 0; i < std::size(named); ++i) {
    auto bytes = bytes_of(named[i]);
    if (!bytes.has_value()) {
      return make_error<DebugInfo>(Status::InvalidInput, "dwarf.section_out_of_bounds",
                                   "a debug section lies outside the file");
    }
    *targets[i] = *bytes;
  }
  if (sections.abbrev.empty()) {
    return make_error<DebugInfo>(Status::InvalidInput, "dwarf.no_abbrev",
                                 ".debug_info without .debug_abbrev");
  }
  DebugInfo out;
  Reader reader(sections, options, out);
  reader.run();
  return out;
}

}  // namespace donkey
