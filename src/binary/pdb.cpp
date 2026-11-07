#include "donkey/binary/pdb.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/byte_reader.h"

namespace donkey {
namespace {

// The MSF 7.00 magic: "Microsoft C/C++ MSF 7.00\r\n", 0x1A, "DS", then three zero bytes.
constexpr std::array<std::uint8_t, 32> kMagic = {
    'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't',  ' ',  'C',  '/', 'C', '+', '+', ' ',
    'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', 0x1a, 'D', 'S', 0,   0,   0};
constexpr std::uint32_t kNilStream = 0xffff'ffffU;
constexpr std::uint32_t kStreamPdbInfo = 1;
constexpr std::uint32_t kStreamTypes = 2;
constexpr std::uint32_t kStreamDbi = 3;
constexpr std::size_t kDbiHeaderSize = 64;
constexpr std::size_t kModuleFixedSize = 64;
constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::uint32_t kSectionHeaderIndex = 5;  // in the optional debug header

// Type leaves (the record kinds of the type stream) that name a class-like type.
constexpr std::uint16_t kLfClass = 0x1504;
constexpr std::uint16_t kLfStructure = 0x1505;
constexpr std::uint16_t kLfUnion = 0x1506;
constexpr std::uint16_t kLfEnum = 0x1507;
constexpr std::uint16_t kPropForwardReference = 0x0080;

// Symbol record kinds.
constexpr std::uint16_t kSymGlobalProc32 = 0x1110;
constexpr std::uint16_t kSymLocalProc32 = 0x110f;
constexpr std::uint16_t kSymGlobalData32 = 0x110d;
constexpr std::uint16_t kSymLocalData32 = 0x110c;
constexpr std::uint32_t kC13Signature = 4;

std::uint64_t align4(std::uint64_t value) {
  return (value + 3U) & ~std::uint64_t{3};
}

std::string text_of(std::string_view view) {
  return std::string(view);
}

void note(PdbInfo& info, Status status, std::string code, std::string message,
          std::uint64_t offset) {
  info.diagnostics.push_back(Diagnostic::make(status, std::move(code), std::move(message), offset));
  info.partial = true;
}

/// The MSF container: its blocks and the stream directory.
class Msf {
 public:
  explicit Msf(std::span<const std::byte> file) : file_(file) {}

  /// Reads the superblock and the directory. Errors are `pdb.` diagnostics.
  Result<bool> open(const PdbLimits& limits) {
    const ByteReader reader(file_);
    if (file_.size() < 56) {
      return make_error<bool>(Status::InvalidInput, "pdb.truncated",
                              "the file is too short for an MSF superblock");
    }
    for (std::size_t i = 0; i < kMagic.size(); ++i) {
      if (static_cast<std::uint8_t>(file_[i]) != kMagic[i]) {
        return make_error<bool>(Status::InvalidInput, "pdb.magic",
                                "the file is not an MSF 7.00 PDB");
      }
    }
    const auto block_size = reader.u32(32, Endian::Little);
    const auto block_count = reader.u32(40, Endian::Little);
    const auto dir_bytes = reader.u32(44, Endian::Little);
    const auto block_map = reader.u32(52, Endian::Little);
    if (!block_size || !block_count || !dir_bytes || !block_map) {
      return make_error<bool>(Status::InvalidInput, "pdb.superblock",
                              "the superblock is unreadable");
    }
    const std::uint32_t size = block_size.value();
    if (size != 512 && size != 1024 && size != 2048 && size != 4096) {
      return make_error<bool>(Status::InvalidInput, "pdb.block_size",
                              "the block size is not 512, 1024, 2048 or 4096");
    }
    block_size_ = size;
    block_count_ = block_count.value();
    if (static_cast<std::uint64_t>(block_count_) * size > file_.size()) {
      return make_error<bool>(Status::InvalidInput, "pdb.truncated",
                              "the file is shorter than its block count");
    }
    if (dir_bytes.value() > limits.max_stream_bytes) {
      return make_error<bool>(Status::ResourceLimit, "pdb.directory_size",
                              "the stream directory is larger than the limit");
    }
    // The block map lists the blocks of the directory; it occupies consecutive blocks from
    // BlockMapAddr. The directory is those blocks, read in order.
    const std::uint64_t directory_blocks = blocks_for(dir_bytes.value());
    const std::vector<std::byte> map = read_consecutive(block_map.value(), directory_blocks * 4);
    if (map.size() < directory_blocks * 4) {
      return make_error<bool>(Status::InvalidInput, "pdb.block_map",
                              "the block map runs past the end of the file");
    }
    std::vector<std::byte> directory;
    directory.reserve(static_cast<std::size_t>(dir_bytes.value()));
    const ByteReader map_reader(map);
    for (std::uint64_t i = 0; i < directory_blocks; ++i) {
      const auto block = map_reader.u32(i * 4, Endian::Little);
      if (!block || block.value() >= block_count_) {
        return make_error<bool>(Status::InvalidInput, "pdb.block_map",
                                "the directory names a block outside the file");
      }
      const std::vector<std::byte> bytes = read_block(block.value());
      directory.insert(directory.end(), bytes.begin(), bytes.end());
    }
    directory.resize(std::min<std::size_t>(directory.size(), dir_bytes.value()));

    const ByteReader dir(directory);
    const auto streams = dir.u32(0, Endian::Little);
    if (!streams || streams.value() > limits.max_streams) {
      return make_error<bool>(Status::ResourceLimit, "pdb.stream_count",
                              "the directory names more streams than the limit");
    }
    const std::uint64_t count = streams.value();
    std::uint64_t at = 4 + count * 4;
    if (at > directory.size()) {
      return make_error<bool>(Status::InvalidInput, "pdb.directory", "the directory is truncated");
    }
    for (std::uint64_t i = 0; i < count; ++i) {
      const auto length = dir.u32(4 + i * 4, Endian::Little);
      const std::uint64_t bytes = (!length || length.value() == kNilStream) ? 0 : length.value();
      if (bytes > limits.max_stream_bytes) {
        return make_error<bool>(Status::ResourceLimit, "pdb.stream_size",
                                "a stream is larger than the limit");
      }
      std::vector<std::uint32_t> blocks;
      const std::uint64_t needed = blocks_for(static_cast<std::uint32_t>(bytes));
      for (std::uint64_t b = 0; b < needed; ++b) {
        const auto block = dir.u32(at, Endian::Little);
        at += 4;
        if (!block || at > directory.size()) {
          return make_error<bool>(Status::InvalidInput, "pdb.directory",
                                  "the directory's block lists are truncated");
        }
        blocks.push_back(block.value());
      }
      stream_sizes_.push_back(static_cast<std::uint32_t>(bytes));
      stream_blocks_.push_back(std::move(blocks));
      stream_nil_.push_back(length && length.value() == kNilStream);
    }
    return true;
  }

  std::size_t stream_count() const { return stream_sizes_.size(); }

  /// The bytes of stream `index`, or nothing when the index is out of range or a block is.
  std::optional<std::vector<std::byte>> stream(std::uint32_t index) const {
    if (index >= stream_sizes_.size() || stream_nil_[index]) {
      return std::nullopt;
    }
    std::vector<std::byte> out;
    out.reserve(stream_sizes_[index]);
    for (const std::uint32_t block : stream_blocks_[index]) {
      if (block >= block_count_) {
        return std::nullopt;
      }
      const std::vector<std::byte> bytes = read_block(block);
      out.insert(out.end(), bytes.begin(), bytes.end());
    }
    out.resize(std::min<std::size_t>(out.size(), stream_sizes_[index]));
    return out;
  }

 private:
  std::uint64_t blocks_for(std::uint32_t bytes) const {
    return (static_cast<std::uint64_t>(bytes) + block_size_ - 1) / block_size_;
  }

  std::vector<std::byte> read_block(std::uint32_t block) const {
    const std::uint64_t at = static_cast<std::uint64_t>(block) * block_size_;
    if (at >= file_.size()) {
      return {};
    }
    const std::size_t length =
        static_cast<std::size_t>(std::min<std::uint64_t>(block_size_, file_.size() - at));
    const auto begin = file_.begin() + static_cast<std::ptrdiff_t>(at);
    return std::vector<std::byte>(begin, begin + static_cast<std::ptrdiff_t>(length));
  }

  /// `length` bytes from the start of block `first`, over consecutive blocks.
  std::vector<std::byte> read_consecutive(std::uint32_t first, std::uint64_t length) const {
    std::vector<std::byte> out;
    const std::uint64_t blocks =
        blocks_for(static_cast<std::uint32_t>(std::min<std::uint64_t>(length, 0xffff'ffffU)));
    for (std::uint64_t i = 0; i < blocks && first + i < block_count_; ++i) {
      const std::vector<std::byte> bytes = read_block(static_cast<std::uint32_t>(first + i));
      out.insert(out.end(), bytes.begin(), bytes.end());
    }
    out.resize(std::min<std::size_t>(out.size(), static_cast<std::size_t>(length)));
    return out;
  }

  std::span<const std::byte> file_;
  std::uint32_t block_size_ = 0;
  std::uint32_t block_count_ = 0;
  std::vector<std::uint32_t> stream_sizes_;
  std::vector<std::vector<std::uint32_t>> stream_blocks_;
  std::vector<bool> stream_nil_;
};

/// A numeric leaf (the encoding of sizes and constants in type records). Returns the value and
/// its encoded length, or nothing for a kind this reader does not decode.
std::optional<std::pair<std::uint64_t, std::uint64_t>> numeric(const ByteReader& reader,
                                                               std::uint64_t at) {
  const auto leaf = reader.u16(at, Endian::Little);
  if (!leaf) {
    return std::nullopt;
  }
  if (leaf.value() < 0x8000) {
    return std::make_pair(static_cast<std::uint64_t>(leaf.value()), std::uint64_t{2});
  }
  switch (leaf.value()) {
    case 0x8000: {  // LF_CHAR
      const auto v = reader.u8(at + 2);
      if (!v) return std::nullopt;
      return std::make_pair(static_cast<std::uint64_t>(v.value()), std::uint64_t{3});
    }
    case 0x8001:    // LF_SHORT
    case 0x8002: {  // LF_USHORT
      const auto v = reader.u16(at + 2, Endian::Little);
      if (!v) return std::nullopt;
      return std::make_pair(static_cast<std::uint64_t>(v.value()), std::uint64_t{4});
    }
    case 0x8003:    // LF_LONG
    case 0x8004: {  // LF_ULONG
      const auto v = reader.u32(at + 2, Endian::Little);
      if (!v) return std::nullopt;
      return std::make_pair(static_cast<std::uint64_t>(v.value()), std::uint64_t{6});
    }
    case 0x8009:    // LF_QUADWORD
    case 0x800a: {  // LF_UQUADWORD
      const auto v = reader.u64(at + 2, Endian::Little);
      if (!v) return std::nullopt;
      return std::make_pair(v.value(), std::uint64_t{10});
    }
    default:
      return std::nullopt;
  }
}

constexpr std::uint16_t kLfModifier = 0x1001;
constexpr std::uint16_t kLfPointer = 0x1002;
constexpr std::uint16_t kLfProcedure = 0x1008;
constexpr std::uint16_t kLfArgList = 0x1201;
constexpr std::uint16_t kLfFieldList = 0x1203;
constexpr std::uint16_t kLfIndex = 0x1404;
constexpr std::uint16_t kLfArray = 0x1503;
constexpr std::uint16_t kLfMember = 0x150d;

/// An LF_FIELDLIST record: its instance fields, an LF_INDEX continuation to another list, and
/// whether a subrecord this reader does not decode ended it early (then it is incomplete).
struct FieldList {
  std::vector<PdbMember> members;
  std::uint32_t continuation = 0;
  bool complete = true;
};

/// Reads the subrecords of an LF_FIELDLIST body in [begin, end). Subrecords are padded to 4
/// bytes with bytes of 0xF0 and up. A subrecord kind this reader does not decode (a base class,
/// a virtual table, a method) ends the list as incomplete: the fields after it are not read.
FieldList read_field_list(const ByteReader& reader, std::uint64_t begin, std::uint64_t end) {
  FieldList list;
  std::uint64_t at = begin;
  while (at < end) {
    const auto lead = reader.u8(at);
    if (!lead) {
      list.complete = false;
      break;
    }
    if (lead.value() >= 0xf0) {
      ++at;  // padding before the next subrecord
      continue;
    }
    const auto leaf = reader.u16(at, Endian::Little);
    if (!leaf) {
      list.complete = false;
      break;
    }
    if (leaf.value() == kLfMember) {
      const auto type = reader.u32(at + 4, Endian::Little);
      const auto offset = numeric(reader, at + 8);
      if (!type || !offset) {
        list.complete = false;
        break;
      }
      const std::uint64_t name_at = at + 8 + offset->second;
      const auto name = reader.c_string(name_at, 4096);
      if (!name) {
        list.complete = false;
        break;
      }
      PdbMember member;
      member.name = text_of(name.value());
      member.type = type.value();
      member.offset = offset->first;
      list.members.push_back(std::move(member));
      at = name_at + name.value().size() + 1;
    } else if (leaf.value() == kLfIndex) {
      const auto continuation = reader.u32(at + 4, Endian::Little);
      if (!continuation) {
        list.complete = false;
        break;
      }
      list.continuation = continuation.value();
      at += 8;
    } else {
      list.complete = false;
      break;
    }
  }
  return list;
}

/// Appends the fields of field list `index` and of its continuations. Depth is limited, so a
/// continuation cycle is reported as incomplete rather than followed forever.
void collect_members(const std::map<std::uint32_t, FieldList>& lists, std::uint32_t index,
                     std::vector<PdbMember>& out, bool& complete, int depth) {
  const auto found = lists.find(index);
  if (depth > 16 || found == lists.end()) {
    complete = false;
    return;
  }
  out.insert(out.end(), found->second.members.begin(), found->second.members.end());
  if (!found->second.complete) {
    complete = false;
  }
  if (found->second.continuation != 0) {
    collect_members(lists, found->second.continuation, out, complete, depth + 1);
  }
}

/// The type stream: the class-like types it names, with their sizes and forward references, and
/// the fields, pointers, arrays, modifiers and procedures that the rest of it describes.
void read_types(const Msf& msf, PdbInfo& info, const PdbLimits& limits) {
  const auto stream = msf.stream(kStreamTypes);
  if (!stream) {
    return;
  }
  const ByteReader reader(*stream);
  const auto header_size = reader.u32(4, Endian::Little);
  const auto begin = reader.u32(8, Endian::Little);
  if (!header_size || !begin || header_size.value() > stream->size()) {
    note(info, Status::Partial, "pdb.tpi_header", "the type stream header is unreadable", 0);
    return;
  }
  std::uint64_t at = header_size.value();
  std::uint32_t index = begin.value();
  std::size_t records = 0;
  std::map<std::uint32_t, FieldList> field_lists;
  std::map<std::uint32_t, std::vector<std::uint32_t>> argument_lists;
  std::map<std::uint32_t, std::uint32_t> procedure_arglists;  // procedure index -> arglist index
  while (at + 4 <= stream->size()) {
    if (++records > limits.max_types) {
      note(info, Status::ResourceLimit, "pdb.type_limit", "more types than the limit", at);
      return;
    }
    const auto length = reader.u16(at, Endian::Little);
    const auto kind = reader.u16(at + 2, Endian::Little);
    if (!length || !kind || length.value() < 2 || at + 2 + length.value() > stream->size()) {
      note(info, Status::Partial, "pdb.type_record", "a type record runs past the stream", at);
      return;
    }
    const std::uint64_t body = at + 4;
    const std::uint64_t end = at + 2 + length.value();
    const std::uint16_t leaf = kind.value();
    if (leaf == kLfClass || leaf == kLfStructure || leaf == kLfUnion || leaf == kLfEnum) {
      const auto property = reader.u16(body + 2, Endian::Little);
      PdbType type;
      type.index = index;
      type.kind = leaf == kLfClass       ? "class"
                  : leaf == kLfStructure ? "struct"
                  : leaf == kLfUnion     ? "union"
                                         : "enum";
      type.forward = property && (property.value() & kPropForwardReference) != 0;
      std::uint64_t name_at = 0;
      if (leaf == kLfEnum) {
        name_at = body + 12;  // count, property, underlying type, field list
      } else if (leaf == kLfUnion) {
        if (const auto size = numeric(reader, body + 8)) {
          type.size = size->first;
          name_at = body + 8 + size->second;
        }
      } else if (const auto size = numeric(reader, body + 16)) {
        type.size = size->first;
        name_at = body + 16 + size->second;
      }
      if (name_at != 0 && name_at < end) {
        if (const auto name = reader.c_string(name_at, 4096)) {
          type.name = text_of(name.value());
        }
      }
      if (type.forward) {
        type.size = 0;
      } else if (const auto field_list =
                     reader.u32(leaf == kLfEnum ? body + 8 : body + 4, Endian::Little)) {
        type.field_list = field_list.value();  // enum: its enumerators, not read here
      }
      if (leaf == kLfEnum) {
        if (const auto underlying = reader.u32(body + 4, Endian::Little)) {
          type.underlying = underlying.value();
        }
      }
      info.types.push_back(std::move(type));
    } else if (leaf == kLfFieldList) {
      field_lists.emplace(index, read_field_list(reader, body, end));
    } else if (leaf == kLfArgList) {
      const auto count = reader.u32(body, Endian::Little);
      // Each argument is 4 bytes after the count; a count past the record is reported.
      const std::uint64_t room = end >= body + 4 ? (end - body - 4) / 4 : 0;
      if (!count || count.value() > room) {
        note(info, Status::Partial, "pdb.arglist", "an argument list runs past its record", at);
      } else {
        std::vector<std::uint32_t> arguments;
        for (std::uint64_t i = 0; i < count.value(); ++i) {
          const auto argument = reader.u32(body + 4 + 4 * i, Endian::Little);
          if (!argument) {
            break;
          }
          arguments.push_back(argument.value());
        }
        argument_lists[index] = std::move(arguments);
      }
    } else if (leaf == kLfPointer) {
      const auto referent = reader.u32(body, Endian::Little);
      const auto attributes = reader.u32(body + 4, Endian::Little);
      if (!referent || !attributes) {
        note(info, Status::Partial, "pdb.pointer", "a pointer record is truncated", at);
      } else {
        PdbDerived derived;
        derived.index = index;
        derived.referent = referent.value();
        const std::uint32_t form = attributes.value() & 0x1fU;         // CV_ptrtype_e
        const std::uint32_t mode = (attributes.value() >> 5U) & 0x7U;  // CV_ptrmode_e
        derived.kind = mode == 0                ? "pointer"
                       : mode == 1 || mode == 2 ? "reference"
                                                : "pointer to member";
        derived.size = (attributes.value() >> 13U) & 0x3fU;
        if (derived.size == 0) {
          derived.size = form == 0x0c ? 8 : form == 0x0a ? 4 : 0;  // ptr64, near32
        }
        info.derived.push_back(std::move(derived));
      }
    } else if (leaf == kLfArray) {
      const auto element = reader.u32(body, Endian::Little);
      const auto bytes = numeric(reader, body + 8);
      if (!element || !bytes) {
        note(info, Status::Partial, "pdb.array", "an array record is truncated", at);
      } else {
        PdbDerived derived;
        derived.index = index;
        derived.kind = "array";
        derived.referent = element.value();
        derived.size = bytes->first;
        info.derived.push_back(std::move(derived));
      }
    } else if (leaf == kLfModifier) {
      const auto modified = reader.u32(body, Endian::Little);
      const auto modifier = reader.u16(body + 4, Endian::Little);
      if (!modified || !modifier) {
        note(info, Status::Partial, "pdb.modifier", "a modifier record is truncated", at);
      } else {
        PdbDerived derived;
        derived.index = index;
        derived.referent = modified.value();
        const bool is_const = (modifier.value() & 0x1U) != 0;
        const bool is_volatile = (modifier.value() & 0x2U) != 0;
        // An unaligned-only modifier changes nothing, and is kept as "unaligned".
        derived.kind = is_const && is_volatile ? "const volatile"
                       : is_const              ? "const"
                       : is_volatile           ? "volatile"
                                               : "unaligned";
        info.derived.push_back(std::move(derived));
      }
    } else if (leaf == kLfProcedure) {
      const auto returns = reader.u32(body, Endian::Little);
      const auto arglist = reader.u32(body + 8, Endian::Little);
      if (!returns || !arglist) {
        note(info, Status::Partial, "pdb.procedure", "a procedure record is truncated", at);
      } else {
        PdbDerived derived;
        derived.index = index;
        derived.kind = "procedure";
        derived.referent = returns.value();
        procedure_arglists[index] = arglist.value();
        info.derived.push_back(std::move(derived));
      }
    }
    at = end;
    ++index;
  }

  // Resolve the references the records named: a complete struct's fields, and a procedure's
  // parameters. A reference to a record that is not there is reported, not guessed.
  for (PdbType& type : info.types) {
    if (type.forward) {
      continue;
    }
    if (type.field_list == 0) {
      type.members_complete = type.kind != "enum";  // no fields: complete, unless an enum
      continue;
    }
    if (type.kind == "enum") {
      continue;  // enumerators are not read, so the enum keeps no members
    }
    bool complete = true;
    collect_members(field_lists, type.field_list, type.members, complete, 0);
    type.members_complete = complete;
  }
  for (PdbDerived& derived : info.derived) {
    if (derived.kind != "procedure") {
      continue;
    }
    const auto arglist = procedure_arglists.find(derived.index);
    const auto arguments = arglist == procedure_arglists.end()
                               ? argument_lists.end()
                               : argument_lists.find(arglist->second);
    if (arguments == argument_lists.end()) {
      note(info, Status::Partial, "pdb.arglist", "a procedure names a missing argument list",
           derived.index);
      continue;
    }
    derived.arguments = arguments->second;
  }
}

/// The DBI stream: the module list and the index of the section header stream.
struct Dbi {
  std::uint16_t symbol_record_stream = 0xffff;
  std::uint16_t section_header_stream = 0xffff;
  std::vector<PdbModule> modules;
};

Dbi read_dbi(const Msf& msf, PdbInfo& info, const PdbLimits& limits) {
  Dbi dbi;
  const auto stream = msf.stream(kStreamDbi);
  if (!stream) {
    note(info, Status::Partial, "pdb.dbi", "the DBI stream is missing", 0);
    return dbi;
  }
  const ByteReader reader(*stream);
  const auto symbols = reader.u16(20, Endian::Little);
  const auto module_bytes = reader.u32(24, Endian::Little);
  const auto contribution_bytes = reader.u32(28, Endian::Little);
  const auto section_map_bytes = reader.u32(32, Endian::Little);
  const auto source_bytes = reader.u32(36, Endian::Little);
  const auto type_server_bytes = reader.u32(40, Endian::Little);
  const auto optional_bytes = reader.u32(48, Endian::Little);
  const auto ec_bytes = reader.u32(52, Endian::Little);
  if (!symbols || !module_bytes || !contribution_bytes || !section_map_bytes || !source_bytes ||
      !type_server_bytes || !optional_bytes || !ec_bytes) {
    note(info, Status::Partial, "pdb.dbi_header", "the DBI header is unreadable", 0);
    return dbi;
  }
  dbi.symbol_record_stream = symbols.value();

  // The module information: fixed fields, then the module and object names, 4-byte aligned.
  const std::uint64_t modules_end = kDbiHeaderSize + module_bytes.value();
  if (modules_end > stream->size()) {
    note(info, Status::Partial, "pdb.dbi_modules", "the module list runs past the DBI stream",
         kDbiHeaderSize);
    return dbi;
  }
  std::uint64_t at = kDbiHeaderSize;
  while (at + kModuleFixedSize <= modules_end) {
    if (dbi.modules.size() >= limits.max_records) {
      note(info, Status::ResourceLimit, "pdb.module_limit", "more modules than the limit", at);
      break;
    }
    const auto stream_index = reader.u16(at + 34, Endian::Little);
    const auto name = reader.c_string(at + kModuleFixedSize, modules_end - (at + kModuleFixedSize));
    if (!stream_index || !name) {
      note(info, Status::Partial, "pdb.dbi_module", "a module entry is unreadable", at);
      break;
    }
    PdbModule module;
    module.name = text_of(name.value());
    module.symbol_stream = stream_index.value();
    if (const auto symbol_bytes = reader.u32(at + 36, Endian::Little)) {
      module.symbol_bytes = symbol_bytes.value();
    }
    const std::uint64_t object_at = at + kModuleFixedSize + name.value().size() + 1;
    if (object_at < modules_end) {
      if (const auto object = reader.c_string(object_at, modules_end - object_at)) {
        module.object = text_of(object.value());
        at = align4(object_at + object.value().size() + 1);
      } else {
        at = modules_end;
      }
    } else {
      at = modules_end;
    }
    dbi.modules.push_back(std::move(module));
  }

  // The optional debug header lists the streams of the section headers and the other tables.
  const std::uint64_t optional_at = modules_end + contribution_bytes.value() +
                                    section_map_bytes.value() + source_bytes.value() +
                                    type_server_bytes.value() + ec_bytes.value();
  if (optional_bytes.value() >= (kSectionHeaderIndex + 1) * 2 &&
      optional_at + kSectionHeaderIndex * 2 + 2 <= stream->size()) {
    if (const auto index = reader.u16(optional_at + kSectionHeaderIndex * 2, Endian::Little)) {
      dbi.section_header_stream = index.value();
    }
  }
  return dbi;
}

void read_sections(const Msf& msf, const Dbi& dbi, PdbInfo& info) {
  if (dbi.section_header_stream == 0xffff) {
    return;
  }
  const auto stream = msf.stream(dbi.section_header_stream);
  if (!stream) {
    note(info, Status::Partial, "pdb.section_headers", "the section header stream is missing", 0);
    return;
  }
  const ByteReader reader(*stream);
  for (std::uint64_t at = 0; at + kSectionHeaderSize <= stream->size(); at += kSectionHeaderSize) {
    const auto name = reader.c_string(at, 8);
    const auto virtual_size = reader.u32(at + 8, Endian::Little);
    const auto rva = reader.u32(at + 12, Endian::Little);
    if (!virtual_size || !rva) {
      break;
    }
    PdbSection section;
    section.name = name ? text_of(name.value()) : std::string();
    section.virtual_size = virtual_size.value();
    section.rva = rva.value();
    info.sections.push_back(std::move(section));
  }
}

std::uint32_t section_address(const PdbInfo& info, std::uint16_t section) {
  if (section == 0 || section > info.sections.size()) {
    return 0;
  }
  return info.sections[section - 1].rva;
}

/// The records of a symbol stream, starting after its signature. `procedures` collects the
/// procedures of a module stream; `globals` collects the data and the public symbols of the
/// global symbol record stream.
void read_symbols(const std::vector<std::byte>& stream, std::uint64_t limit_bytes, PdbInfo& info,
                  const std::string& module, bool module_stream, const PdbLimits& limits) {
  const ByteReader reader(stream);
  const std::uint64_t end = std::min<std::uint64_t>(stream.size(), limit_bytes);
  std::uint64_t at = module_stream ? 4 : 0;
  std::size_t records = 0;
  while (at + 4 <= end) {
    if (++records > limits.max_records) {
      note(info, Status::ResourceLimit, "pdb.symbol_limit", "more symbols than the limit", at);
      return;
    }
    const auto length = reader.u16(at, Endian::Little);
    const auto kind = reader.u16(at + 2, Endian::Little);
    if (!length || !kind || length.value() < 2 || at + 2 + length.value() > end) {
      note(info, Status::Partial, "pdb.symbol_record", "a symbol record runs past its stream", at);
      return;
    }
    const std::uint16_t leaf = kind.value();
    if (module_stream && (leaf == kSymGlobalProc32 || leaf == kSymLocalProc32)) {
      const auto size = reader.u32(at + 16, Endian::Little);
      const auto type = reader.u32(at + 28, Endian::Little);
      const auto offset = reader.u32(at + 32, Endian::Little);
      const auto section = reader.u16(at + 36, Endian::Little);
      const auto name = reader.c_string(at + 39, 4096);
      if (size && type && offset && section && name) {
        PdbFunction function;
        function.name = text_of(name.value());
        function.module = module;
        function.section = section.value();
        function.offset = offset.value();
        function.rva = section_address(info, section.value()) + offset.value();
        function.size = size.value();
        function.type = type.value();
        function.global = leaf == kSymGlobalProc32;
        info.functions.push_back(std::move(function));
      }
    } else if (!module_stream && (leaf == kSymGlobalData32 || leaf == kSymLocalData32)) {
      const auto type = reader.u32(at + 4, Endian::Little);
      const auto offset = reader.u32(at + 8, Endian::Little);
      const auto section = reader.u16(at + 12, Endian::Little);
      const auto name = reader.c_string(at + 14, 4096);
      if (type && offset && section && name) {
        PdbVariable variable;
        variable.name = text_of(name.value());
        variable.section = section.value();
        variable.offset = offset.value();
        variable.rva = section_address(info, section.value()) + offset.value();
        variable.type = type.value();
        info.variables.push_back(std::move(variable));
      }
    }
    at += 2 + length.value();
  }
}

}  // namespace

std::string PdbInfo::guid_text() const {
  // The first three fields are stored little-endian; the last eight bytes are as they are.
  char buffer[40];
  std::snprintf(buffer, sizeof(buffer),
                "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}", guid[3],
                guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6], guid[8], guid[9],
                guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]);
  return buffer;
}

bool is_pdb(std::span<const std::byte> file) noexcept {
  if (file.size() < kMagic.size()) {
    return false;
  }
  for (std::size_t i = 0; i < kMagic.size(); ++i) {
    if (static_cast<std::uint8_t>(file[i]) != kMagic[i]) {
      return false;
    }
  }
  return true;
}

Result<PdbInfo> read_pdb(std::span<const std::byte> file, const PdbLimits& limits) {
  Msf msf(file);
  if (auto opened = msf.open(limits); !opened) {
    return Result<PdbInfo>(opened.diagnostic());
  }
  PdbInfo info;
  if (const auto stream = msf.stream(kStreamPdbInfo); stream && stream->size() >= 28) {
    const ByteReader reader(*stream);
    if (const auto age = reader.u32(8, Endian::Little)) {
      info.age = age.value();
    }
    for (std::size_t i = 0; i < 16; ++i) {
      if (const auto byte = reader.u8(12 + i)) {
        info.guid[i] = byte.value();
      }
    }
  } else {
    note(info, Status::Partial, "pdb.info", "the PDB info stream is missing", 0);
  }
  read_types(msf, info, limits);
  const Dbi dbi = read_dbi(msf, info, limits);
  info.modules = dbi.modules;
  read_sections(msf, dbi, info);

  // The procedures of each module, from its symbol stream.
  for (const PdbModule& module : dbi.modules) {
    if (module.symbol_stream == 0xffff) {
      continue;
    }
    const auto stream = msf.stream(module.symbol_stream);
    if (!stream || stream->size() < 4) {
      continue;
    }
    const ByteReader reader(*stream);
    const auto signature = reader.u32(0, Endian::Little);
    if (!signature || signature.value() != kC13Signature) {
      note(info, Status::Partial, "pdb.module_symbols", "a module's symbols have no C13 signature",
           0);
      continue;
    }
    // The symbol records are the first symbol_bytes; the C11 and C13 line information follows.
    read_symbols(*stream, std::min<std::uint64_t>(module.symbol_bytes, stream->size()), info,
                 module.name, /*module_stream=*/true, limits);
  }
  // The global data, from the symbol record stream that the DBI names.
  if (dbi.symbol_record_stream != 0xffff) {
    if (const auto stream = msf.stream(dbi.symbol_record_stream)) {
      read_symbols(*stream, stream->size(), info, std::string(), /*module_stream=*/false, limits);
    }
  }
  return info;
}

}  // namespace donkey
