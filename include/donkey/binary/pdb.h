#pragma once

// Windows PDB files (G06): the MSF 7.00 container, its stream directory, and the streams that
// name the modules, procedures, data and types of a program: the PDB info stream, the type
// stream (TPI), the DBI stream with its module list and section headers, the symbol record
// stream and each module's symbol stream. Written from the public description of the format;
// no code from a PDB reader was used. Every read is bounded.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

struct PdbLimits {
  std::size_t max_streams = 65'536;
  std::size_t max_stream_bytes = 256U * 1024U * 1024U;
  std::size_t max_records = 1'000'000;
  std::size_t max_types = 1'000'000;
};

struct PdbModule {
  std::string name;    ///< the module's name (usually the object file's path as the linker saw it)
  std::string object;  ///< the object file the module was compiled to
  std::uint16_t symbol_stream = 0xffff;
  std::uint32_t symbol_bytes = 0;  ///< the symbol records' size; line information follows them
};

struct PdbSection {
  std::string name;
  std::uint32_t virtual_size = 0;
  std::uint32_t rva = 0;  ///< the section's relative virtual address
};

/// A procedure: its section and offset, its code size and its type index. `rva` is
/// the section's address plus the offset, relative to the image base.
struct PdbFunction {
  std::string name;
  std::string module;
  std::uint16_t section = 0;  ///< 1-based, as the symbol records number sections
  std::uint32_t offset = 0;
  std::uint32_t rva = 0;
  std::uint32_t size = 0;
  std::uint32_t type = 0;
  bool global = false;  ///< S_GPROC32 (external) rather than S_LPROC32 (static)
};

struct PdbVariable {
  std::string name;
  std::uint16_t section = 0;
  std::uint32_t offset = 0;
  std::uint32_t rva = 0;
  std::uint32_t type = 0;
};

/// One instance field of a struct, class or union: an LF_MEMBER of its field list.
struct PdbMember {
  std::string name;
  std::uint32_t type = 0;    ///< the field's type index; below 0x1000 it is a primitive
  std::uint64_t offset = 0;  ///< byte offset from the start of the aggregate
};

/// One enumerator of an enum: an LF_ENUMERATE of its field list, with its value (sign-extended
/// where the numeric leaf is signed).
struct PdbEnumerator {
  std::string name;
  std::int64_t value = 0;
};

/// A struct, class, union or enum from the type stream. A forward reference has no size and
/// names the complete type; the complete one is the entry with `forward == false`.
struct PdbType {
  std::uint32_t index = 0;
  std::string kind;  ///< "struct", "class", "union" or "enum"
  std::string name;
  std::uint64_t size = 0;
  bool forward = false;
  std::uint32_t field_list = 0;  ///< the LF_FIELDLIST index, 0 when there is none
  std::uint32_t underlying = 0;  ///< an enum's underlying integer type index, 0 for the others
  /// An enum's enumerators, in field-list order. Only meaningful when `enumerators_complete`.
  std::vector<PdbEnumerator> enumerators;
  bool enumerators_complete = false;
  /// The instance fields, in field-list order. Only meaningful when `members_complete`: a base
  /// class, a virtual table or any other entry that changes the layout makes the list incomplete,
  /// and the fields read before it are then not the whole layout.
  std::vector<PdbMember> members;
  bool members_complete = false;
};

/// A type built from another one: a pointer or reference, an array, a const or volatile
/// modifier, or a procedure. `referent` is the pointee, element, modified or return type.
struct PdbDerived {
  std::uint32_t index = 0;
  std::string kind;  ///< "pointer", "reference", "array", "const", "volatile" or "procedure"
  std::uint32_t referent = 0;
  std::uint64_t size = 0;  ///< a pointer's or an array's size in bytes, 0 when not stated
  std::vector<std::uint32_t> arguments;  ///< a procedure's parameter types, in order
};

struct PdbInfo {
  std::uint32_t age = 0;
  std::array<std::uint8_t, 16> guid{};  ///< the GUID, in the order it is stored
  std::vector<PdbModule> modules;
  std::vector<PdbSection> sections;
  std::vector<PdbFunction> functions;
  std::vector<PdbVariable> variables;  ///< the data symbols of the global symbol records
  std::vector<PdbType> types;
  std::vector<PdbDerived> derived;  ///< pointers, arrays, modifiers and procedures
  std::vector<Diagnostic> diagnostics;
  bool partial = false;
  /// The GUID as Microsoft prints it: {DCD7BA01-17F5-EA32-4C4C-44205044422E}.
  [[nodiscard]] std::string guid_text() const;
};

/// True when `file` begins with the MSF 7.00 magic of a PDB.
[[nodiscard]] bool is_pdb(std::span<const std::byte> file) noexcept;

/// Reads the PDB in `file`. The container and the streams it names are checked: a stream that
/// is out of range, a record that runs past its stream, or a count over the limit is reported
/// as a diagnostic and the read stops there, keeping what was read. Errors (not a PDB, a bad
/// superblock) are `pdb.` codes.
[[nodiscard]] Result<PdbInfo> read_pdb(std::span<const std::byte> file,
                                       const PdbLimits& limits = {});

}  // namespace donkey
