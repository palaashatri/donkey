#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/core/result.h"

namespace donkey {

/// Where a name or type came from. Imported debug information never
/// replaces a user edit: callers show user annotations first, then symbol
/// names, then debug-info names, and label each with its provenance.
struct DebugProvenance {
  std::string format;             ///< "DWARF"
  std::uint16_t version = 0;      ///< DWARF version of the compile unit
  std::uint64_t unit_offset = 0;  ///< offset of the compile unit in .debug_info
  std::uint64_t die_offset = 0;   ///< offset of the entry in .debug_info

  [[nodiscard]] std::string label() const;  ///< e.g. "DWARF 5 @0x2c"
};

enum class DebugTypeKind : std::uint8_t {
  Void,
  Base,
  Pointer,
  Reference,
  Const,
  Volatile,
  Restrict,
  Typedef,
  Struct,
  Union,
  Class,
  Enum,
  Array,
  Function,
  Unspecified,
};

struct DebugMember {
  std::string name;
  std::uint64_t type = 0;  ///< DebugInfo::types key; 0 = unknown
  std::uint64_t offset = 0;
};

struct DebugType {
  DebugTypeKind kind = DebugTypeKind::Unspecified;
  std::string name;
  std::uint64_t byte_size = 0;
  std::uint64_t target = 0;          ///< referenced type for pointers, typedefs, arrays...
  std::uint64_t element_count = 0;   ///< arrays: elements of the first dimension (0 unknown)
  std::vector<DebugMember> members;  ///< structs, unions, classes
  DebugProvenance provenance;
};

struct DebugParameter {
  std::string name;
  std::uint64_t type = 0;
};

struct DebugFunction {
  std::uint64_t address = 0;
  std::uint64_t size = 0;  ///< 0 when only the start is known
  std::string name;
  std::string linkage_name;
  std::uint64_t return_type = 0;  ///< 0 = void or unknown
  std::vector<DebugParameter> parameters;
  bool variadic = false;
  bool external = false;
  std::string file;
  std::uint32_t line = 0;
  DebugProvenance provenance;
};

struct DebugVariable {
  std::uint64_t address = 0;
  std::string name;
  std::uint64_t type = 0;
  std::string file;
  std::uint32_t line = 0;
  DebugProvenance provenance;
};

struct DebugInfo {
  std::string format = "DWARF";
  std::uint16_t min_version = 0;
  std::uint16_t max_version = 0;
  std::size_t compile_units = 0;
  std::vector<std::string> producers;        ///< distinct DW_AT_producer strings
  std::vector<DebugFunction> functions;      ///< sorted by address
  std::vector<DebugVariable> variables;      ///< sorted by address
  std::map<std::uint64_t, DebugType> types;  ///< keyed by .debug_info offset
  std::vector<Diagnostic> diagnostics;
  bool partial = false;

  /// C-like spelling of a type ("const char *", "struct point", "int[4]").
  [[nodiscard]] std::string type_name(std::uint64_t type) const;
  /// "int donkey_module_answer(int value)".
  [[nodiscard]] std::string prototype(const DebugFunction& function) const;
  /// The function whose [address, address + size) contains `address`.
  [[nodiscard]] const DebugFunction* function_containing(std::uint64_t address) const;
  [[nodiscard]] const DebugFunction* function_at(std::uint64_t address) const;
};

struct DebugInfoOptions {
  CancellationToken cancellation_token;
  std::size_t max_entries = 4'000'000;  ///< debugging information entries read
  std::size_t max_functions = 1'000'000;
  std::size_t max_types = 2'000'000;
};

/// Read DWARF from an image's .debug_* sections (ELF and PE; Mach-O
/// __DWARF sections when present). Bounded: every read is range-checked,
/// and a malformed compile unit stops with a diagnostic while earlier
/// units are kept (`partial`). Returns `dwarf.not_present` (Unsupported)
/// when the image has no .debug_info, and `dwarf.compressed` when its debug
/// sections are compressed (not supported yet).
[[nodiscard]] Result<DebugInfo> read_debug_info(const BinaryImage& image,
                                                std::span<const std::byte> data,
                                                const DebugInfoOptions& options = {});

}  // namespace donkey
