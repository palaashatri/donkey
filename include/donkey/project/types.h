#pragma once

// The type store (G05-T1): C types as data, validated as a whole. A type records
// where it came from, and its size and alignment follow the ABI rules the table
// checks. Types are not applied to code here; G05-T3 does that.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "donkey/binary/debug_info.h"
#include "donkey/core/ids.h"
#include "donkey/core/result.h"

namespace donkey {

enum class TypeKind : std::uint8_t {
  Void = 0,
  Integer = 1,
  Float = 2,
  Pointer = 3,
  Array = 4,
  Struct = 5,
  Union = 6,
  Enum = 7,
  Typedef = 8,
  Function = 9,
};

/// Where a type's definition came from. Only `User` types are edited by hand.
enum class TypeProvenance : std::uint8_t {
  User = 0,
  Dwarf = 1,
  Pdb = 2,
  Inferred = 3,
  Library = 4,
};

const char* type_kind_name(TypeKind kind) noexcept;
const char* type_provenance_name(TypeProvenance provenance) noexcept;

/// A struct or union member, or a function parameter (name and type only).
struct TypeField {
  std::string name;
  /// Byte offset of the member within the struct. Zero for union members and
  /// parameters.
  std::uint64_t offset = 0;
  TypeId type{};
  /// Bit-field placement: the first bit within the byte at `offset`, and the
  /// number of bits. `bit_size` is zero for an ordinary member.
  std::uint8_t bit_offset = 0;
  std::uint8_t bit_size = 0;
};

struct TypeEnumerator {
  std::string name;
  std::int64_t value = 0;
};

/// One type. Which fields are meaningful depends on `kind`:
///   Integer, Float, Enum  size; Integer also is_signed; Enum may have enumerators
///   Pointer               target (0 is void *), size 4 or 8
///   Array                 target (element) and count; the size is derived
///   Struct, Union         size and fields
///   Typedef               target
///   Function              target (return; 0 is void) and fields (parameters)
struct TypeDefinition {
  TypeId id{};
  TypeKind kind = TypeKind::Void;
  std::string name;
  TypeProvenance provenance = TypeProvenance::User;
  std::uint64_t size = 0;
  bool is_signed = false;
  std::uint64_t count = 0;
  TypeId target{};
  bool variadic = false;
  std::vector<TypeField> fields;
  std::vector<TypeEnumerator> enumerators;
  /// Arrays: false when the producer gave no bound (a flexible array member). Such an array has no
  /// size of its own; as the last member of a struct it adds none, and anywhere else it is refused.
  bool count_known = true;
  /// Scalars: the alignment when the target aligns the scalar less than its size (for example an
  /// eight-byte scalar in a 32-bit System V unit). 0 means the size.
  std::uint64_t alignment = 0;
};

/// A set of types, keyed by id. `validate` checks the whole set; the other
/// accessors do not, so a table can be built in any order.
class TypeTable {
 public:
  /// Inserts the type under `definition.id`, replacing any type with that id.
  /// An invalid (zero) id is rejected by `validate`.
  void put(TypeDefinition definition);

  /// Removes one type. Returns false when it was absent.
  bool remove(TypeId id);

  [[nodiscard]] const TypeDefinition* find(TypeId id) const;

  /// Whether `id` is a function type, or a typedef that leads to one. A prototype application
  /// needs such a type.
  [[nodiscard]] bool names_function(TypeId id) const;

  /// Every type, ordered by id.
  [[nodiscard]] std::vector<TypeDefinition> list() const;

  /// One more than the largest id in use (1 for an empty table).
  [[nodiscard]] TypeId next_id() const;

  [[nodiscard]] std::size_t size() const noexcept { return types_.size(); }

  /// Checks every type: references resolve, no type contains itself by value,
  /// integer, float, pointer and enum sizes are ABI sizes, and each struct or
  /// union has its members at aligned offsets and a size that is the padded end
  /// of its last member. Returns the first problem, with a stable code.
  [[nodiscard]] Result<void> validate() const;

  /// The size in bytes of a complete type. Fails for a function type, an
  /// unknown id, or a table with a problem `validate` would report.
  [[nodiscard]] Result<std::uint64_t> size_of(TypeId id) const;

  /// The alignment in bytes of a complete type (a power of two).
  [[nodiscard]] Result<std::uint64_t> alignment_of(TypeId id) const;

 private:
  std::map<TypeId, TypeDefinition> types_;
};

/// Converts the DWARF types of a debuggee into a table. Ids are the DWARF
/// offsets plus one, so every reference keeps its meaning. Qualifiers (const,
/// volatile, restrict) do not get a type of their own; a reference to one names
/// the type it qualifies. Enumerator values are not recorded by the DWARF reader
/// and come out empty. The result is not validated; call `validate` on it.
[[nodiscard]] TypeTable types_from_debug_info(const DebugInfo& info);

}  // namespace donkey
