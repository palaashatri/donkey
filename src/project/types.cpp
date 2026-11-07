#include "donkey/project/types.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace donkey {
namespace {

/// Deepest chain of types that layout follows, and the most a valid type may
/// contain by value. Matches the nesting limit of the declaration parser.
constexpr int kMaxNesting = 64;

template <typename T>
Result<T> fail(std::string code, std::string message) {
  return make_error<T>(Status::InvalidInput, std::move(code), std::move(message));
}

std::string describe(TypeId id, const TypeDefinition* definition) {
  if (definition != nullptr && !definition->name.empty()) {
    return "'" + definition->name + "'";
  }
  return "type #" + std::to_string(id.value());
}

bool valid_integer_size(std::uint64_t size) {
  return size == 1 || size == 2 || size == 4 || size == 8 || size == 16;
}

bool valid_float_size(std::uint64_t size) {
  return size == 4 || size == 8 || size == 16;
}

bool valid_enum_size(std::uint64_t size) {
  return size == 1 || size == 2 || size == 4 || size == 8;
}

bool valid_pointer_size(std::uint64_t size) {
  return size == 4 || size == 8;
}

std::uint64_t round_up(std::uint64_t value, std::uint64_t alignment) {
  return (value + alignment - 1) / alignment * alignment;
}

struct Layout {
  std::uint64_t size = 0;
  std::uint64_t alignment = 1;
};

/// The layout of an integer, float, enum or pointer: its size, and an alignment that is the size
/// unless the table gives a smaller one. A stored alignment must be a power of two no larger than
/// the size, so a scalar can be aligned less than its size but never more.
Result<Layout> scalar_layout(const TypeDefinition& definition, const std::string& name) {
  const std::uint64_t alignment =
      definition.alignment == 0 ? definition.size : definition.alignment;
  if (alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > definition.size) {
    return fail<Layout>("type.bad_alignment",
                        name + " is aligned to " + std::to_string(alignment) +
                            " bytes; a scalar of " + std::to_string(definition.size) +
                            " bytes is aligned to a power of two no larger than its size");
  }
  return Layout{definition.size, alignment};
}

/// The array of unknown bound that `id` names, directly or through typedefs; null when it names
/// none. Such an array has no size of its own: a struct may end with one (a flexible array member),
/// and anywhere else its layout is refused.
const TypeDefinition* unbounded_array(const std::map<TypeId, TypeDefinition>& types, TypeId id) {
  for (int hop = 0; hop < kMaxNesting && id.valid(); ++hop) {
    const auto found = types.find(id);
    if (found == types.end()) {
      return nullptr;
    }
    if (found->second.kind == TypeKind::Array) {
      return found->second.count_known ? nullptr : &found->second;
    }
    if (found->second.kind != TypeKind::Typedef) {
      return nullptr;
    }
    id = found->second.target;
  }
  return nullptr;
}

/// The size and alignment of a type, checked as it is computed. Void (id 0) is
/// size 0. Each struct or union is laid out from its members: they must sit at
/// aligned offsets (a union member at zero), and the stored size must be the
/// padded end of the last member.
/// Whether a + b does not fit in 64 bits. Offsets and sizes come from untrusted DWARF, so a sum
/// that wraps must be refused rather than validated as small.
bool sum_overflows(std::uint64_t a, std::uint64_t b) {
  return a > std::numeric_limits<std::uint64_t>::max() - b;
}

Result<Layout> layout_of(const std::map<TypeId, TypeDefinition>& types, TypeId id, int depth) {
  if (!id.valid()) {
    return Layout{};
  }
  if (depth > kMaxNesting) {
    return fail<Layout>("type.nesting_too_deep", "types nest deeper than 64 levels");
  }
  const auto found = types.find(id);
  if (found == types.end()) {
    return fail<Layout>("type.missing",
                        "type #" + std::to_string(id.value()) + " is not in the table");
  }
  const TypeDefinition& definition = found->second;
  const std::string name = describe(id, &definition);
  switch (definition.kind) {
    case TypeKind::Void:
      if (definition.size != 0) {
        return fail<Layout>("type.void_size", name + " is void and has a size");
      }
      return Layout{};
    case TypeKind::Integer:
      if (!valid_integer_size(definition.size)) {
        return fail<Layout>("type.bad_integer_size",
                            name + " is an integer of " + std::to_string(definition.size) +
                                " bytes; the ABI sizes are 1, 2, 4, 8 and 16");
      }
      return scalar_layout(definition, name);
    case TypeKind::Float:
      if (!valid_float_size(definition.size)) {
        return fail<Layout>("type.bad_float_size", name + " is a float of " +
                                                       std::to_string(definition.size) +
                                                       " bytes; the sizes are 4, 8 and 16");
      }
      return scalar_layout(definition, name);
    case TypeKind::Enum:
      if (!valid_enum_size(definition.size)) {
        return fail<Layout>("type.bad_enum_size", name + " is an enum of " +
                                                      std::to_string(definition.size) +
                                                      " bytes; the sizes are 1, 2, 4 and 8");
      }
      return scalar_layout(definition, name);
    case TypeKind::Pointer:
      if (!valid_pointer_size(definition.size)) {
        return fail<Layout>("type.bad_pointer_size", name + " is a pointer of " +
                                                         std::to_string(definition.size) +
                                                         " bytes; the sizes are 4 and 8");
      }
      return scalar_layout(definition, name);
    case TypeKind::Typedef:
      return layout_of(types, definition.target, depth + 1);
    case TypeKind::Array: {
      if (!definition.target.valid()) {
        return fail<Layout>("type.array_without_element", name + " has no element type");
      }
      if (!definition.count_known) {
        return fail<Layout>("type.incomplete_array",
                            name + " is an array of unknown bound and has no size");
      }
      auto element = layout_of(types, definition.target, depth + 1);
      if (!element) {
        return element;
      }
      const std::uint64_t element_size = element.value().size;
      if (definition.count != 0 &&
          element_size > std::numeric_limits<std::uint64_t>::max() / definition.count) {
        return fail<Layout>("type.too_large", name + " is larger than 64 bits can count");
      }
      return Layout{definition.count * element_size, element.value().alignment};
    }
    case TypeKind::Function:
      return fail<Layout>("type.function_by_value",
                          name + " is a function; a function has no size by value");
    case TypeKind::Struct:
    case TypeKind::Union: {
      const bool is_union = definition.kind == TypeKind::Union;
      if (definition.fields.empty() && (definition.size == 0 || definition.size == 1)) {
        // No members: an empty C struct has size 0, and an empty C++ class has the ABI's
        // minimum of one byte. Either is accepted as declared.
        return Layout{definition.size, 1};
      }
      std::uint64_t alignment = 1;
      std::uint64_t end = 0;
      for (const TypeField& field : definition.fields) {
        if (!field.type.valid()) {
          return fail<Layout>("type.void_member",
                              name + " has a member '" + field.name + "' of type void");
        }
        // A flexible array member: the last member of a struct, of an array of unknown bound. It
        // adds no size of its own, but its element sets the alignment, and it sits at an aligned
        // offset.
        if (const TypeDefinition* unbounded = unbounded_array(types, field.type);
            unbounded != nullptr) {
          const bool last = &field == &definition.fields.back();
          if (is_union || !last || field.bit_size != 0) {
            return fail<Layout>(
                "type.flexible_member_not_last",
                name + " has an array member '" + field.name +
                    "' of unknown bound; only the last member of a struct may be one");
          }
          auto element = layout_of(types, unbounded->target, depth + 1);
          if (!element) {
            return element;
          }
          const std::uint64_t element_alignment = element.value().alignment;
          if (element_alignment == 0 || field.offset % element_alignment != 0) {
            return fail<Layout>("type.misaligned_field",
                                name + " has member '" + field.name + "' at offset " +
                                    std::to_string(field.offset) + ", not aligned to " +
                                    std::to_string(element_alignment));
          }
          alignment = std::max(alignment, element_alignment);
          end = std::max(end, field.offset);
          continue;
        }
        auto member = layout_of(types, field.type, depth + 1);
        if (!member) {
          return member;
        }
        const Layout& layout = member.value();
        std::uint64_t member_end = 0;
        if (field.bit_size != 0) {
          const std::uint64_t container_bits = layout.size * 8;
          if (field.bit_size > 64 || field.bit_offset > 7 ||
              static_cast<std::uint64_t>(field.bit_offset) + field.bit_size > container_bits) {
            return fail<Layout>("type.bad_bit_field", name + " has a bit-field '" + field.name +
                                                          "' that does not fit its type");
          }
          const std::uint64_t bytes =
              (static_cast<std::uint64_t>(field.bit_offset) + field.bit_size + 7) / 8;
          if (sum_overflows(field.offset, bytes)) {
            return fail<Layout>("type.member_overflow", name + " has a member '" + field.name +
                                                            "' whose offset wraps past 64 bits");
          }
          member_end = field.offset + bytes;
        } else {
          if (is_union && field.offset != 0) {
            return fail<Layout>("type.union_member_offset",
                                name + " has member '" + field.name + "' at offset " +
                                    std::to_string(field.offset) + "; union members sit at 0");
          }
          if (layout.alignment == 0 || field.offset % layout.alignment != 0) {
            return fail<Layout>("type.misaligned_field",
                                name + " has member '" + field.name + "' at offset " +
                                    std::to_string(field.offset) + ", not aligned to " +
                                    std::to_string(layout.alignment));
          }
          if (sum_overflows(field.offset, layout.size)) {
            return fail<Layout>("type.member_overflow", name + " has a member '" + field.name +
                                                            "' whose offset wraps past 64 bits");
          }
          member_end = field.offset + layout.size;
        }
        end = std::max(end, member_end);
        alignment = std::max(alignment, layout.alignment);
      }
      if (sum_overflows(end, alignment - 1)) {
        return fail<Layout>("type.member_overflow", name + " is too large to round up");
      }
      const std::uint64_t computed = round_up(end, alignment);
      if (computed != definition.size) {
        return fail<Layout>("type.size_mismatch", name + " is " + std::to_string(definition.size) +
                                                      " bytes but its members need " +
                                                      std::to_string(computed));
      }
      return Layout{definition.size, alignment};
    }
  }
  return fail<Layout>("type.unknown_kind", name + " has an unknown kind");
}

/// True for a function type, or a typedef that names one. Such a type has no size,
/// so it is checked where it is used by value and not as a type in its own right.
bool names_a_function(const std::map<TypeId, TypeDefinition>& types, TypeId id) {
  for (int hop = 0; hop < kMaxNesting && id.valid(); ++hop) {
    const auto found = types.find(id);
    if (found == types.end()) {
      return false;
    }
    if (found->second.kind == TypeKind::Function) {
      return true;
    }
    if (found->second.kind != TypeKind::Typedef) {
      return false;
    }
    id = found->second.target;
  }
  return false;
}

/// The types a type contains by value: those whose layout it needs. A pointer
/// or a function does not contain its target, so it does not appear here.
std::vector<TypeId> by_value_children(const TypeDefinition& definition) {
  std::vector<TypeId> children;
  switch (definition.kind) {
    case TypeKind::Struct:
    case TypeKind::Union:
      for (const TypeField& field : definition.fields) {
        if (field.type.valid()) {
          children.push_back(field.type);
        }
      }
      break;
    case TypeKind::Array:
    case TypeKind::Typedef:
      if (definition.target.valid()) {
        children.push_back(definition.target);
      }
      break;
    default:
      break;
  }
  return children;
}

/// Resolves qualifiers to the type they qualify. An offset with no entry is kept,
/// so the reference it came from fails validation instead of disappearing.
std::uint64_t resolve_qualifiers(const DebugInfo& info, std::uint64_t offset) {
  for (int hop = 0; hop < kMaxNesting && offset != 0; ++hop) {
    const auto found = info.types.find(offset);
    if (found == info.types.end()) {
      return offset;
    }
    const DebugTypeKind kind = found->second.kind;
    if (kind != DebugTypeKind::Const && kind != DebugTypeKind::Volatile &&
        kind != DebugTypeKind::Restrict) {
      return offset;
    }
    offset = found->second.target;
  }
  return offset;
}

TypeId dwarf_id(std::uint64_t offset) {
  return TypeId(offset + 1);
}

/// The id of the part type a complex or imaginary base type is built from. The high bit keeps it
/// apart from every DWARF offset.
TypeId dwarf_part_id(std::uint64_t offset) {
  return TypeId(offset + 1 + (std::uint64_t{1} << 62));
}

TypeId dwarf_reference(const DebugInfo& info, std::uint64_t offset) {
  const std::uint64_t resolved = resolve_qualifiers(info, offset);
  return resolved == 0 ? TypeId{} : dwarf_id(resolved);
}

bool is_qualifier(DebugTypeKind kind) {
  return kind == DebugTypeKind::Const || kind == DebugTypeKind::Volatile ||
         kind == DebugTypeKind::Restrict;
}

}  // namespace

const char* type_kind_name(TypeKind kind) noexcept {
  switch (kind) {
    case TypeKind::Void:
      return "void";
    case TypeKind::Integer:
      return "integer";
    case TypeKind::Float:
      return "float";
    case TypeKind::Pointer:
      return "pointer";
    case TypeKind::Array:
      return "array";
    case TypeKind::Struct:
      return "struct";
    case TypeKind::Union:
      return "union";
    case TypeKind::Enum:
      return "enum";
    case TypeKind::Typedef:
      return "typedef";
    case TypeKind::Function:
      return "function";
  }
  return "unknown";
}

const char* type_provenance_name(TypeProvenance provenance) noexcept {
  switch (provenance) {
    case TypeProvenance::User:
      return "user";
    case TypeProvenance::Dwarf:
      return "dwarf";
    case TypeProvenance::Pdb:
      return "pdb";
    case TypeProvenance::Inferred:
      return "inferred";
    case TypeProvenance::Library:
      return "library";
  }
  return "unknown";
}

void TypeTable::put(TypeDefinition definition) {
  const TypeId id = definition.id;
  types_[id] = std::move(definition);
}

bool TypeTable::remove(TypeId id) {
  return types_.erase(id) != 0;
}

const TypeDefinition* TypeTable::find(TypeId id) const {
  const auto found = types_.find(id);
  return found == types_.end() ? nullptr : &found->second;
}

std::vector<TypeDefinition> TypeTable::list() const {
  std::vector<TypeDefinition> out;
  out.reserve(types_.size());
  for (const auto& [id, definition] : types_) {
    out.push_back(definition);
  }
  return out;
}

TypeId TypeTable::next_id() const {
  return types_.empty() ? TypeId(1) : TypeId(types_.rbegin()->first.value() + 1);
}

Result<void> TypeTable::validate() const {
  for (const auto& [id, definition] : types_) {
    const std::string name = describe(id, &definition);
    if (!id.valid()) {
      return fail<void>("type.bad_id", "a type has id " + std::to_string(id.value()));
    }
    if (definition.kind == TypeKind::Array && !definition.target.valid()) {
      return fail<void>("type.array_without_element", name + " has no element type");
    }
    if (definition.target.valid() && types_.find(definition.target) == types_.end()) {
      return fail<void>("type.missing", name + " refers to type #" +
                                            std::to_string(definition.target.value()) +
                                            ", which is not in the table");
    }
    if (!definition.fields.empty() && definition.kind != TypeKind::Struct &&
        definition.kind != TypeKind::Union && definition.kind != TypeKind::Function) {
      return fail<void>("type.unexpected_fields",
                        name + " is a " + type_kind_name(definition.kind) + " and has members");
    }
    for (const TypeField& field : definition.fields) {
      if (!field.type.valid() || types_.find(field.type) == types_.end()) {
        return fail<void>("type.missing", name + " has member '" + field.name +
                                              "' of a type that is not in the table");
      }
    }
  }

  // A type may not contain itself by value: the depth-first search over by-value
  // edges must not meet a type on its own path. Iterative, so a long chain of
  // types cannot exhaust the stack.
  enum class Mark : std::uint8_t { Unvisited, OnPath, Done };
  std::map<TypeId, Mark> marks;
  for (const auto& [root, root_definition] : types_) {
    if (marks[root] != Mark::Unvisited) {
      continue;
    }
    std::vector<std::pair<TypeId, std::vector<TypeId>>> path;
    path.push_back({root, by_value_children(root_definition)});
    marks[root] = Mark::OnPath;
    while (!path.empty()) {
      auto& [current, pending] = path.back();
      if (pending.empty()) {
        marks[current] = Mark::Done;
        path.pop_back();
        continue;
      }
      const TypeId next = pending.back();
      pending.pop_back();
      const Mark mark = marks[next];
      if (mark == Mark::OnPath) {
        const TypeDefinition* definition = find(next);
        return fail<void>("type.contains_itself",
                          describe(next, definition) +
                              " contains itself by value; a struct may hold a pointer to itself, "
                              "not itself");
      }
      if (mark == Mark::Done) {
        continue;
      }
      const TypeDefinition* definition = find(next);
      marks[next] = Mark::OnPath;
      path.push_back({next, by_value_children(*definition)});
    }
  }

  for (const auto& [id, definition] : types_) {
    // A function has no size, and an array of unknown bound has none of its own: each is checked
    // where a complete type uses it by value.
    if (names_a_function(types_, id) || unbounded_array(types_, id) != nullptr) {
      continue;
    }
    auto layout = layout_of(types_, id, 0);
    if (!layout) {
      return make_error<void>(layout.diagnostic().status, layout.diagnostic().code,
                              layout.diagnostic().message);
    }
  }
  return Result<void>();
}

Result<std::uint64_t> TypeTable::size_of(TypeId id) const {
  auto layout = layout_of(types_, id, 0);
  if (!layout) {
    return make_error<std::uint64_t>(layout.diagnostic().status, layout.diagnostic().code,
                                     layout.diagnostic().message);
  }
  return layout.value().size;
}

Result<std::uint64_t> TypeTable::alignment_of(TypeId id) const {
  auto layout = layout_of(types_, id, 0);
  if (!layout) {
    return make_error<std::uint64_t>(layout.diagnostic().status, layout.diagnostic().code,
                                     layout.diagnostic().message);
  }
  return layout.value().alignment;
}

TypeTable types_from_debug_info(const DebugInfo& info) {
  TypeTable table;
  for (const auto& [offset, source] : info.types) {
    if (is_qualifier(source.kind)) {
      continue;  // a qualifier names the type it qualifies; see dwarf_reference
    }
    TypeDefinition definition;
    definition.id = dwarf_id(offset);
    definition.provenance = TypeProvenance::Dwarf;
    definition.name = source.name;
    definition.size = source.byte_size;
    definition.alignment = source.alignment;
    switch (source.kind) {
      case DebugTypeKind::Void:
      case DebugTypeKind::Unspecified:
        definition.kind = TypeKind::Void;
        definition.size = 0;
        break;
      case DebugTypeKind::Base:
        // DW_ATE: 2 boolean, 4 float, 5 signed, 6 signed_char, 7 unsigned,
        // 8 unsigned_char, 16 UTF. Anything else is taken as unsigned.
        if (source.encoding == 3 || source.encoding == 9) {
          // A complex value is two floats side by side and an imaginary value is one float. Both
          // are kept as an array of their parts: the layout matches the compiler's, and no scalar
          // type is claimed for them.
          const bool complex = source.encoding == 3;
          TypeDefinition part;
          part.id = dwarf_part_id(offset);
          part.kind = TypeKind::Float;
          part.provenance = TypeProvenance::Dwarf;
          part.name = source.name + " (part)";
          part.size = complex ? source.byte_size / 2 : source.byte_size;
          table.put(std::move(part));
          definition.kind = TypeKind::Array;
          definition.target = dwarf_part_id(offset);
          definition.count = complex ? 2 : 1;
          definition.size = 0;
          break;
        }
        if (source.encoding == 4) {
          definition.kind = TypeKind::Float;
        } else {
          definition.kind = TypeKind::Integer;
          definition.is_signed = source.encoding == 5 || source.encoding == 6;
        }
        break;
      case DebugTypeKind::Pointer:
      case DebugTypeKind::Reference:
        definition.kind = TypeKind::Pointer;
        definition.target = dwarf_reference(info, source.target);
        break;
      case DebugTypeKind::Typedef:
        definition.kind = TypeKind::Typedef;
        definition.target = dwarf_reference(info, source.target);
        break;
      case DebugTypeKind::Struct:
      case DebugTypeKind::Class:
      case DebugTypeKind::Union:
        definition.kind = source.kind == DebugTypeKind::Union ? TypeKind::Union : TypeKind::Struct;
        for (const DebugMember& member : source.members) {
          TypeField field;
          field.name = member.name;
          field.offset = member.offset;
          field.type = member.type == 0 ? TypeId{} : dwarf_reference(info, member.type);
          definition.fields.push_back(std::move(field));
        }
        break;
      case DebugTypeKind::Enum:
        definition.kind = TypeKind::Enum;
        break;
      case DebugTypeKind::Array:
        definition.kind = TypeKind::Array;
        definition.target = dwarf_reference(info, source.target);
        definition.count = source.element_count;
        definition.count_known = source.bound_known;
        definition.size = 0;  // derived from the element
        break;
      case DebugTypeKind::Function:
        definition.kind = TypeKind::Function;
        definition.target = dwarf_reference(info, source.target);
        definition.size = 0;
        // The reader keeps the formal parameters in `members`; they become the function's fields.
        for (const DebugMember& parameter : source.members) {
          TypeField field;
          field.name = parameter.name;
          field.type = parameter.type == 0 ? TypeId{} : dwarf_reference(info, parameter.type);
          definition.fields.push_back(std::move(field));
        }
        break;
      case DebugTypeKind::Const:
      case DebugTypeKind::Volatile:
      case DebugTypeKind::Restrict:
        continue;
    }
    table.put(std::move(definition));
  }
  return table;
}

bool TypeTable::names_function(TypeId id) const {
  return names_a_function(types_, id);
}

}  // namespace donkey
