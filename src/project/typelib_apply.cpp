#include "donkey/project/typelib_apply.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace donkey {
namespace {

enum class Space { None, Tag, Ordinary };

Space space_of(const TypeDefinition& type) {
  if (type.name.empty()) {
    return Space::None;
  }
  switch (type.kind) {
    case TypeKind::Struct:
    case TypeKind::Union:
    case TypeKind::Enum:
      return Space::Tag;
    case TypeKind::Typedef:
    case TypeKind::Function:
      return Space::Ordinary;
    default:
      return Space::None;
  }
}

/// Whether two definitions with one name describe the same thing, as far as a layout goes: kind,
/// size, and the members' names and offsets (or the parameters' count and the variadic flag).
bool same_shape(const TypeDefinition& a, const TypeDefinition& b) {
  if (a.kind != b.kind || a.size != b.size || a.variadic != b.variadic ||
      a.fields.size() != b.fields.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.fields.size(); ++i) {
    if (a.kind != TypeKind::Function &&
        (a.fields[i].name != b.fields[i].name || a.fields[i].offset != b.fields[i].offset)) {
      return false;
    }
  }
  return true;
}

}  // namespace

Result<TypeLibraryMerge> merge_type_library(const TypeTable& existing, const TypeLibrary& library) {
  TypeLibraryMerge merge;
  merge.table = existing;
  // The existing named types, by name space.
  std::map<std::string, TypeId> existing_tags;
  std::map<std::string, TypeId> existing_ordinary;
  for (const TypeDefinition& type : existing.list()) {
    const Space space = space_of(type);
    if (space == Space::Tag) {
      existing_tags.emplace(type.name, type.id);
    } else if (space == Space::Ordinary) {
      existing_ordinary.emplace(type.name, type.id);
    }
  }
  // Each library id to its id in the merged table.
  std::map<std::uint64_t, TypeId> moved;
  std::uint64_t next = existing.next_id().value();
  std::vector<const TypeDefinition*> added;
  for (const TypeDefinition& type : library.types) {
    const Space space = space_of(type);
    const auto& names = space == Space::Tag ? existing_tags : existing_ordinary;
    if (space != Space::None) {
      if (const auto found = names.find(type.name); found != names.end()) {
        moved[type.id.value()] = found->second;
        const TypeDefinition* old = existing.find(found->second);
        merge.collisions.push_back(
            {type.name, found->second, old == nullptr || !same_shape(*old, type)});
        continue;
      }
    }
    moved[type.id.value()] = TypeId{next++};
    added.push_back(&type);
  }
  const auto remap = [&moved](TypeId id) {
    const auto found = moved.find(id.value());
    return found == moved.end() ? id : found->second;
  };
  for (const TypeDefinition* type : added) {
    TypeDefinition copy = *type;
    copy.id = remap(copy.id);
    copy.target = remap(copy.target);
    for (TypeField& field : copy.fields) {
      field.type = remap(field.type);
    }
    copy.provenance = TypeProvenance::Library;
    merge.table.put(std::move(copy));
    ++merge.added;
  }
  if (auto valid = merge.table.validate(); !valid) {
    return make_error<TypeLibraryMerge>(Status::InvalidInput, "typelib_apply.invalid",
                                        "the merged type table is not valid: " +
                                            valid.diagnostic().message);
  }
  for (const TypeDefinition& type : library.types) {
    const Space space = space_of(type);
    if (space == Space::Tag) {
      merge.tags.emplace(type.name, remap(type.id));
    } else if (space == Space::Ordinary) {
      merge.ordinary.emplace(type.name, remap(type.id));
    }
  }
  return merge;
}

std::string import_match_name(std::string_view name, bool mach_o) {
  std::string out(name.substr(0, name.find('@')));
  if (mach_o && !out.empty() && out.front() == '_') {
    out.erase(0, 1);
  }
  return out;
}

std::vector<ImportPrototype> match_import_prototypes(const std::vector<std::string>& imports,
                                                     const TypeLibraryMerge& merge, bool mach_o) {
  // The versions each match name comes with: two different ones make the name ambiguous.
  std::map<std::string, std::set<std::string>> versions;
  for (const std::string& import : imports) {
    const std::size_t at = import.find('@');
    versions[import_match_name(import, mach_o)].insert(
        at == std::string::npos ? std::string() : import.substr(at));
  }
  std::vector<ImportPrototype> out;
  out.reserve(imports.size());
  for (const std::string& import : imports) {
    ImportPrototype entry;
    entry.import = import;
    const std::string name = import_match_name(import, mach_o);
    if (name.rfind("ordinal_", 0) == 0) {
      entry.reason = "ordinal import";
    } else if (versions[name].size() > 1) {
      entry.reason = "ambiguous";
    } else if (const auto found = merge.ordinary.find(name);
               found != merge.ordinary.end() &&
               merge.table.find(found->second) != nullptr &&
               merge.table.find(found->second)->kind == TypeKind::Function) {
      entry.prototype = found->second;
    } else {
      entry.reason = "no prototype";
    }
    out.push_back(std::move(entry));
  }
  return out;
}

}  // namespace donkey
