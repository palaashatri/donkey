#pragma once

// Applying a type library (G22-T3, first part): merging its types into a project's type table, and
// matching the image's imported names to its function prototypes. Nothing here reads a binary or
// writes a project: the caller passes the names and stores the result.

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/project/project.h"
#include "donkey/project/typelib.h"
#include "donkey/project/types.h"

namespace donkey {

/// A library name that an existing type of the table already has (the same C name space).
struct TypeLibraryCollision {
  std::string name;
  TypeId existing{};
  /// True when the two definitions differ in kind or layout (size, fields, target): the existing
  /// one is kept, and the library's is dropped, so a library layout never replaces a user, DWARF or
  /// PDB layout.
  bool differs = false;
};

/// The table after a merge.
struct TypeLibraryMerge {
  TypeTable table;
  /// Every named library type, by name space and name, to the id it has in `table`: its new id, or
  /// the existing type's id on a collision. Tags (struct, union, enum) and ordinary names (typedef,
  /// function) are kept apart, as in C.
  std::map<std::string, TypeId> tags;
  std::map<std::string, TypeId> ordinary;
  std::vector<TypeLibraryCollision> collisions;
  std::size_t added = 0;
};

/// Merges the library's types into `existing`. A library type whose name an existing type has in
/// the same name space is not added: references to it are moved to the existing type, and the
/// collision is listed (`differs` when the definitions do not match). Every other type is added
/// with a fresh id and provenance Library. The result is validated as a whole; an invalid table is
/// refused (`typelib_apply.invalid`) and `existing` is unchanged.
[[nodiscard]] Result<TypeLibraryMerge> merge_type_library(const TypeTable& existing,
                                                          const TypeLibrary& library);

/// The name an import is matched by: an ELF version suffix (`@VERSION` or `@@VERSION`) is removed,
/// and so is one leading underscore on Mach-O (`mach_o`).
[[nodiscard]] std::string import_match_name(std::string_view name, bool mach_o = false);

/// One import matched to a prototype, or not.
struct ImportPrototype {
  std::string import;  ///< as the image names it
  TypeId prototype{};  ///< the function type, or 0 when none applies
  /// Empty when matched; otherwise why not: `no prototype`, `ordinal import`, or `ambiguous` (one
  /// stripped name came with two different versions, so which prototype applies is not known).
  std::string reason;
};

/// Matches each import to a function prototype of the merge, by its match name. An ordinal import
/// (`ordinal_N`, PE) is never matched. When two imports have one match name with different
/// versions (`memcpy@GLIBC_2.2.5` and `memcpy@GLIBC_2.14`), both are `ambiguous`: a library has one
/// prototype per name and cannot tell the versions apart.
[[nodiscard]] std::vector<ImportPrototype> match_import_prototypes(
    const std::vector<std::string>& imports, const TypeLibraryMerge& merge, bool mach_o = false);

/// An import as the analysis found it: the stub or thunk that calls it, and the import's name.
struct ImportSite {
  std::string name;
  std::uint64_t address = 0;
};

/// What `apply_library_prototypes` did at one import site.
struct LibraryPrototypeApplication {
  std::string import;
  std::uint64_t address = 0;
  TypeId prototype{};  ///< the applied function type; 0 when nothing was applied
  /// Empty when applied; otherwise why not: the `match_import_prototypes` reasons, or `kept: user`
  /// (`kept: dwarf`, ...) when the address already has a prototype of another source.
  std::string reason;
};

/// The function prototypes a project's type libraries brought (`project type library add`): every
/// named function type of `table` with provenance Library, by name. Types from other sources are
/// not library prototypes, even when they share a name.
[[nodiscard]] TypeLibraryMerge library_prototypes(const TypeTable& table);

/// Applies the library prototypes of the project's type table to the import sites of one image,
/// as FunctionPrototype applications with source Library. A site whose address already has an
/// application of another source keeps it. The caller checks that the libraries fit the image
/// (architecture); nothing here reads the binary.
[[nodiscard]] Result<std::vector<LibraryPrototypeApplication>> apply_library_prototypes(
    Project& project, std::int64_t image_id, const std::vector<ImportSite>& sites,
    bool mach_o = false);

}  // namespace donkey
