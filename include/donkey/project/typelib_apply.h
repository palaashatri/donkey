#pragma once

// Applying a type library (G22-T3): merging its types into a project's type table, finding where
// each import of an image binds, and giving an import the library's prototype only when the
// import is shown to bind to a library file the type library describes (its `provides` records),
// for the ABI the image's code follows.

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/elf_load_scope.h"
#include "donkey/binary/image.h"
#include "donkey/core/result.h"
#include "donkey/project/project.h"
#include "donkey/project/typelib.h"
#include "donkey/project/types.h"

namespace donkey {

/// A library name that an existing type of the table already has (the same C name space).
struct TypeLibraryCollision {
  std::string name;
  TypeId existing{};
  /// True when the two definitions differ in kind or layout: size, members' names, offsets and
  /// types, the target, the parameters, compared through the types they refer to (not by id, as a
  /// library type and an equal project type have different ids). The existing one is kept, and the
  /// library's is dropped, so a library layout never replaces a user, DWARF or PDB layout.
  bool differs = false;
};

/// The table after a merge.
struct TypeLibraryMerge {
  TypeTable table;
  /// Every named library type, by name space and name, to the id it has in `table`: its new id, or
  /// the existing type's id on a collision. Tags (struct, union, enum) and ordinary names (typedef,
  /// function, a record named by a typedef) are kept apart, as in C. A tag declared inside a
  /// prototype is in neither: it is not a file-scope name.
  std::map<std::string, TypeId> tags;
  std::map<std::string, TypeId> ordinary;
  /// The library function prototypes, by name: one per library that declares the name (a
  /// prototype of another library with the same name is not a collision).
  std::map<std::string, std::vector<TypeId>> functions;
  std::vector<TypeLibraryCollision> collisions;
  /// Library types not added because they refer, directly or through other library types, to a
  /// name the project defines differently (a collision that `differs`): moving their references to
  /// the project's definition would change what they mean.
  std::vector<std::string> dependent;
  std::size_t added = 0;
};

/// Merges the library's types into `existing`. A library type whose name an existing file-scope
/// type has in the same name space is not added: references to it are moved to the existing type,
/// and the collision is listed (`differs` when the definitions do not match). A library type that
/// depends on a collision that differs is not added either (`dependent`). A function prototype that
/// another library brought under the same name is not a collision: both are kept. Every other type
/// is added with a fresh id, provenance Library and `library` set to `library_id`. The result is
/// validated as a whole; an invalid table is refused (`typelib_apply.invalid`) and `existing` is
/// unchanged.
[[nodiscard]] Result<TypeLibraryMerge> merge_type_library(const TypeTable& existing,
                                                          const TypeLibrary& library,
                                                          std::int64_t library_id = 0);

/// The name an import is matched by: an ELF version suffix (`@VERSION` or `@@VERSION`) is removed,
/// and so is one leading underscore on Mach-O (`mach_o`).
[[nodiscard]] std::string import_match_name(std::string_view name, bool mach_o = false);

/// The ABI an image's code follows, in a type library's terms (typelib.h). `abi` is empty when no
/// library can describe the image (another format or architecture).
struct ImageAbi {
  std::string platform;  ///< `windows` (PE), `macos` (Mach-O); empty for ELF (Linux or FreeBSD)
  std::string architecture;
  std::string abi;         ///< sysv, aapcs64 or win64
  std::string data_model;  ///< LP64 or LLP64
};

/// The ABI of an image of `format` and `architecture`, spelled as format_name and
/// architecture_name spell them (`ELF`, `x86_64`), with `bits` its class. Only 64-bit images have
/// one: an ELF x32 image (x86-64 in ELFCLASS32, ILP32) gets none.
[[nodiscard]] ImageAbi image_abi(std::string_view format, std::string_view architecture,
                                 unsigned bits);

/// Why a loaded library does not describe code of `image`, or empty when it does: the
/// architecture, ABI and data model must be the image's, and so must the platform where the image
/// shows one.
[[nodiscard]] std::string library_misfit(const TypeLibraryRecord& library, const ImageAbi& image);

/// An import as the analysis found it: the stub or thunk that calls it, its name, and where each
/// of its references binds.
struct ImportSite {
  std::string name;
  std::uint64_t address = 0;
  /// Each version the image imports the name with (`GLIBC_2.2.5`, or empty for an unversioned
  /// reference), from the dynamic symbols, not from `name`.
  std::vector<std::string> versions;
  /// The library each reference binds to: its SONAME, or its file name when it has none (ELF); the
  /// DLL the import names (PE). Filled only when every reference is shown to bind.
  std::vector<std::string> providers;
  /// Why the provider is not shown, when it is not (a library of the load scope that could not be
  /// read, a name that binds nowhere, a format whose stubs are not bound).
  std::string unbound;
  /// PE: imported by ordinal (the import directory says so; the name is then `ordinal_N`).
  bool by_ordinal = false;
};

/// The import stubs and thunks of an analysed image, each with where its references bind: on ELF
/// by the dynamic loader's own search and lookup (ElfLoadScope, glibc's or musl's), on PE by the
/// DLL each import names. Mach-O and other formats give no providers (`unbound` says why).
[[nodiscard]] std::vector<ImportSite> import_sites(const BinaryImage& image,
                                                   std::span<const std::byte> data,
                                                   const AnalysisResult& analysis,
                                                   const ElfLibrarySearch& search = {});

/// One import matched to a prototype, or not.
struct ImportPrototype {
  std::string import;  ///< as the image names it
  TypeId prototype{};  ///< the first candidate, or 0 when none applies
  /// Every library prototype of the name, one per library, in id order.
  std::vector<TypeId> candidates;
  /// Empty when matched; otherwise why not: `no prototype`, `ordinal import`, or `ambiguous` (the
  /// name is imported with two different versions, and a library has one prototype per name).
  std::string reason;
};

/// Matches each site to the library function prototypes of the merge, by its match name. Only a
/// function type with provenance Library matches: a user, DWARF or PDB type that kept a library
/// name on a collision is not a library prototype. An import by ordinal (`ImportSite::by_ordinal`)
/// is never matched.
[[nodiscard]] std::vector<ImportPrototype> match_import_prototypes(
    const std::vector<ImportSite>& sites, const TypeLibraryMerge& merge);

/// What `apply_library_prototypes` did at one import site.
struct LibraryPrototypeApplication {
  std::string import;
  std::uint64_t address = 0;
  TypeId prototype{};  ///< the applied function type; 0 when nothing was applied
  /// The library that brought the prototype (`name version`), when one matched.
  std::string library;
  /// Empty when applied; otherwise why not: the `match_import_prototypes` reasons, the library not
  /// fitting the image's ABI, the provider not shown (`provider not shown: ...`), a provider the
  /// library does not describe (`bound to ...`), or `kept: user` (`kept: dwarf`, ...) when the
  /// address already has a prototype of another source.
  std::string reason;
};

/// The function prototypes a project's type libraries brought (`project type library add`): every
/// named function type of `table` with provenance Library, by name. Types from other sources are
/// not library prototypes, even when they share a name.
[[nodiscard]] TypeLibraryMerge library_prototypes(const TypeTable& table);

/// Applies the library prototypes of the project's type table to the import sites of one image, as
/// FunctionPrototype applications with source Library: a site gets the first candidate whose
/// library fits `image` (library_misfit) and `provides` the file every reference of the site binds
/// to. A site whose address already has an application of another source keeps it, also one
/// another connection wrote after this call read the applications (`kept: ...`).
[[nodiscard]] Result<std::vector<LibraryPrototypeApplication>> apply_library_prototypes(
    Project& project, std::int64_t image_id, const std::vector<ImportSite>& sites,
    const ImageAbi& image);

}  // namespace donkey
