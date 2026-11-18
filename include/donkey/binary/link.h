#pragma once

// Import resolution across several images of one project (G15-T2). The images are given in
// link order, the executable first, as the dynamic loader searches them. Each import of an image
// is bound to the first other image that exports the same name, among the libraries the importer
// names: the DT_NEEDED entries of an ELF image, or the DLL named by a PE import. Nothing is
// executed and no image is changed. Cross-image references (calls through the bound imports) are
// not computed here.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"

namespace donkey {

/// One image of a link set: the parsed image and the bytes it was parsed from.
struct LinkInput {
  const BinaryImage* image = nullptr;
  std::span<const std::byte> data;
};

/// The names an ELF image gives itself (DT_SONAME) and the libraries it needs (DT_NEEDED).
struct ElfLibraryNames {
  std::string soname;
  std::vector<std::string> needed;
  /// DT_RPATH and DT_RUNPATH as written (colon-separated, `$ORIGIN` not expanded); empty when
  /// absent.
  std::string rpath;
  std::string runpath;
  bool has_rpath = false;
  bool has_runpath = false;
  /// DF_1_NODEFLIB in DT_FLAGS_1: the loader skips ld.so.cache and the default directories for the
  /// libraries this object needs.
  bool nodeflib = false;
  /// DF_1_PIE in DT_FLAGS_1: a position-independent executable, not a shared library.
  bool pie = false;
  /// DT_SYMBOLIC, or DF_SYMBOLIC in DT_FLAGS: the object's own references look in it first.
  bool symbolic = false;
  /// DT_VERSYM, DT_VERDEF and DT_VERNEED are present: the loader reads symbol versions.
  bool version_symbols = false;
  bool version_definitions = false;
  bool version_needs = false;
  /// The image has a dynamic table (PT_DYNAMIC, or a `.dynamic` section when it has no program
  /// headers).
  bool dynamic = false;
  /// False when part of the dynamic table could not be read (the table is cut short, a name lies
  /// outside the string table, or the program headers are unreadable): a library or search
  /// directory may be missing from the lists above.
  bool complete = true;
};

/// Reads the dynamic table of an ELF image the way the loader does: PT_DYNAMIC, with names from
/// DT_STRTAB (the `.dynamic` and `.dynstr` sections only when the image has no program headers).
/// Every list is empty for other formats and for an image that is not dynamically linked.
[[nodiscard]] ElfLibraryNames read_library_names(const BinaryImage& image,
                                                 std::span<const std::byte> data);

/// The index of an import that no image exports.
inline constexpr std::size_t kUnboundImport = static_cast<std::size_t>(-1);

/// One import of one input and the export it is bound to.
struct ImportBinding {
  std::size_t importer = 0;  ///< index into the link inputs
  std::string name;
  std::size_t provider = kUnboundImport;  ///< index into the link inputs, or kUnboundImport
  std::uint64_t address = 0;              ///< the provider's address for the export; 0 if unbound
  std::string library;  ///< the provider's soname (ELF) or file name (PE); "" if unbound
};

struct LinkResult {
  std::vector<ImportBinding> bindings;  ///< in input order, then symbol order
  std::size_t unbound = 0;              ///< the number of bindings with no provider
};

/// Binds every import of every input. A null image is skipped. A provider must export the name
/// with a non-zero address, and must be one of the libraries the importer names: an ELF import
/// is matched by the DT_NEEDED entries (against the provider's soname or file name), a PE import
/// by its DLL name (against the provider's file name), and any other format by name alone.
[[nodiscard]] LinkResult resolve_imports(std::span<const LinkInput> inputs);

}  // namespace donkey
