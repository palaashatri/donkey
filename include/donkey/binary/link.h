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
};

/// Reads DT_SONAME and DT_NEEDED from the `.dynamic` section of an ELF image. Both are empty for
/// other formats and for an image without a dynamic section.
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
