#pragma once

// ELF initialisation and termination functions (G24): the functions the loader or the C runtime
// calls before and after main, which no call in the image reaches. They are named by the dynamic
// tags DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY and DT_PREINIT_ARRAY (with their *SZ sizes),
// and, in an image with section headers, by the `.init` and `.fini` sections and the
// `.init_array`, `.fini_array` and `.preinit_array` sections. An array entry is the value its
// R_*_RELATIVE relocation gives, or the file's bytes when no relocation covers it; an entry with a
// symbolic relocation names another image and is not a start here. Reads bytes only.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// Entries read from one array before the reader stops.
inline constexpr std::size_t kInitFiniMaxEntries = std::size_t{1} << 16;

struct InitFiniStarts {
  /// The starts, ascending and without repeats. They are not yet checked to be in executable code.
  std::vector<std::uint64_t> starts;
  /// Array entries or tags that could not be read (outside the file, a size that is not a whole
  /// number of pointers, more entries than the limit). Starts they name may be missing.
  std::size_t unreadable = 0;
};

/// The initialisation and termination function starts of an ELF image; none for another format.
[[nodiscard]] InitFiniStarts read_init_fini_of_image(const BinaryImage& image,
                                                     std::span<const std::byte> file);

}  // namespace donkey
