#pragma once

// Linking an ELF relocatable object (`ET_REL`, a `.o` file) for analysis (G15-T1).
// The allocated sections are laid out one after another from kObjectBase, the file is
// copied, and the copy's section bodies are patched with the relocations that apply.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// Where the first allocated section of an object is placed. Zero is avoided: it reads
/// as "no address" elsewhere in the analysis.
inline constexpr std::uint64_t kObjectBase = 0x1000;

/// True for an ELF64 file whose type is ET_REL.
[[nodiscard]] bool is_relocatable_elf(std::span<const std::byte> file);

/// Lays out and relocates the object in `file`. Returns the bytes to analyse: the file
/// itself, followed by a copy of each allocated section (a section's file_offset then
/// points into the copy). `image` gets the layout addresses, the symbol addresses, and
/// a diagnostic for every relocation that cannot be applied, which also sets `partial`.
/// Relocations in non-allocated sections (debug information) are not applied and are
/// not reported. A malformed section table is an error.
[[nodiscard]] Result<std::vector<std::byte>> link_relocatable_object(
    std::span<const std::byte> file, BinaryImage& image);

}  // namespace donkey
