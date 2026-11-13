#pragma once

// PLT stubs of ELF images: which imported name each stub calls (G15-T2). Reads the image's bytes
// only; nothing is run.

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>

#include "donkey/binary/image.h"

namespace donkey {

/// The stubs of an ELF image's `.plt` and `.plt.sec` sections, keyed by stub address, each with the
/// imported name its JUMP_SLOT relocation names. The x86-64 form (an indirect jump through the GOT
/// slot, after an optional ENDBR64 or BND prefix) and the AArch64 form (ADRP, LDR, ADD, BR) are
/// read. PLT0 and any other stub form are not listed, so a stub is never given a guessed name.
[[nodiscard]] std::map<std::uint64_t, std::string> plt_stub_imports(
    const BinaryImage& image, std::span<const std::byte> data);

/// The GOT slots of an x86-64 ELF image that a GLOB_DAT relocation in `.rela.dyn` names, keyed by
/// slot address, each with the imported name. Code built with -fno-plt calls such an import with
/// `call *slot(%rip)`, which reads the slot instead of going through a stub. A slot is listed only
/// when a relocation names it. AArch64 GOT loads are not read, and neither is a slot that code
/// reaches only through a register it loaded first.
[[nodiscard]] std::map<std::uint64_t, std::string> got_import_slots(
    const BinaryImage& image, std::span<const std::byte> data);

}  // namespace donkey
