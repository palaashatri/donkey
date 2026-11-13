#pragma once

// Itanium C++ ABI RTTI and vtables (G10-T3), read from ELF images of x86-64 and AArch64.
// Classes come from the `_ZTI` typeinfo objects, their vtables from the matching `_ZTV`
// symbols. Nothing is executed and no call site is rewritten: this is a description of the
// class layout that other views and the decompiler may read.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// The shape of a class's typeinfo object, from the ABI's `__class_type_info` family.
enum class RttiKind : std::uint8_t {
  Class,     ///< no base classes (`__class_type_info`)
  Single,    ///< one base class (`__si_class_type_info`)
  Multiple,  ///< several base classes (`__vmi_class_type_info`)
};

const char* rtti_kind_name(RttiKind kind) noexcept;

/// One entry of a vtable group. `address` is 0 for a null entry (an abstract class's
/// destructor slots are null in the final image). An entry that is a symbol relocation has
/// no address here; its `name` is the symbol it names.
struct RttiSlot {
  std::uint64_t address = 0;
  std::string name;  ///< demangled symbol at `address`, or the import it calls; "" if unknown
  bool pure_virtual = false;  ///< the entry calls `__cxa_pure_virtual`
};

/// One subobject's function table inside a class's vtable symbol. Group 0 is the primary
/// vtable; later groups belong to base subobjects and have their own offset-to-top.
struct RttiVtableGroup {
  std::int64_t offset_to_top = 0;
  std::vector<RttiSlot> slots;
};

struct RttiClass {
  std::string name;             ///< demangled class name, e.g. "ns::Box"
  std::string typeinfo_symbol;  ///< the mangled `_ZTI` name
  std::uint64_t typeinfo_address = 0;
  RttiKind kind = RttiKind::Class;
  std::vector<std::uint64_t> bases;  ///< typeinfo addresses of the direct bases, in order
  std::uint64_t vtable_address = 0;  ///< 0 when no `_ZTV` symbol exists
  std::vector<RttiVtableGroup> groups;
};

struct RttiInfo {
  std::vector<RttiClass> classes;  ///< sorted by typeinfo address
  std::vector<Diagnostic> diagnostics;
  bool partial = false;
};

struct RttiOptions {
  std::size_t max_classes = 100'000;
  std::size_t max_slots = 1'000'000;
};

/// Reads the classes of an ELF image (64-bit, little-endian, x86-64 or AArch64). Other
/// images return `rtti.unsupported_image` (Unsupported). Relocations are read from
/// `.rela.dyn`, so pointers in position-independent images resolve to their addends. Malformed
/// entries become diagnostics and `partial`, never guesses.
[[nodiscard]] Result<RttiInfo> read_itanium_rtti(const BinaryImage& image,
                                                 std::span<const std::byte> data,
                                                 const RttiOptions& options = {});

/// The MSVC C++ RTTI of an x64 PE image: complete object locators, type descriptors and class
/// hierarchy descriptors (G10-T3). Names are the decorated class names read back. Slots are read
/// while the entries point at code (the MSVC vftable has no count). Other images are refused.
[[nodiscard]] Result<RttiInfo> read_msvc_rtti(const BinaryImage& image,
                                              std::span<const std::byte> data,
                                              const RttiOptions& options = {});

/// The C++ RTTI of an image by its format: Itanium for ELF, MSVC for x64 PE. Anything else is
/// refused with `rtti.unsupported_image`.
[[nodiscard]] Result<RttiInfo> read_rtti(const BinaryImage& image, std::span<const std::byte> data,
                                         const RttiOptions& options = {});

/// The class whose typeinfo object is at `typeinfo_address`, or nullptr.
[[nodiscard]] const RttiClass* find_rtti_class(const RttiInfo& info,
                                               std::uint64_t typeinfo_address) noexcept;

}  // namespace donkey
