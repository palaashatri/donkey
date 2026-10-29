#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace donkey {

/// A stable, project-scoped identifier. Editing or sorting a UI table never
/// changes these values; IDs are never pointers or row indexes.
template <typename Tag, typename Rep = std::uint64_t>
class Id {
 public:
  using rep_type = Rep;

  constexpr Id() noexcept = default;
  constexpr explicit Id(Rep value) noexcept : value_(value) {}

  [[nodiscard]] constexpr Rep value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
  constexpr explicit operator bool() const noexcept { return valid(); }

  friend constexpr auto operator<=>(const Id&, const Id&) noexcept = default;

 private:
  Rep value_{};
};

struct ImageTag;
struct SectionTag;
struct SegmentTag;
struct SymbolTag;
struct FunctionTag;
struct BasicBlockTag;
struct TypeTag;
struct CommentTag;

using ImageId = Id<ImageTag>;
using SectionId = Id<SectionTag>;
using SegmentId = Id<SegmentTag>;
using SymbolId = Id<SymbolTag>;
using FunctionId = Id<FunctionTag>;
using BasicBlockId = Id<BasicBlockTag>;
using TypeId = Id<TypeTag>;

/// What an offset is relative to. Mixing these up is the classic
/// reverse-engineering bug: never convert implicitly.
enum class AddressSpace : std::uint8_t {
  FileOffset = 0,             ///< Byte offset in the file on disk.
  ImageRva = 1,               ///< Relative virtual address (image base removed).
  ImageVa = 2,                ///< Preferred virtual address in the image.
  RuntimeVirtualAddress = 3,  ///< VA after relocation into a live process.
};

const char* address_space_name(AddressSpace space) noexcept;

/// A code or data location. The preferred image base stays separate from the
/// runtime relocation mapping, so this is not a raw pointer-sized address.
struct Location {
  ImageId image;
  AddressSpace space = AddressSpace::ImageVa;
  std::uint64_t offset = 0;

  friend constexpr auto operator<=>(const Location&, const Location&) noexcept = default;
};

}  // namespace donkey

template <typename Tag, typename Rep>
struct std::hash<donkey::Id<Tag, Rep>> {
  std::size_t operator()(const donkey::Id<Tag, Rep>& id) const noexcept {
    return std::hash<Rep>{}(id.value());
  }
};

template <>
struct std::hash<donkey::Location> {
  std::size_t operator()(const donkey::Location& location) const noexcept {
    return std::hash<std::uint64_t>{}(location.offset) ^
           (std::hash<std::uint64_t>{}(location.image.value()) << 1U) ^
           (static_cast<std::size_t>(location.space) << 7U);
  }
};
