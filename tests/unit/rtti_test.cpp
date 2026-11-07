#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/binary/rtti.h"

namespace {

donkey::RttiInfo read_classes(const std::string& path) {
  auto loaded = donkey::load_binary(path);
  EXPECT_TRUE(loaded.has_value()) << path;
  if (!loaded) {
    return {};
  }
  auto info = donkey::read_itanium_rtti(loaded.value().image, loaded.value().data);
  EXPECT_TRUE(info.has_value()) << info.diagnostic().code;
  return info.has_value() ? info.value() : donkey::RttiInfo{};
}

const donkey::RttiClass* named_class(const donkey::RttiInfo& info, const std::string& name) {
  for (const auto& cls : info.classes) {
    if (cls.name == name) {
      return &cls;
    }
  }
  return nullptr;
}

std::vector<std::string> slot_names(const donkey::RttiVtableGroup& group) {
  std::vector<std::string> names;
  for (const auto& slot : group.slots) {
    names.push_back(slot.pure_virtual ? slot.name + " [pure]" : slot.name);
  }
  return names;
}

/// The class graph and vtables of tests/fixtures/rtti/hierarchy.cpp. The expected names
/// and slots were read from `gdb` on the non-PIE build (`x/a` of each vtable and typeinfo),
/// and the PIE build must give the same graph.
void expect_hierarchy(const donkey::RttiInfo& info) {
  EXPECT_FALSE(info.partial);
  EXPECT_EQ(info.classes.size(), 6U);

  const auto* shape = named_class(info, "Shape");
  ASSERT_NE(shape, nullptr);
  EXPECT_EQ(shape->kind, donkey::RttiKind::Class);
  EXPECT_TRUE(shape->bases.empty());
  ASSERT_EQ(shape->groups.size(), 1U);
  // The two destructor slots of an abstract class are compiler-dependent: GCC leaves them null
  // (the gdb oracle), Clang fills them with the destructor. Both are accepted; the rest is exact.
  const auto& shape_slots = shape->groups[0].slots;
  ASSERT_EQ(shape_slots.size(), 4U);
  for (std::size_t i = 0; i < 2; ++i) {
    const bool null_slot = shape_slots[i].address == 0 && shape_slots[i].name.empty();
    const bool destructor = shape_slots[i].name == "Shape::~Shape()";
    EXPECT_TRUE(null_slot || destructor) << "slot " << i << " is " << shape_slots[i].name;
  }
  EXPECT_EQ(shape_slots[2].name, "__cxa_pure_virtual");
  EXPECT_TRUE(shape_slots[2].pure_virtual);
  EXPECT_EQ(shape_slots[3].name, "Shape::label() const");

  const auto* named = named_class(info, "Named");
  ASSERT_NE(named, nullptr);
  EXPECT_EQ(named->kind, donkey::RttiKind::Class);
  ASSERT_EQ(named->groups.size(), 1U);
  EXPECT_EQ(slot_names(named->groups[0]),
            (std::vector<std::string>{"Named::name() const", "Named::rank() const"}));

  const auto* lone = named_class(info, "Lone");
  ASSERT_NE(lone, nullptr);
  EXPECT_EQ(lone->kind, donkey::RttiKind::Class);
  ASSERT_EQ(lone->groups.size(), 1U);
  EXPECT_EQ(slot_names(lone->groups[0]),
            (std::vector<std::string>{"Lone::ping()", "Lone::pong(int)"}));

  const auto* square = named_class(info, "Square");
  ASSERT_NE(square, nullptr);
  EXPECT_EQ(square->kind, donkey::RttiKind::Single);
  ASSERT_EQ(square->bases.size(), 1U);
  EXPECT_EQ(square->bases[0], shape->typeinfo_address);
  ASSERT_EQ(square->groups.size(), 1U);
  EXPECT_EQ(slot_names(square->groups[0]),
            (std::vector<std::string>{"Square::~Square()", "Square::~Square()",
                                      "Square::area() const", "Square::label() const"}));

  const auto* cube = named_class(info, "Cube");
  ASSERT_NE(cube, nullptr);
  EXPECT_EQ(cube->kind, donkey::RttiKind::Single);
  ASSERT_EQ(cube->bases.size(), 1U);
  EXPECT_EQ(cube->bases[0], square->typeinfo_address);
  EXPECT_EQ(slot_names(cube->groups[0]),
            (std::vector<std::string>{"Cube::~Cube()", "Cube::~Cube()", "Cube::area() const",
                                      "Square::label() const"}));

  // Two bases: the primary group, then the Named subobject's group, whose offset-to-top is -16
  // and whose first entry is the thunk that adjusts `this` before `Tagged::name()`.
  const auto* tagged = named_class(info, "Tagged");
  ASSERT_NE(tagged, nullptr);
  EXPECT_EQ(tagged->kind, donkey::RttiKind::Multiple);
  ASSERT_EQ(tagged->bases.size(), 2U);
  EXPECT_EQ(tagged->bases[0], shape->typeinfo_address);
  EXPECT_EQ(tagged->bases[1], named->typeinfo_address);
  ASSERT_EQ(tagged->groups.size(), 2U);
  EXPECT_EQ(tagged->groups[0].offset_to_top, 0);
  EXPECT_EQ(
      slot_names(tagged->groups[0]),
      (std::vector<std::string>{"Tagged::~Tagged()", "Tagged::~Tagged()", "Tagged::area() const",
                                "Shape::label() const", "Tagged::name() const"}));
  EXPECT_EQ(tagged->groups[1].offset_to_top, -16);
  EXPECT_EQ(slot_names(tagged->groups[1]),
            (std::vector<std::string>{"non-virtual thunk to Tagged::name() const",
                                      "Named::rank() const"}));

  // The lookup by typeinfo address finds the same class.
  const auto* found = donkey::find_rtti_class(info, square->typeinfo_address);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->name, "Square");
  EXPECT_EQ(donkey::find_rtti_class(info, 1), nullptr);
}

/// The file's bytes with every pointer that a RELATIVE relocation fills set to zero. What is
/// left in the file is then only the relocation table, so the reader can learn those
/// pointers from `.rela.dyn` alone.
std::vector<std::byte> without_relative_pointers(const donkey::LoadedBinary& loaded) {
  std::vector<std::byte> bytes = loaded.data.to_vector();
  auto u64_at = [&bytes](std::uint64_t offset) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
      value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset + i]))
               << (8 * i);
    }
    return value;
  };
  constexpr std::uint64_t kRelativeX86_64 = 8;
  for (const auto& section : loaded.image.sections) {
    if (section.name != ".rela.dyn") {
      continue;
    }
    for (std::uint64_t entry = section.file_offset;
         entry + 24 <= section.file_offset + section.file_size; entry += 24) {
      if ((u64_at(entry + 8) & 0xffffffffU) != kRelativeX86_64) {
        continue;
      }
      const auto place = loaded.image.va_to_file_offset(u64_at(entry));
      if (!place) {
        continue;
      }
      for (std::uint64_t i = 0; i < 8; ++i) {
        bytes[place.value() + i] = std::byte{0};
      }
    }
  }
  return bytes;
}

}  // namespace

// Position-independent executables store every vtable pointer as a relocation addend; the
// non-PIE build stores it in the file. Both must describe the same classes.
TEST(Rtti, ReadsThePieHierarchyFromRelocations) {
  expect_hierarchy(read_classes(DONKEY_TEST_HIERARCHY_PATH));
}

TEST(Rtti, PiePointersComeFromTheRelocationTableNotTheFile) {
  auto loaded = donkey::load_binary(DONKEY_TEST_HIERARCHY_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const std::vector<std::byte> zeroed = without_relative_pointers(loaded.value());
  // The copy differs from the file only in relocated places, and it must still describe the
  // same hierarchy: the vtable and typeinfo pointers come from `.rela.dyn` alone.
  EXPECT_NE(zeroed, loaded.value().data.to_vector());
  auto info = donkey::read_itanium_rtti(loaded.value().image, zeroed);
  ASSERT_TRUE(info.has_value()) << info.diagnostic().code;
  expect_hierarchy(info.value());
}

TEST(Rtti, ReadsTheNonPieHierarchyFromTheFile) {
  expect_hierarchy(read_classes(DONKEY_TEST_HIERARCHY_NOPIE_PATH));
}

// AArch64 builds of the same source (tests/fixtures/rtti/PROVENANCE.md). Their PLT entries load
// the GOT slot with ADRP and LDR, so the pure-virtual slot is named through its JUMP_SLOT, and
// the graph is complete (not partial).
TEST(Rtti, ReadsTheAArch64NonPieHierarchyWithItsPltNames) {
  expect_hierarchy(read_classes(std::string(DONKEY_FIXTURE_DIR) + "/rtti/hierarchy-aarch64-nopie"));
}

TEST(Rtti, ReadsTheAArch64PieHierarchyFromRelocations) {
  expect_hierarchy(read_classes(std::string(DONKEY_FIXTURE_DIR) + "/rtti/hierarchy-aarch64-pie"));
}

TEST(Rtti, AnImageWithoutItaniumTypeinfoHasNoClasses) {
  const auto info = read_classes(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-elf-x86_64");
  EXPECT_TRUE(info.classes.empty());
  EXPECT_FALSE(info.partial);
}

TEST(Rtti, OtherFormatsAreUnsupportedNotGuessed) {
  auto loaded =
      donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-pe-x86_64.exe");
  ASSERT_TRUE(loaded.has_value());
  const auto info = donkey::read_itanium_rtti(loaded.value().image, loaded.value().data);
  ASSERT_FALSE(info.has_value());
  EXPECT_EQ(info.diagnostic().status, donkey::Status::Unsupported);
  EXPECT_EQ(info.diagnostic().code, "rtti.unsupported_image");
}
