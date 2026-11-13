#include <gtest/gtest.h>

#include <string>

#include "donkey/binary/image.h"
#include "donkey/binary/rtti.h"

// MSVC RTTI (G10-T3): the x64 PE fixture tests/fixtures/rtti/msvc/hierarchy.exe (see its
// PROVENANCE.md). The expected classes, bases and vtable slot counts come from the source file, not
// from the reader.

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/" + name;
}

const donkey::RttiClass* named_class(const donkey::RttiInfo& info, const std::string& name) {
  for (const donkey::RttiClass& cls : info.classes) {
    if (cls.name == name) {
      return &cls;
    }
  }
  return nullptr;
}

}  // namespace

TEST(RttiMsvc, ReadsTheClassesOfAnX64PeImage) {
  auto loaded = donkey::load_binary(fixture("rtti/msvc/hierarchy.exe"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().code;
  auto info = donkey::read_msvc_rtti(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(info.has_value()) << info.diagnostic().code;
  EXPECT_FALSE(info.value().partial);
  ASSERT_EQ(info.value().classes.size(), 5U);
  for (const char* name : {"Shape", "Square", "Tagged", "Named", "Cube"}) {
    EXPECT_NE(named_class(info.value(), name), nullptr) << name;
  }
}

TEST(RttiMsvc, BasesAreTheDirectBasesInDeclarationOrder) {
  auto loaded = donkey::load_binary(fixture("rtti/msvc/hierarchy.exe"));
  ASSERT_TRUE(loaded.has_value());
  auto info = donkey::read_msvc_rtti(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(info.has_value());
  const donkey::RttiClass* shape = named_class(info.value(), "Shape");
  const donkey::RttiClass* square = named_class(info.value(), "Square");
  const donkey::RttiClass* tagged = named_class(info.value(), "Tagged");
  const donkey::RttiClass* named = named_class(info.value(), "Named");
  ASSERT_NE(shape, nullptr);
  ASSERT_NE(square, nullptr);
  ASSERT_NE(tagged, nullptr);
  ASSERT_NE(named, nullptr);
  EXPECT_TRUE(shape->bases.empty());
  EXPECT_TRUE(named->bases.empty());
  ASSERT_EQ(square->bases.size(), 1U);
  EXPECT_EQ(square->bases[0], shape->typeinfo_address);
  ASSERT_EQ(tagged->bases.size(), 2U);
  EXPECT_EQ(tagged->bases[0], shape->typeinfo_address);
  EXPECT_EQ(tagged->bases[1], named->typeinfo_address);
  // Cube derives from Square, which derives from Shape. Its hierarchy array lists Shape too, as an
  // indirect base: only Square is a direct base.
  const donkey::RttiClass* cube = named_class(info.value(), "Cube");
  ASSERT_NE(cube, nullptr);
  ASSERT_EQ(cube->bases.size(), 1U);
  EXPECT_EQ(cube->bases[0], square->typeinfo_address);
  EXPECT_EQ(cube->kind, donkey::RttiKind::Single);
  EXPECT_EQ(shape->kind, donkey::RttiKind::Class);
  EXPECT_EQ(square->kind, donkey::RttiKind::Single);
  EXPECT_EQ(tagged->kind, donkey::RttiKind::Multiple);
}

TEST(RttiMsvc, EachVtableGroupHasTheSourcesVirtualFunctions) {
  auto loaded = donkey::load_binary(fixture("rtti/msvc/hierarchy.exe"));
  ASSERT_TRUE(loaded.has_value());
  auto info = donkey::read_msvc_rtti(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(info.has_value());
  const donkey::RttiClass* square = named_class(info.value(), "Square");
  ASSERT_NE(square, nullptr);
  ASSERT_EQ(square->groups.size(), 1U);
  EXPECT_EQ(square->groups[0].slots.size(), 3U);  // destructor, area, label
  const donkey::RttiClass* tagged = named_class(info.value(), "Tagged");
  ASSERT_NE(tagged, nullptr);
  ASSERT_EQ(tagged->groups.size(), 2U);  // the primary, then the Named subobject
  EXPECT_EQ(tagged->groups[0].offset_to_top, 0);
  EXPECT_EQ(tagged->groups[0].slots.size(), 3U);
  EXPECT_EQ(tagged->groups[1].offset_to_top, -16);
  EXPECT_EQ(tagged->groups[1].slots.size(), 2U);  // name, rank
  const donkey::RttiClass* named = named_class(info.value(), "Named");
  ASSERT_NE(named, nullptr);
  ASSERT_EQ(named->groups.size(), 1U);
  EXPECT_EQ(named->groups[0].slots.size(), 2U);
  const donkey::RttiClass* cube = named_class(info.value(), "Cube");
  ASSERT_NE(cube, nullptr);
  ASSERT_EQ(cube->groups.size(), 1U);
  EXPECT_EQ(cube->groups[0].slots.size(), 3U);  // destructor, area (override), label (inherited)
  // The slots point at code: the destructor of Square is the first slot of its primary vtable.
  for (const donkey::RttiSlot& slot : square->groups[0].slots) {
    EXPECT_NE(loaded.value().image.section_for_va(slot.address), nullptr);
  }
}

TEST(RttiMsvc, TheVtableOfSquareIsWhereItsLocatorIsReferenced) {
  auto loaded = donkey::load_binary(fixture("rtti/msvc/hierarchy.exe"));
  ASSERT_TRUE(loaded.has_value());
  auto info = donkey::read_msvc_rtti(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(info.has_value());
  const donkey::RttiClass* square = named_class(info.value(), "Square");
  ASSERT_NE(square, nullptr);
  // The locator sits at RVA 0x2020 and slot -1 of the vtable at RVA 0x2008 refers to it (the object
  // file dump in PROVENANCE.md); the vtable is therefore at image base + 0x2008.
  EXPECT_EQ(square->vtable_address, loaded.value().image.image_base + 0x2008);
}

TEST(RttiMsvc, AnElfImageIsRefusedByThisReader) {
  auto loaded = donkey::load_binary(fixture("rtti/hierarchy-aarch64-nopie"));
  if (!loaded.has_value()) {
    GTEST_SKIP() << "the AArch64 fixture is not present";
  }
  auto refused = donkey::read_msvc_rtti(loaded.value().image, loaded.value().data);
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "rtti.unsupported_image");
  auto dispatched = donkey::read_rtti(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(dispatched.has_value());
  EXPECT_FALSE(dispatched.value().classes.empty());
}
