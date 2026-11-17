// Applying a type library (G22-T3, first part): merging its types into a project table and
// matching imported names to its prototypes.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "donkey/project/cdecl.h"
#include "donkey/project/typelib.h"
#include "donkey/project/typelib_apply.h"
#include "donkey/project/types.h"
#include "donkey/core/sha256.h"
#include <span>

namespace {

const char* kLibrary =
    "donkey-typelib 1\n"
    "library: apply-test\n"
    "library_version: 1\n"
    "platform: linux\n"
    "architecture: x86_64\n"
    "abi: sysv\n"
    "data_model: LP64\n"
    "pointer_size: 8\n"
    "long_size: 8\n"
    "char_is_signed: true\n"
    "source: unit test\n"
    "source_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
    "licence: MIT\n"
    "licence_file: LICENSE\n"
    "licence_sha256: 1111111111111111111111111111111111111111111111111111111111111111\n"
    "generator: hand-written 1\n"
    "generator_command: none\n"
    "preprocessor: none\n"
    "created: 2026-11-17\n";

std::string library_text(const std::string& body) {
  donkey::TypeTable empty;
  auto parsed = donkey::parse_c_declarations(body, empty);
  EXPECT_TRUE(parsed.has_value()) << parsed.diagnostic().message;
  // body_sha256 and the declarations count, as the generator computes them.
  std::string text = kLibrary;
  text += "body_sha256: " + donkey::Sha256::hex(std::span<const std::byte>(
                                reinterpret_cast<const std::byte*>(body.data()), body.size())) +
          "\n";
  text += "declarations: " + std::to_string(parsed.value().size()) + "\n\n" + body;
  return text;
}

donkey::TypeLibrary library_of(const std::string& body, const donkey::TypeTable& known) {
  auto library = donkey::read_type_library(library_text(body), known);
  EXPECT_TRUE(library.has_value()) << library.diagnostic().message;
  return library.value();
}

}  // namespace

TEST(TypeLibApply, MergeAddsLibraryTypesWithFreshIds) {
  const donkey::TypeTable empty;
  const auto library = library_of(
      "struct point { int32_t x; int32_t y; };\nint32_t norm(const struct point *p);\n", empty);
  auto merge = donkey::merge_type_library(empty, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  EXPECT_GT(merge.value().added, 0U);
  EXPECT_TRUE(merge.value().collisions.empty());
  ASSERT_TRUE(merge.value().ordinary.contains("norm"));
  const auto* norm = merge.value().table.find(merge.value().ordinary.at("norm"));
  ASSERT_NE(norm, nullptr);
  EXPECT_EQ(norm->kind, donkey::TypeKind::Function);
  EXPECT_EQ(norm->provenance, donkey::TypeProvenance::Library);
}

// A user type with the library's name wins: the library's is not added, references move to the
// user's, and the collision is listed, with `differs` when the layouts do not match.
TEST(TypeLibApply, UserAndDebugTypesWinOverALibrary) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations("struct point { int64_t x; };\n", user);
  ASSERT_TRUE(declared.has_value());
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto library = library_of(
      "struct point { int32_t x; int32_t y; };\nint32_t norm(const struct point *p);\n", user);
  auto merge = donkey::merge_type_library(user, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  ASSERT_EQ(merge.value().collisions.size(), 1U);
  EXPECT_EQ(merge.value().collisions[0].name, "point");
  EXPECT_TRUE(merge.value().collisions[0].differs);
  // The user's struct keeps its layout: 8 bytes, one member.
  const auto* point = merge.value().table.find(merge.value().tags.at("point"));
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(point->provenance, donkey::TypeProvenance::User);
  EXPECT_EQ(point->fields.size(), 1U);
}

TEST(TypeLibApply, SameNameDifferentLayoutIsACollision) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations("struct point { int32_t x; int32_t y; };\n", user);
  ASSERT_TRUE(declared.has_value());
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto same = library_of("struct point { int32_t x; int32_t y; };\n", user);
  auto merge = donkey::merge_type_library(user, same);
  ASSERT_TRUE(merge.has_value());
  ASSERT_EQ(merge.value().collisions.size(), 1U);
  EXPECT_FALSE(merge.value().collisions[0].differs);
}

TEST(TypeLibApply, VersionedNameMatchesTheUnversionedLibraryName) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(
      empty, library_of("void *memcpy(void *, const void *, size_t);\nint puts(const char *);\n",
                        empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched = donkey::match_import_prototypes(
      {"memcpy@GLIBC_2.14", "puts", "frobnicate"}, merge.value());
  ASSERT_EQ(matched.size(), 3U);
  EXPECT_EQ(matched[0].prototype, merge.value().ordinary.at("memcpy"));
  EXPECT_EQ(matched[1].prototype, merge.value().ordinary.at("puts"));
  EXPECT_EQ(matched[2].reason, "no prototype");
  EXPECT_EQ(donkey::import_match_name("memcpy@@GLIBC_2.14"), "memcpy");
  EXPECT_EQ(donkey::import_match_name("_puts", true), "puts");
}

TEST(TypeLibApply, AmbiguousVersionsApplyNothing) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(
      empty, library_of("void *memcpy(void *, const void *, size_t);\n", empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched = donkey::match_import_prototypes(
      {"memcpy@GLIBC_2.2.5", "memcpy@GLIBC_2.14"}, merge.value());
  EXPECT_EQ(matched[0].reason, "ambiguous");
  EXPECT_EQ(matched[1].reason, "ambiguous");
  EXPECT_EQ(matched[0].prototype.value(), 0U);
}

TEST(TypeLibApply, OrdinalImportIsNotMatched) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(empty, library_of("int ordinal_7(void);\n", empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched = donkey::match_import_prototypes({"ordinal_7"}, merge.value());
  EXPECT_EQ(matched[0].reason, "ordinal import");
}

// The shipped musl library merges into an empty table, and the imports of a C program match it.
TEST(TypeLibApply, MuslLibraryGivesPrototypesToCommonImports) {
  auto library = donkey::load_type_library(std::string(DONKEY_FIXTURE_DIR) +
                                           "/../../typelibs/musl-1.2.4-x86_64-linux.dtl");
  ASSERT_TRUE(library.has_value()) << library.diagnostic().message;
  auto merge = donkey::merge_type_library(donkey::TypeTable{}, library.value());
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  const auto matched = donkey::match_import_prototypes(
      {"puts@GLIBC_2.2.5", "abort", "malloc", "strlen", "__cxa_finalize"}, merge.value());
  EXPECT_NE(matched[0].prototype.value(), 0U);
  EXPECT_NE(matched[1].prototype.value(), 0U);
  EXPECT_NE(matched[2].prototype.value(), 0U);
  EXPECT_NE(matched[3].prototype.value(), 0U);
  EXPECT_EQ(matched[4].reason, "no prototype");  // not a public musl function
}
