// The type library generator (G22-T2): splitting preprocessed C into declarations, keeping what
// Donkey's parser accepts and listing the rest, and the shipped musl library.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "donkey/project/typelib.h"
#include "donkey/project/typelib_gen.h"
#include "donkey/project/types.h"

namespace {

donkey::TypeLibraryMakeOptions test_options() {
  donkey::TypeLibraryMakeOptions options;
  options.library = "test-lib";
  options.library_version = "1";
  options.source = "unit test input";
  options.source_sha256 = std::string(64, '0');
  options.licence = "MIT";
  options.licence_file = "LICENSE";
  options.licence_sha256 = std::string(64, '1');
  options.generator_command = "unit test";
  options.preprocessor = "none";
  options.created = "2026-11-17";
  return options;
}

const donkey::TypeDefinition* type_named(const donkey::TypeLibrary& library,
                                         const std::string& name, donkey::TypeKind kind) {
  for (const donkey::TypeDefinition& type : library.types) {
    if (type.name == name && type.kind == kind) {
      return &type;
    }
  }
  return nullptr;
}

}  // namespace

TEST(TypeLibMake, SplitsTopLevelDeclarations) {
  const auto declarations = donkey::split_c_declarations(
      "# 1 \"x.h\"\n"
      "typedef unsigned long size_t;\n"
      "struct point {\n  int x;\n  int y;\n};\n"
      "int add(int a, int b) { return a + b; }\n"
      "void *memcpy(void *restrict, const void *restrict, size_t)"
      " __attribute__((__nonnull__(1, 2)));\n");
  ASSERT_EQ(declarations.size(), 4U);
  EXPECT_EQ(declarations[0], "typedef unsigned long size_t;");
  EXPECT_EQ(declarations[1], "struct point { int x; int y; };");
  EXPECT_EQ(declarations[2], "int add(int a, int b) { return a + b; }");
  EXPECT_EQ(declarations[3], "void *memcpy(void *, const void *, size_t);");
}

TEST(TypeLibMake, KeepsWhatParsesAndListsTheRest) {
  const char* input =
      "typedef int myint;\n"
      "extern int counter;\n"  // a variable: not a type
      "struct s { myint a; };\n"
      "static int twice(int a) { return a * 2; }\n"  // a definition
      "int use(struct s *);\n"
      "int use(struct s *);\n"                // declared again
      "unknown_t broken(void);\n"             // an unknown type
      "struct t { struct gone member; };\n";  // a member of an unknown struct
  auto made = donkey::make_type_library(input, test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  EXPECT_EQ(made.value().kept, 3U);
  std::vector<std::string> skipped;
  for (const donkey::TypeLibrarySkipped& entry : made.value().skipped) {
    skipped.push_back(entry.name);
  }
  EXPECT_EQ(skipped, (std::vector<std::string>{"counter", "twice", "use", "broken", "t"}));
  EXPECT_FALSE(made.value().skipped[0].reason.empty());  // the parser refuses a variable
  EXPECT_NE(made.value().skipped[1].reason.find("function definition"), std::string::npos);
  EXPECT_NE(made.value().skipped[2].reason.find("declared again"), std::string::npos);
  EXPECT_NE(made.value().skipped[3].reason.find("cdecl."), std::string::npos);

  // The text reads back, with every skipped declaration listed and the kept types present.
  auto library = donkey::read_type_library(made.value().text);
  ASSERT_TRUE(library.has_value()) << library.diagnostic().message;
  EXPECT_EQ(library.value().skipped.size(), 5U);
  EXPECT_EQ(library.value().generator, std::string(donkey::kTypeLibraryGenerator));
  EXPECT_NE(type_named(library.value(), "use", donkey::TypeKind::Function), nullptr);
  EXPECT_NE(type_named(library.value(), "s", donkey::TypeKind::Struct), nullptr);
  EXPECT_EQ(type_named(library.value(), "t", donkey::TypeKind::Struct), nullptr);
}

TEST(TypeLibMake, RefusesAnInputWithNothingKept) {
  auto made = donkey::make_type_library("extern int only_a_variable;\n", test_options());
  ASSERT_FALSE(made.has_value());
  EXPECT_EQ(made.diagnostic().code, "typelib_make.empty");
}

TEST(TypeLibMake, RefusesOptionsTheFormatRefuses) {
  donkey::TypeLibraryMakeOptions options = test_options();
  options.created = "17 November";
  auto made = donkey::make_type_library("int f(void);\n", options);
  ASSERT_FALSE(made.has_value());
  EXPECT_EQ(made.diagnostic().code.rfind("typelib.", 0), 0U) << made.diagnostic().code;
}

// The shipped library (typelibs/musl-1.2.4-x86_64-linux.dtl, made by tools/typelib/make-musl.sh):
// it loads, and the prototypes of the C library's common functions are in it.
TEST(TypeLibMake, ShippedMuslLibraryLoads) {
  auto library = donkey::load_type_library(std::string(DONKEY_FIXTURE_DIR) +
                                           "/../../typelibs/musl-1.2.4-x86_64-linux.dtl");
  ASSERT_TRUE(library.has_value()) << library.diagnostic().message;
  EXPECT_EQ(library.value().library, "musl-libc");
  EXPECT_EQ(library.value().licence, "MIT");
  EXPECT_GE(library.value().source_files.size(), 80U);
  for (const char* name : {"puts", "memcpy", "strlen", "malloc", "open", "fopen"}) {
    const auto* function = type_named(library.value(), name, donkey::TypeKind::Function);
    ASSERT_NE(function, nullptr) << name;
    EXPECT_EQ(function->provenance, donkey::TypeProvenance::Library) << name;
  }
  const auto* printf_type = type_named(library.value(), "printf", donkey::TypeKind::Function);
  ASSERT_NE(printf_type, nullptr);
  EXPECT_TRUE(printf_type->variadic);
  EXPECT_NE(type_named(library.value(), "stat", donkey::TypeKind::Struct), nullptr);
  // pthread_attr_t's layout uses `sizeof` in an array bound, which the parser does not evaluate:
  // it and the functions that name it are listed as skipped, not dropped.
  bool listed = false;
  for (const donkey::TypeLibrarySkipped& skipped : library.value().skipped) {
    listed = listed || skipped.name == "pthread_create";
  }
  EXPECT_TRUE(listed);
}
