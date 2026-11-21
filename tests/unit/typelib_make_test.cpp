// The type library generator (G22-T2): splitting preprocessed C into declarations, keeping what
// Donkey's parser accepts and listing the rest, and the shipped musl library.

#include <gtest/gtest.h>

#include <map>
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

// A pragma that may change a layout is not dropped: the input is refused. Pragmas known to change
// no type pass, as before.
TEST(TypeLibMake, LayoutPragmasAreRefused) {
  for (const char* pragma :
       {"#pragma pack(push, 1)\n", "  #  pragma pack(1)\n",
        "#pragma scalar_storage_order big-endian\n", "#pragma something_unknown\n"}) {
    SCOPED_TRACE(pragma);
    const auto made = donkey::make_type_library(
        std::string(pragma) + "struct s { char c; int i; };\n", test_options());
    ASSERT_FALSE(made.has_value());
    EXPECT_EQ(made.diagnostic().code, "typelib_make.pragma");
  }
  const auto harmless = donkey::make_type_library(
      "  #  pragma GCC diagnostic push\nstruct s { char c; int i; };\n#pragma GCC diagnostic pop\n",
      test_options());
  ASSERT_TRUE(harmless.has_value()) << harmless.diagnostic().message;
  EXPECT_EQ(harmless.value().kept, 1U);
}

// Comments in the input (gcc -C keeps them) are spaces: they neither join declarations nor count
// as delimiters.
TEST(TypeLibMake, CommentsAreSpaces) {
  const auto made = donkey::make_type_library(
      "typedef int A; // note\n"
      "typedef int B; /* a ; { } */ typedef int C;\n"
      "/* unterminated ; ",
      test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  EXPECT_EQ(made.value().kept, 3U);
  EXPECT_TRUE(made.value().skipped.empty());
  const auto split = donkey::split_c_declarations("typedef int A; // ;\ntypedef int B;\n");
  ASSERT_EQ(split.size(), 2U);
  // A pragma inside a comment is not one; a directive after a comment on its line is; and a "/*"
  // inside a literal opens no comment that could hide a pragma.
  const auto commented = donkey::make_type_library(
      "/*\n#pragma pack(1)\n*/\ntypedef int A;\n// #pragma pack(2)\ntypedef int B;\n",
      test_options());
  ASSERT_TRUE(commented.has_value()) << commented.diagnostic().message;
  EXPECT_EQ(commented.value().kept, 2U);
  for (const char* input :
       {"/* note */ #pragma pack(1)\nstruct s { char c; int i; };\n",
        "const char *p = \"/*\";\n#pragma pack(1)\nstruct s { char c; int i; };\n"}) {
    SCOPED_TRACE(input);
    const auto refused = donkey::make_type_library(input, test_options());
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.diagnostic().code, "typelib_make.pragma");
  }
}

// Bit-field rules come from the ABI and the platform: AAPCS64 on Linux is modelled, Apple arm64 is
// not, so a declaration with a bit-field is skipped there and the rest of the library is kept.
TEST(TypeLibMake, BitFieldsFollowTheAbiAndThePlatform) {
  EXPECT_EQ(donkey::bit_field_layout("sysv", "linux"), donkey::CBitFieldLayout::SystemV);
  EXPECT_EQ(donkey::bit_field_layout("aapcs64", "linux"), donkey::CBitFieldLayout::Aapcs64);
  EXPECT_EQ(donkey::bit_field_layout("aapcs64", "freebsd"), donkey::CBitFieldLayout::Aapcs64);
  EXPECT_EQ(donkey::bit_field_layout("aapcs64", "macos"), donkey::CBitFieldLayout::Unmodelled);
  EXPECT_EQ(donkey::bit_field_layout("win64", "windows"), donkey::CBitFieldLayout::Unmodelled);

  auto options = test_options();
  options.platform = "macos";
  options.architecture = "aarch64";
  options.abi = "aapcs64";
  options.char_is_signed = true;
  const auto made = donkey::make_type_library(
      "struct flags { unsigned a : 1; };\nstruct plain { int x; };\n", options);
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  EXPECT_EQ(made.value().kept, 1U);
  ASSERT_EQ(made.value().skipped.size(), 1U);
  EXPECT_NE(made.value().skipped[0].reason.find("cdecl.bitfield_abi"), std::string::npos);

  // A library text for Apple arm64 that does contain a bit-field is refused when read.
  options.platform = "linux";
  const auto linux_made = donkey::make_type_library("struct flags { unsigned a : 1; };\n", options);
  ASSERT_TRUE(linux_made.has_value()) << linux_made.diagnostic().message;
  std::string text = linux_made.value().text;
  const std::size_t platform = text.find("platform: linux");
  ASSERT_NE(platform, std::string::npos);
  text.replace(platform, std::string("platform: linux").size(), "platform: macos");
  const auto read = donkey::read_type_library(text);
  ASSERT_FALSE(read.has_value());
  EXPECT_NE(read.diagnostic().message.find("bit-field layout is not modelled"), std::string::npos)
      << read.diagnostic().message;
}

// An untagged enum declares no type name, but its constants are names later declarations use.
TEST(TypeLibMake, AnUntaggedEnumIsKeptForItsConstants) {
  const auto made = donkey::make_type_library(
      "typedef int ok;\nenum { N = 4 };\ntypedef int A[N];\n"
      "enum { N = 5 };\n",  // N again: skipped
      test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  EXPECT_EQ(made.value().kept, 3U);
  ASSERT_EQ(made.value().skipped.size(), 1U);
  auto library = donkey::read_type_library(made.value().text);
  ASSERT_TRUE(library.has_value()) << library.diagnostic().message;
  const auto* array_typedef = type_named(library.value(), "A", donkey::TypeKind::Typedef);
  ASSERT_NE(array_typedef, nullptr);
  const donkey::TypeDefinition* array = nullptr;
  for (const donkey::TypeDefinition& type : library.value().types) {
    if (type.id == array_typedef->target) {
      array = &type;
    }
  }
  ASSERT_NE(array, nullptr);
  EXPECT_EQ(array->count, 4U);
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

// Delimiters inside a character or string literal are not C structure: the definition of f still
// ends at its closing brace, and g is a declaration of its own.
TEST(TypeLibMake, LiteralsAreNotDelimiters) {
  const auto declarations = donkey::split_c_declarations(
      "typedef int ok; static int f(void) { return '('; } int g(void);\n"
      "static const char *h(void) { return \"};( \\\" )\"; }\n"
      "int k(void);\n");
  ASSERT_EQ(declarations.size(), 5U);
  EXPECT_EQ(declarations[0], "typedef int ok;");
  EXPECT_EQ(declarations[1], "static int f(void) { return '('; }");
  EXPECT_EQ(declarations[2], "int g(void);");
  // The literal is copied as it is, spaces and escapes included.
  EXPECT_EQ(declarations[3], "static const char *h(void) { return \"};( \\\" )\"; }");
  EXPECT_EQ(declarations[4], "int k(void);");
}

// An attribute that may change a type is never dropped: the declaration is listed as skipped with
// the attribute. One that changes neither the type nor the layout (noreturn, nonnull) is removed.
TEST(TypeLibMake, TypeChangingAttributesAreNotDropped) {
  const char* input =
      "typedef __attribute__((vector_size(16))) int v4;\n"
      "struct packed_s { char c; int i; } __attribute__((__packed__));\n"
      "typedef int aligned_t __attribute__((aligned(16)));\n"
      "void quit(int) __attribute__((__noreturn__, __nonnull__));\n";
  auto made = donkey::make_type_library(input, test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  EXPECT_EQ(made.value().kept, 1U);  // quit
  ASSERT_EQ(made.value().skipped.size(), 3U);
  for (const donkey::TypeLibrarySkipped& skipped : made.value().skipped) {
    EXPECT_NE(skipped.reason.find("attribute that may change the type"), std::string::npos)
        << skipped.name << ": " << skipped.reason;
  }
  EXPECT_NE(made.value().skipped[0].reason.find("vector_size"), std::string::npos);
  auto library = donkey::read_type_library(made.value().text);
  ASSERT_TRUE(library.has_value()) << library.diagnostic().message;
  EXPECT_EQ(type_named(library.value(), "v4", donkey::TypeKind::Typedef), nullptr);
  EXPECT_NE(type_named(library.value(), "quit", donkey::TypeKind::Function), nullptr);
}

// A tag the kept text names only by a forward reference (a pointer member) is completed by its
// definition later in the input, as one C text completes it; a second definition is refused.
TEST(TypeLibMake, AForwardReferencedTagIsCompletedByItsDefinition) {
  const char* input =
      "typedef struct entry { struct entry *next; struct info *info; } entry_t;\n"
      "struct info { int id; long size; };\n"
      "int info_of(const char *, struct info *);\n"
      "struct info { int other; };\n";
  auto made = donkey::make_type_library(input, test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  EXPECT_EQ(made.value().kept, 3U);
  ASSERT_EQ(made.value().skipped.size(), 1U);
  EXPECT_EQ(made.value().skipped[0].name, "info");
  EXPECT_NE(made.value().skipped[0].reason.find("cdecl.redefinition"), std::string::npos)
      << made.value().skipped[0].reason;
  auto library = donkey::read_type_library(made.value().text);
  ASSERT_TRUE(library.has_value()) << library.diagnostic().message;
  const auto* info = type_named(library.value(), "info", donkey::TypeKind::Struct);
  ASSERT_NE(info, nullptr);
  ASSERT_EQ(info->fields.size(), 2U);
  EXPECT_EQ(info->fields[1].name, "size");
  EXPECT_EQ(info->fields[1].offset, 8U);
  EXPECT_EQ(info->size, 16U);
}

// A skipped record names the declarator the parser refused, not the last name in the group.
TEST(TypeLibMake, ASkippedRecordNamesTheRefusedDeclarator) {
  auto made = donkey::make_type_library("int f(void);\nextern int optind, opterr, optopt;\n",
                                        test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  ASSERT_EQ(made.value().skipped.size(), 1U);
  EXPECT_EQ(made.value().skipped[0].name, "optind");
  // The position is the declaration's own ("line 1"), not the kept text's.
  EXPECT_NE(made.value().skipped[0].reason.find("line 1,"), std::string::npos)
      << made.value().skipped[0].reason;
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
  // struct sigaltstack is named first by a forward reference (stack_t), then defined: kept whole.
  const auto* sigaltstack = type_named(library.value(), "sigaltstack", donkey::TypeKind::Struct);
  ASSERT_NE(sigaltstack, nullptr);
  ASSERT_EQ(sigaltstack->fields.size(), 3U);
  EXPECT_EQ(sigaltstack->fields[2].name, "ss_size");
  EXPECT_EQ(sigaltstack->size, 24U);
  // Layouts that need bit-fields and constant expressions: musl's timespec pads with
  // `int :8*(sizeof(time_t)-sizeof(long))*(1234==4321);`, and sigset_t, pthread_attr_t, fd_set and
  // the rest size their arrays with `sizeof`. The sizes, alignments and offsets are GCC's for the
  // same musl-dev 1.2.4-2 headers on x86-64.
  donkey::TypeTable table;
  for (const donkey::TypeDefinition& type : library.value().types) {
    table.put(type);
  }
  // A name may be a typedef or, for `typedef struct { ... } name;`, the struct itself.
  const auto type_or_typedef = [&](const std::string& name) -> const donkey::TypeDefinition* {
    for (const donkey::TypeDefinition& type : library.value().types) {
      if (type.name == name &&
          (type.kind == donkey::TypeKind::Typedef || type.kind == donkey::TypeKind::Struct ||
           type.kind == donkey::TypeKind::Union)) {
        return &type;
      }
    }
    return nullptr;
  };
  struct Expected {
    const char* name;
    std::uint64_t size;
    std::uint64_t alignment;
  };
  for (const Expected& expected :
       {Expected{"stat", 144, 8}, Expected{"timespec", 16, 8}, Expected{"itimerspec", 32, 8},
        Expected{"sigset_t", 128, 8}, Expected{"pthread_attr_t", 56, 8},
        Expected{"pthread_mutex_t", 40, 8}, Expected{"fd_set", 128, 8}, Expected{"fenv_t", 32, 4},
        Expected{"cpu_set_t", 128, 8}, Expected{"jmp_buf", 200, 8}, Expected{"sem_t", 32, 4}}) {
    SCOPED_TRACE(expected.name);
    const auto* type = type_or_typedef(expected.name);
    if (type == nullptr) {
      ADD_FAILURE() << "missing";
      continue;
    }
    const auto size = table.size_of(type->id);
    const auto alignment = table.alignment_of(type->id);
    if (!size || !alignment) {
      ADD_FAILURE() << "no layout";
      continue;
    }
    EXPECT_EQ(size.value(), expected.size);
    EXPECT_EQ(alignment.value(), expected.alignment);
  }
  const auto* stat = type_named(library.value(), "stat", donkey::TypeKind::Struct);
  ASSERT_NE(stat, nullptr);
  std::map<std::string, std::uint64_t> offsets;
  for (const donkey::TypeField& field : stat->fields) {
    offsets[field.name] = field.offset;
  }
  EXPECT_EQ(offsets["st_size"], 48U);
  EXPECT_EQ(offsets["st_atim"], 72U);
  EXPECT_EQ(offsets["st_ctim"], 104U);
  // pthread_create takes a function pointer, a parenthesised declarator the subset does not
  // parse: it is listed as skipped, not dropped.
  bool listed = false;
  for (const donkey::TypeLibrarySkipped& skipped : library.value().skipped) {
    listed = listed || (skipped.name == "pthread_create" &&
                        skipped.reason.find("cdecl.parenthesized_declarator") != std::string::npos);
  }
  EXPECT_TRUE(listed);
}

// An assembler label gives a declaration another symbol name. The format cannot record it, so
// the declaration is skipped rather than kept under the wrong name.
TEST(TypeLibMake, AnAssemblerLabelIsSkipped) {
  const auto made = donkey::make_type_library(
      "int public_api(int) __asm__(\"real_api\");\nint plain(int);\n", test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  EXPECT_EQ(made.value().kept, 1U);
  ASSERT_EQ(made.value().skipped.size(), 1U);
  EXPECT_EQ(made.value().skipped[0].name, "public_api");
  EXPECT_NE(made.value().skipped[0].reason.find("__asm__(\"real_api\")"), std::string::npos)
      << made.value().skipped[0].reason;
  const std::string& text = made.value().text;
  EXPECT_EQ(text.find("public_api", text.find("\n\n")), std::string::npos);  // not in the body
}

// Every declaration of an assembler-labelled name is skipped, in either order: an unlabelled
// redeclaration would otherwise keep the prototype under the wrong symbol name.
TEST(TypeLibMake, EveryDeclarationOfALabelledNameIsSkipped) {
  for (const char* text : {"int f(int) __asm__(\"actual_f\");\nint f(int);\nint g(int);\n",
                           "int f(int);\nint f(int) __asm__(\"actual_f\");\nint g(int);\n"}) {
    SCOPED_TRACE(text);
    const auto made = donkey::make_type_library(text, test_options());
    ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
    EXPECT_EQ(made.value().kept, 1U);  // g
    ASSERT_EQ(made.value().skipped.size(), 2U);
    EXPECT_EQ(made.value().skipped[0].name, "f");
    EXPECT_EQ(made.value().skipped[1].name, "f");
  }
}

// A tag with the name of a relabelled function is another name (glibc's `struct stat` beside
// `stat() __asm__("stat64")`): the struct and its layout are kept.
TEST(TypeLibMake, ATagNamedLikeALabelledFunctionIsKept) {
  const auto made = donkey::make_type_library(
      "struct stat { long size; };\n"
      "int stat(const char *, struct stat *) __asm__(\"stat64\");\n",
      test_options());
  ASSERT_TRUE(made.has_value()) << made.diagnostic().message;
  ASSERT_EQ(made.value().skipped.size(), 1U);
  EXPECT_EQ(made.value().skipped[0].name, "stat");
  EXPECT_NE(made.value().skipped[0].reason.find("__asm__"), std::string::npos)
      << made.value().skipped[0].reason;
  EXPECT_NE(made.value().text.find("struct stat {"), std::string::npos) << made.value().text;
}
