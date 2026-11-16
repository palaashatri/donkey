// Type library reader (G22-T1). Each refusal is checked for its exact code. The inputs are built
// here, and the body hash is computed with donkey::Sha256, so a test that is not about the hash
// still passes the hash check.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "donkey/core/sha256.h"
#include "donkey/project/cdecl.h"
#include "donkey/project/typelib.h"
#include "test_io.h"

namespace {

using Lines = std::vector<std::string>;

constexpr const char* kZeroDigest =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// A header that reads back cleanly for the body it is finalised with (see `finalize`).
Lines base_header() {
  return {
      "donkey-typelib 1",
      "library: test-lib",
      "library_version: 1.0",
      "platform: linux",
      "architecture: x86_64",
      "abi: sysv",
      "data_model: LP64",
      "pointer_size: 8",
      "long_size: 8",
      "char_is_signed: true",
      "source: written in the unit test",
      std::string("source_sha256: ") + kZeroDigest,
      "licence: MIT",
      "licence_file: LICENSE",
      std::string("licence_sha256: ") + kZeroDigest,
      "generator: unit test 1",
      "generator_command: none",
      "preprocessor: none",
      "created: 2026-11-15",
      "body_sha256: 0",
      "declarations: 0",
  };
}

/// Replaces the line for a single key, or inserts it before the first repeated record.
void put(Lines& header, const std::string& key, const std::string& value) {
  const std::string prefix = key + ": ";
  for (std::string& line : header) {
    if (line.starts_with(prefix)) {
      line = prefix + value;
      return;
    }
  }
  for (std::size_t i = 0; i < header.size(); ++i) {
    for (const char* repeated : {"source_file: ", "macro: ", "skipped: ", "note: "}) {
      if (header[i].starts_with(repeated)) {
        header.insert(header.begin() + static_cast<std::ptrdiff_t>(i), prefix + value);
        return;
      }
    }
  }
  header.push_back(prefix + value);
}

void drop(Lines& header, const std::string& key) {
  const std::string prefix = key + ": ";
  for (auto it = header.begin(); it != header.end(); ++it) {
    if (it->starts_with(prefix)) {
      header.erase(it);
      return;
    }
  }
}

/// Sets body_sha256 and declarations to match `body`, as a correct producer would.
void finalize(Lines& header, std::string_view body) {
  const auto digest = donkey::Sha256::digest(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(body.data()), body.size()));
  put(header, "body_sha256", donkey::Sha256::hex(digest));
  const auto parsed = donkey::parse_c_declarations(body, donkey::TypeTable{});
  put(header, "declarations", std::to_string(parsed ? parsed.value().size() : 0));
}

/// The file text: the header lines, the empty line, then the body exactly as given.
std::string assemble(const Lines& header, std::string_view body) {
  std::string text;
  for (const std::string& line : header) {
    text += line;
    text += '\n';
  }
  text += '\n';
  text += body;
  return text;
}

/// A file whose header is correct for `body`.
std::string valid_file(std::string_view body, Lines header = base_header()) {
  finalize(header, body);
  return assemble(header, body);
}

constexpr const char* kBody =
    "typedef int32_t handle_t;\n"
    "struct point { int32_t x; int32_t y; };\n"
    "int32_t point_sum(const struct point *points, size_t count);\n";

/// Checks that `text` is refused with `code`, and returns the diagnostic for further checks.
donkey::Diagnostic expect_refused(const std::string& text, const char* code,
                                  donkey::Status status = donkey::Status::InvalidInput,
                                  const donkey::TypeTable& known = {}) {
  const auto result = donkey::read_type_library(text, known);
  EXPECT_FALSE(result.has_value()) << code;
  if (result.has_value()) {
    return {};
  }
  EXPECT_EQ(result.diagnostic().code, code) << result.diagnostic().message;
  EXPECT_EQ(result.diagnostic().status, status) << result.diagnostic().message;
  return result.diagnostic();
}

const donkey::TypeDefinition* named(const std::vector<donkey::TypeDefinition>& types,
                                    std::string_view name) {
  for (const donkey::TypeDefinition& type : types) {
    if (type.name == name) {
      return &type;
    }
  }
  return nullptr;
}

}  // namespace

TEST(TypeLib, ReadsAHeaderAndItsDeclarations) {
  const std::filesystem::path fixture =
      std::filesystem::path(DONKEY_FIXTURE_DIR) / "types" / "typelib-small.dtl";
  const auto loaded = donkey::load_type_library(fixture);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().code << ": "
                                  << loaded.diagnostic().message;
  const donkey::TypeLibrary& library = loaded.value();

  EXPECT_EQ(library.library, "donkey-typelib-fixture");
  EXPECT_EQ(library.library_version, "1");
  EXPECT_EQ(library.platform, "linux");
  EXPECT_EQ(library.architecture, "x86_64");
  EXPECT_EQ(library.abi, "sysv");
  EXPECT_EQ(library.data_model, "LP64");
  EXPECT_EQ(library.pointer_size, 8U);
  EXPECT_EQ(library.long_size, 8U);
  EXPECT_TRUE(library.char_is_signed);
  EXPECT_EQ(library.licence, "MIT");
  EXPECT_EQ(library.created, "2026-11-15");
  EXPECT_EQ(library.body_sha256,
            "d1e0d3920f76020abd355c0da29a0acbd220e9ece046e9d86c60c500e87969aa");
  EXPECT_EQ(library.notes.size(), 1U);
  EXPECT_EQ(library.declarations, library.types.size());

  // The declarations the fixture's C text makes: an enum, a typedef, two structs, a typedef of a
  // struct and three prototypes.
  const auto* flags = named(library.types, "open_flags");
  ASSERT_NE(flags, nullptr);
  EXPECT_EQ(flags->kind, donkey::TypeKind::Enum);
  EXPECT_EQ(flags->enumerators.size(), 3U);
  const auto* handle = named(library.types, "file_handle");
  ASSERT_NE(handle, nullptr);
  EXPECT_EQ(handle->kind, donkey::TypeKind::Typedef);
  const auto* point = named(library.types, "point");
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(point->kind, donkey::TypeKind::Struct);
  EXPECT_EQ(point->size, 8U);
  EXPECT_NE(named(library.types, "point_t"), nullptr);
  const auto* open = named(library.types, "file_open");
  ASSERT_NE(open, nullptr);
  EXPECT_EQ(open->kind, donkey::TypeKind::Function);
  EXPECT_EQ(open->fields.size(), 2U);
  EXPECT_NE(named(library.types, "file_read"), nullptr);
  EXPECT_NE(named(library.types, "file_close"), nullptr);
  EXPECT_NE(named(library.types, "point_sum"), nullptr);

  // The same bytes read with no file access give the same library.
  std::ifstream in(fixture, std::ios::binary);
  const std::string text = donkey_test::read_stream<std::string>(in);
  const auto from_text = donkey::read_type_library(text);
  ASSERT_TRUE(from_text.has_value()) << from_text.diagnostic().message;
  EXPECT_EQ(from_text.value().types.size(), library.types.size());
}

TEST(TypeLib, TypesCarryTheLibraryProvenance) {
  const auto result = donkey::read_type_library(valid_file(kBody));
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  ASSERT_FALSE(result.value().types.empty());
  for (const donkey::TypeDefinition& type : result.value().types) {
    EXPECT_EQ(type.provenance, donkey::TypeProvenance::Library) << type.name;
  }

  // Ids start where the known table left off, so a library cannot collide with the types
  // already in a project.
  donkey::TypeTable known;
  donkey::TypeDefinition existing;
  existing.id = donkey::TypeId(1);
  existing.kind = donkey::TypeKind::Integer;
  existing.name = "int32_t";
  existing.size = 4;
  existing.is_signed = true;
  known.put(existing);
  const auto with_known = donkey::read_type_library(valid_file(kBody), known);
  ASSERT_TRUE(with_known.has_value()) << with_known.diagnostic().message;
  for (const donkey::TypeDefinition& type : with_known.value().types) {
    EXPECT_GT(type.id.value(), 1U) << type.name;
  }
}

TEST(TypeLib, KeepsRepeatedRecordsInOrder) {
  Lines header = base_header();
  header.push_back("source_file: include/a.h " + std::string(64, 'a'));
  header.push_back("source_file: include/b.h " + std::string(64, 'b'));
  header.push_back("macro: BITS=64");
  header.push_back("macro: EMPTY=");
  header.push_back("skipped: fn_ptr: a function pointer is not in the subset");
  header.push_back("note: first note");
  header.push_back("note: second note");
  const auto result = donkey::read_type_library(valid_file(kBody, header));
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const donkey::TypeLibrary& library = result.value();
  ASSERT_EQ(library.source_files.size(), 2U);
  EXPECT_EQ(library.source_files[0].path, "include/a.h");
  EXPECT_EQ(library.source_files[1].path, "include/b.h");
  ASSERT_EQ(library.macros.size(), 2U);
  EXPECT_EQ(library.macros[0].name, "BITS");
  EXPECT_EQ(library.macros[0].value, "64");
  EXPECT_EQ(library.macros[1].value, "");
  ASSERT_EQ(library.skipped.size(), 1U);
  EXPECT_EQ(library.skipped[0].name, "fn_ptr");
  ASSERT_EQ(library.notes.size(), 2U);
  EXPECT_EQ(library.notes[0], "first note");
  EXPECT_EQ(library.notes[1], "second note");
}

TEST(TypeLib, RefusesAnUnknownFormatVersion) {
  Lines header = base_header();
  header[0] = "donkey-typelib 2";
  expect_refused(valid_file(kBody, header), "typelib.version");

  header[0] = "donkey-typelib 1.1";
  expect_refused(valid_file(kBody, header), "typelib.version");
}

TEST(TypeLib, RefusesAMissingFormatLine) {
  Lines header = base_header();
  header.erase(header.begin());
  expect_refused(valid_file(kBody, header), "typelib.format");
  expect_refused("", "typelib.format");
  expect_refused("\n" + valid_file(kBody), "typelib.format");
}

TEST(TypeLib, RefusesAMissingSeparator) {
  // The header runs to the end of the file: the text is cut just before the empty line.
  const std::string text = valid_file(kBody);
  expect_refused(text.substr(0, text.find("\n\n") + 1), "typelib.format");
}

TEST(TypeLib, RefusesAnUnknownKey) {
  Lines header = base_header();
  header.push_back("colour: blue");
  expect_refused(valid_file(kBody, header), "typelib.unknown_key");
}

TEST(TypeLib, RefusesADuplicateKey) {
  Lines header = base_header();
  header.push_back("platform: linux");
  expect_refused(valid_file(kBody, header), "typelib.duplicate_key");
}

TEST(TypeLib, RefusesAMissingKey) {
  Lines header = base_header();
  drop(header, "licence_sha256");
  expect_refused(valid_file(kBody, header), "typelib.missing_key");
}

TEST(TypeLib, RefusesABadValue) {
  {
    Lines header = base_header();
    put(header, "platform", "plan9");
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    // aapcs64 is the AArch64 standard, so it is refused on x86_64.
    Lines header = base_header();
    put(header, "abi", "aapcs64");
    put(header, "data_model", "LP64");
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    Lines header = base_header();
    put(header, "created", "2026-02-30");
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    Lines header = base_header();
    put(header, "source_sha256", std::string(64, 'A'));  // upper case is refused
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    Lines header = base_header();
    put(header, "char_is_signed", "yes");
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    // finalize writes declarations, so the bad value goes in after it.
    Lines header = base_header();
    finalize(header, kBody);
    put(header, "declarations", "-1");
    expect_refused(assemble(header, kBody), "typelib.bad_value");
  }
  {
    Lines header = base_header();
    put(header, "licence", "");
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    Lines header = base_header();
    header.push_back("source_file: ../outside.h " + std::string(64, 'c'));
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    Lines header = base_header();
    header.push_back("macro: NOT-A-NAME=1");
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
  {
    Lines header = base_header();
    header.push_back("note: ");
    expect_refused(valid_file(kBody, header), "typelib.bad_value");
  }
}

TEST(TypeLib, RefusesARecordOutOfOrder) {
  {
    Lines header = base_header();
    header.push_back("note: first");
    header.push_back("macro: BITS=64");
    expect_refused(valid_file(kBody, header), "typelib.record_order");
  }
  {
    // A single key after a repeated record is out of order too.
    Lines header = base_header();
    header.push_back("note: first");
    header.push_back("library: late");
    expect_refused(valid_file(kBody, header), "typelib.record_order");
  }
}

TEST(TypeLib, RefusesADuplicateSourcePath) {
  Lines header = base_header();
  header.push_back("source_file: include/a.h " + std::string(64, 'a'));
  header.push_back("source_file: include/a.h " + std::string(64, 'b'));
  expect_refused(valid_file(kBody, header), "typelib.duplicate_path");
}

TEST(TypeLib, RefusesADeclarationCountMismatch) {
  const auto parsed = donkey::parse_c_declarations(kBody, donkey::TypeTable{});
  ASSERT_TRUE(parsed.has_value());
  Lines header = base_header();
  finalize(header, kBody);
  put(header, "declarations", std::to_string(parsed.value().size() + 1));
  expect_refused(assemble(header, kBody), "typelib.declaration_count");
}

TEST(TypeLib, RefusesTooManyDeclarations) {
  Lines header = base_header();
  finalize(header, kBody);
  put(header, "declarations", "20001");
  expect_refused(assemble(header, kBody), "typelib.too_many_declarations",
                 donkey::Status::ResourceLimit);
}

TEST(TypeLib, RefusesTooManyHeaderLines) {
  Lines header = base_header();
  for (int i = 0; i < 4100; ++i) {
    header.push_back("note: padding");
  }
  expect_refused(valid_file(kBody, header), "typelib.too_many_lines",
                 donkey::Status::ResourceLimit);
}

TEST(TypeLib, RefusesALongHeaderLine) {
  Lines header = base_header();
  header.push_back("note: " + std::string(300, 'x'));
  expect_refused(valid_file(kBody, header), "typelib.line_too_long", donkey::Status::ResourceLimit);
}

TEST(TypeLib, RefusesACarriageReturn) {
  Lines header = base_header();
  header[1] += '\r';
  expect_refused(valid_file(kBody, header), "typelib.carriage_return");

  const std::string body_with_cr = std::string(kBody) + "\r\n";
  Lines clean = base_header();
  finalize(clean, body_with_cr);
  expect_refused(assemble(clean, body_with_cr), "typelib.carriage_return");

  // A file saved with CRLF line endings is refused for its line endings, not its version.
  const std::string text = valid_file(kBody);
  std::string crlf;
  for (const char c : text) {
    crlf += c == '\n' ? std::string("\r\n") : std::string(1, c);
  }
  expect_refused(crlf, "typelib.carriage_return");
}

TEST(TypeLib, RefusesABodyThatDoesNotMatchItsHash) {
  const std::string text = valid_file(kBody);
  // A change to one byte of the C text, after the hash was written.
  std::string altered = text;
  altered.replace(altered.find("handle_t"), 8, "handle_u");
  const auto result = donkey::read_type_library(altered);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "typelib.body_hash");
  EXPECT_TRUE(std::string_view(result.diagnostic().message).starts_with("line "))
      << result.diagnostic().message;
}

TEST(TypeLib, RefusesAFileOverItsBounds) {
  // The text alone: one byte over the bound is refused before anything is parsed.
  const std::string huge(donkey::kMaxTypeLibraryBytes + 1, 'x');
  expect_refused(huge, "typelib.too_large", donkey::Status::ResourceLimit);

  // The file: refused from its size, and the reader is never given the text.
  const auto path = std::filesystem::temp_directory_path() / "donkey-typelib-too-large.dtl";
  {
    std::ofstream out(path, std::ios::binary);
    out << std::string(donkey::kMaxTypeLibraryBytes + 1, 'x');
  }
  const auto loaded = donkey::load_type_library(path);
  std::error_code ec;
  std::filesystem::remove(path, ec);
  ASSERT_FALSE(loaded.has_value());
  EXPECT_EQ(loaded.diagnostic().code, "typelib.too_large");
  EXPECT_EQ(loaded.diagnostic().status, donkey::Status::ResourceLimit);
}

TEST(TypeLib, RefusesAnUnreadableFile) {
  const auto loaded =
      donkey::load_type_library(std::filesystem::path(DONKEY_FIXTURE_DIR) / "types" / "absent.dtl");
  ASSERT_FALSE(loaded.has_value());
  EXPECT_EQ(loaded.diagnostic().code, "typelib.io");
}

TEST(TypeLib, RefusesADataModelThatContradictsItsAbi) {
  {
    // win64 is LLP64, not LP64.
    Lines header = base_header();
    put(header, "abi", "win64");
    put(header, "platform", "windows");
    put(header, "long_size", "4");
    expect_refused(valid_file(kBody, header), "typelib.data_model_mismatch");
  }
  {
    // LLP64 with an 8-byte long: the example from the format description.
    Lines header = base_header();
    put(header, "data_model", "LLP64");
    expect_refused(valid_file(kBody, header), "typelib.data_model_mismatch");
  }
  {
    // A 4-byte pointer is in no listed data model.
    Lines header = base_header();
    put(header, "pointer_size", "4");
    expect_refused(valid_file(kBody, header), "typelib.data_model_mismatch");
  }
  {
    // The mismatch is located at the line of the key that disagrees.
    Lines header = base_header();
    put(header, "data_model", "LLP64");
    const auto result = donkey::read_type_library(valid_file(kBody, header));
    ASSERT_FALSE(result.has_value());
    // sysv needs LP64, so the disagreement is reported on the abi line (line 6).
    EXPECT_TRUE(std::string_view(result.diagnostic().message).starts_with("line 6:"))
        << result.diagnostic().message;
  }
}

TEST(TypeLib, RefusesAVariableAndAFunctionPointer) {
  // A variable is refused by the parser; its line is in the library file, after the header.
  Lines header = base_header();
  const std::string variable_body = "struct point { int32_t x; };\nint32_t limit;\n";
  finalize(header, variable_body);
  // The header is 21 lines, the empty line is line 22, so body line 2 is file line 24.
  const auto variable = donkey::read_type_library(assemble(header, variable_body));
  ASSERT_FALSE(variable.has_value());
  EXPECT_EQ(variable.diagnostic().code, "cdecl.variable");
  EXPECT_TRUE(std::string_view(variable.diagnostic().message).starts_with("line 24, column 9:"))
      << variable.diagnostic().message;

  // A function pointer, which the parser refuses in this subset.
  Lines pointer_header = base_header();
  const std::string pointer_body = "typedef int32_t (*callback)(int32_t);\n";
  finalize(pointer_header, pointer_body);
  expect_refused(assemble(pointer_header, pointer_body), "cdecl.parenthesized_declarator");
}

TEST(TypeLib, ErrorsAreLocated) {
  // Header errors: the line in the file, from 1.
  {
    Lines header = base_header();
    put(header, "abi", "win64");
    put(header, "platform", "windows");
    put(header, "long_size", "4");
    put(header, "data_model", "LP64");
    const auto result = donkey::read_type_library(valid_file(kBody, header));
    ASSERT_FALSE(result.has_value());
    // The abi line is line 6 of the header (line 1 is the format line).
    EXPECT_TRUE(std::string_view(result.diagnostic().message).starts_with("line 6:"))
        << result.diagnostic().message;
  }

  // C-text errors: the parser's position, moved to the line in the library file.
  // Header of 21 lines (format line included), then the empty line 22, then the body from 23.
  Lines header = base_header();
  const std::string body = "typedef int32_t a;\ntypedef int32_t b;\n@\n";
  finalize(header, body);
  const std::size_t header_lines = header.size();
  ASSERT_EQ(header_lines, 21U);
  const auto result = donkey::read_type_library(assemble(header, body));
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "cdecl.bad_character");
  EXPECT_TRUE(std::string_view(result.diagnostic().message).starts_with("line 25, column 1:"))
      << result.diagnostic().message;  // body line 3 is file line 22 + 3
}

TEST(TypeLib, PassesTheParsersPreprocessorRefusalThrough) {
  // The header is read before the parser runs, so a '#' line reaches the parser as C text.
  Lines header = base_header();
  const std::string body = "#define LIMIT 4\n";
  finalize(header, body);
  const auto result = donkey::read_type_library(assemble(header, body));
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "cdecl.preprocessor");
  EXPECT_TRUE(std::string_view(result.diagnostic().message).starts_with("line 23, column 1:"))
      << result.diagnostic().message;
}

TEST(TypeLib, RefusesADuplicateName) {
  // A struct and an enum with one tag. C has one name space for the tags of structs, unions and
  // enums; the parser keeps a map per kind, so both come out, and the reader refuses the repeat.
  const std::string body = "struct foo { int32_t x; };\nenum foo { FOO_A = 1 };\n";
  Lines header = base_header();
  finalize(header, body);
  expect_refused(assemble(header, body), "typelib.duplicate_name");

  // Two struct bodies with one tag: the parser refuses the redefinition itself.
  const std::string twice = "struct point { int32_t x; };\nstruct point { int32_t y; };\n";
  Lines twice_header = base_header();
  finalize(twice_header, twice);
  expect_refused(assemble(twice_header, twice), "cdecl.redefinition");
}

TEST(TypeLib, RefusesATypeAndAFunctionWithOneName) {
  // A function and a typedef share C's ordinary name space.
  const std::string body = "int32_t point(void);\ntypedef int32_t point;\n";
  Lines header = base_header();
  finalize(header, body);
  expect_refused(assemble(header, body), "typelib.type_and_function");
}

TEST(TypeLib, AcceptsATagAndAnOrdinaryNameWithOneSpelling) {
  // C keeps tags apart from typedef and function names: `struct stat` and the function `stat`,
  // and `typedef struct point point`, are both valid C and common in system headers.
  const std::string body =
      "struct stat { int64_t size; };\nint32_t stat(const char *path, struct stat *out);\n"
      "struct point { int32_t x; int32_t y; };\ntypedef struct point point;\n";
  const auto result = donkey::read_type_library(valid_file(body));
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code << ": "
                                  << result.diagnostic().message;
  std::size_t named_stat = 0;
  std::size_t named_point = 0;
  for (const donkey::TypeDefinition& definition : result.value().types) {
    named_stat += definition.name == "stat" ? 1U : 0U;
    named_point += definition.name == "point" ? 1U : 0U;
  }
  EXPECT_EQ(named_stat, 2U);
  EXPECT_EQ(named_point, 2U);
}

TEST(TypeLib, RefusesADuplicatePrototypeName) {
  // Two prototypes with one name: both come out of the parser, and the reader refuses them.
  const std::string body = "int32_t same(void);\nint32_t same(int32_t x);\n";
  Lines header = base_header();
  finalize(header, body);
  expect_refused(assemble(header, body), "typelib.duplicate_name");
}

TEST(TypeLib, RefusesATypeSetThatDoesNotValidate) {
  // The known table has a typedef to a type it does not contain. The copy the reader checks has
  // that problem, so the library is refused, whatever its own text says.
  donkey::TypeTable known;
  donkey::TypeDefinition dangling;
  dangling.id = donkey::TypeId(1);
  dangling.kind = donkey::TypeKind::Typedef;
  dangling.name = "dangling_t";
  dangling.target = donkey::TypeId(99);
  known.put(dangling);
  expect_refused(valid_file("typedef int32_t handle_t;\n"), "typelib.invalid_types",
                 donkey::Status::InvalidInput, known);
}

TEST(TypeLib, KnownTypedefsDoNotChangeTheLibrarysTypes) {
  // The known table has a typedef named like a built-in type, to a signed 64-bit integer. The
  // library's `uint32_t` is still the built-in unsigned 32-bit integer, and its ids start after
  // the known table's.
  donkey::TypeTable known;
  donkey::TypeDefinition wide;
  wide.id = donkey::TypeId(1);
  wide.kind = donkey::TypeKind::Integer;
  wide.name = "long";
  wide.size = 8;
  wide.is_signed = true;
  known.put(wide);
  donkey::TypeDefinition shadow;
  shadow.id = donkey::TypeId(2);
  shadow.kind = donkey::TypeKind::Typedef;
  shadow.name = "uint32_t";
  shadow.target = donkey::TypeId(1);
  known.put(shadow);

  const auto result = donkey::read_type_library(valid_file("uint32_t width(void);\n"), known);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code << ": "
                                  << result.diagnostic().message;
  const auto& types = result.value().types;
  const donkey::TypeDefinition* function = named(types, "width");
  ASSERT_NE(function, nullptr);
  const donkey::TypeDefinition* returned = nullptr;
  for (const donkey::TypeDefinition& definition : types) {
    EXPECT_GE(definition.id.value(), known.next_id().value()) << definition.name;
    if (definition.id == function->target) {
      returned = &definition;
    }
  }
  ASSERT_NE(returned, nullptr) << "the return type is one of the library's own types";
  EXPECT_EQ(returned->kind, donkey::TypeKind::Integer);
  EXPECT_EQ(returned->size, 4U);
  EXPECT_FALSE(returned->is_signed);
}

TEST(TypeLib, RefusesATypedefOfAnUntaggedStructAndAFunctionWithOneName) {
  // `typedef struct { ... } item;` declares the ordinary name `item` (the struct takes the
  // typedef's name), so a function `item` collides with it, in either order.
  expect_refused(valid_file("typedef struct { int32_t x; } item;\nint32_t item(void);\n"),
                 "typelib.type_and_function");
  expect_refused(valid_file("int32_t item(void);\ntypedef struct { int32_t x; } item;\n"),
                 "typelib.type_and_function");
  // A tagged struct and a function with one name stay apart (`struct stat` and `stat`).
  const auto apart =
      donkey::read_type_library(valid_file("struct item { int32_t x; };\nint32_t item(void);\n"));
  EXPECT_TRUE(apart.has_value()) << apart.diagnostic().code;
}

TEST(TypeLib, PassesTheParsersSizeBoundThrough) {
  // A body over the parser's 1 MiB bound is refused by the parser, with its own code. The file is
  // under the 4 MiB file bound.
  const std::string body(donkey::kMaxCDeclarationBytes + 1, ' ');
  Lines header = base_header();
  finalize(header, body);
  expect_refused(assemble(header, body), "cdecl.too_large", donkey::Status::ResourceLimit);
}
