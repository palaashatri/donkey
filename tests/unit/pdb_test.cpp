#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/binary/pdb.h"
#include "donkey/project/types.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/pdb/" + name;
}

std::vector<std::byte> read_file(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  const std::vector<char> raw((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes;
  bytes.reserve(raw.size());
  for (const char c : raw) {
    bytes.push_back(static_cast<std::byte>(c));
  }
  return bytes;
}

const donkey::PdbFunction* function_named(const donkey::PdbInfo& info, const std::string& name) {
  for (const donkey::PdbFunction& function : info.functions) {
    if (function.name == name) {
      return &function;
    }
  }
  return nullptr;
}

}  // namespace

// The oracle is `llvm-pdbutil dump` on the same PDB (tests/fixtures/pdb/PROVENANCE.md): the
// modules, the procedures with their section, offset, code size and type, the global, the
// struct's two type records, and the section table.
TEST(PdbReader, ReadsTheInfoModulesSectionsAndProcedures) {
  const auto file = read_file(fixture("sample.pdb"));
  ASSERT_TRUE(donkey::is_pdb(file));
  auto result = donkey::read_pdb(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code << ": "
                                  << result.diagnostic().message;
  const donkey::PdbInfo& info = result.value();
  EXPECT_FALSE(info.partial);

  EXPECT_EQ(info.age, 1U);
  EXPECT_EQ(info.guid_text(), "{AAC9DDFC-7CBA-9D49-4C4C-44205044422E}");

  ASSERT_EQ(info.modules.size(), 2U);
  EXPECT_EQ(info.modules[0].object, "/home/user/donkey/tests/fixtures/pdb/sample.obj");
  EXPECT_EQ(info.modules[1].name, "* Linker *");

  ASSERT_EQ(info.sections.size(), 3U);
  EXPECT_EQ(info.sections[0].name, ".text");
  EXPECT_EQ(info.sections[0].rva, 0x1000U);
  EXPECT_EQ(info.sections[0].virtual_size, 0x8aU);
  EXPECT_EQ(info.sections[1].rva, 0x2000U);
  EXPECT_EQ(info.sections[2].name, ".data");
  EXPECT_EQ(info.sections[2].rva, 0x3000U);

  const donkey::PdbFunction* entry = function_named(info, "sample_entry");
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->section, 1U);
  EXPECT_EQ(entry->offset, 0U);
  EXPECT_EQ(entry->rva, 0x1000U);
  EXPECT_EQ(entry->size, 75U);
  EXPECT_EQ(entry->type, 0x1001U);
  EXPECT_TRUE(entry->global);
  EXPECT_EQ(entry->module, "/home/user/donkey/tests/fixtures/pdb/sample.obj");

  const donkey::PdbFunction* scale = function_named(info, "scale");
  ASSERT_NE(scale, nullptr);
  // The call from sample_entry targets 0x140001050 in the executable: scale starts at RVA 0x1050.
  EXPECT_EQ(scale->rva, 0x1050U);
  EXPECT_EQ(scale->size, 58U);
  EXPECT_EQ(scale->type, 0x1007U);
  EXPECT_FALSE(scale->global);
}

TEST(PdbReader, ReadsTheGlobalDataAndTheStructTypes) {
  const auto file = read_file(fixture("sample.pdb"));
  auto result = donkey::read_pdb(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  const donkey::PdbInfo& info = result.value();

  ASSERT_EQ(info.variables.size(), 1U);
  EXPECT_EQ(info.variables[0].name, "shared_total");
  EXPECT_EQ(info.variables[0].section, 3U);
  EXPECT_EQ(info.variables[0].rva, 0x3000U);
  EXPECT_EQ(info.variables[0].type, 0x0074U);  // int

  // `point` has a forward reference (size 0) and its complete definition (size 12).
  const donkey::PdbType* forward = nullptr;
  const donkey::PdbType* complete = nullptr;
  for (const donkey::PdbType& type : info.types) {
    if (type.name != "point") {
      continue;
    }
    if (type.index == 0x1002) {
      forward = &type;
    } else if (type.index == 0x1004) {
      complete = &type;
    }
  }
  ASSERT_NE(forward, nullptr);
  ASSERT_NE(complete, nullptr);
  EXPECT_EQ(complete->kind, "struct");
  EXPECT_TRUE(forward->forward);
  EXPECT_EQ(forward->size, 0U);
  EXPECT_FALSE(complete->forward);
  EXPECT_EQ(complete->size, 12U);
}

TEST(PdbReader, ANonPdbIsRejectedWithItsCode) {
  const auto file = read_file(fixture("../objects/tls.c"));
  EXPECT_FALSE(donkey::is_pdb(file));
  auto result = donkey::read_pdb(file);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "pdb.magic");
}

// A PDB cut short keeps what its streams hold and says what was lost. It is never read past its
// end, and it never yields a stream of garbage.
TEST(PdbReader, ATruncatedPdbIsBoundedAndCoded) {
  const auto file = read_file(fixture("sample.pdb"));
  const std::span<const std::byte> cut(file.data(), 8192);
  auto result = donkey::read_pdb(cut);
  if (result.has_value()) {
    EXPECT_TRUE(result.value().partial);
  } else {
    EXPECT_EQ(result.diagnostic().code.rfind("pdb.", 0), 0U) << result.diagnostic().code;
  }
}

// The fields of `point` (its LF_FIELDLIST 0x1003) with their types and byte offsets, as the
// llvm-pdbutil dump gives them: x and y are int at 0 and 4, tag is long at 8, and the complete
// struct is 12 bytes.
TEST(PdbReader, ReadsTheFieldsOfTheCompleteStruct) {
  const auto file = read_file(fixture("sample.pdb"));
  auto result = donkey::read_pdb(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  const donkey::PdbType* point = nullptr;
  for (const donkey::PdbType& type : result.value().types) {
    if (!type.forward && type.name == "point") {
      point = &type;
    }
  }
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(point->index, 0x1004U);
  EXPECT_EQ(point->size, 12U);
  EXPECT_EQ(point->field_list, 0x1003U);
  ASSERT_TRUE(point->members_complete);
  ASSERT_EQ(point->members.size(), 3U);
  EXPECT_EQ(point->members[0].name, "x");
  EXPECT_EQ(point->members[0].type, 0x0074U);  // int
  EXPECT_EQ(point->members[0].offset, 0U);
  EXPECT_EQ(point->members[1].name, "y");
  EXPECT_EQ(point->members[1].type, 0x0074U);
  EXPECT_EQ(point->members[1].offset, 4U);
  EXPECT_EQ(point->members[2].name, "tag");
  EXPECT_EQ(point->members[2].type, 0x0012U);  // long
  EXPECT_EQ(point->members[2].offset, 8U);
}

// The pointer 0x1005 (to the forward reference 0x1002, 8 bytes) and the two procedures, with the
// parameter lists their argument records (0x1000 and 0x1006) name.
TEST(PdbReader, ReadsPointersAndProcedureParameters) {
  const auto file = read_file(fixture("sample.pdb"));
  auto result = donkey::read_pdb(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  const donkey::PdbInfo& info = result.value();
  const donkey::PdbDerived* pointer = nullptr;
  const donkey::PdbDerived* scale = nullptr;
  const donkey::PdbDerived* entry = nullptr;
  for (const donkey::PdbDerived& derived : info.derived) {
    if (derived.index == 0x1005U) pointer = &derived;
    if (derived.index == 0x1007U) scale = &derived;
    if (derived.index == 0x1001U) entry = &derived;
  }
  ASSERT_NE(pointer, nullptr);
  EXPECT_EQ(pointer->kind, "pointer");
  EXPECT_EQ(pointer->referent, 0x1002U);
  EXPECT_EQ(pointer->size, 8U);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->kind, "procedure");
  EXPECT_EQ(entry->referent, 0x0074U);
  EXPECT_EQ(entry->arguments, std::vector<std::uint32_t>{0x0074U});
  ASSERT_NE(scale, nullptr);
  EXPECT_EQ(scale->arguments, (std::vector<std::uint32_t>{0x1005U, 0x0074U}));
  EXPECT_FALSE(info.partial);
}

// The fixture maps completely: `point` is a 12-byte struct of int, int and long fields, the
// pointer targets the complete struct and not the forward reference, the procedure takes the
// pointer and an int, and the table validates.
TEST(PdbTypes, MapsTheFixtureTypesAndTheyValidate) {
  const auto file = read_file(fixture("sample.pdb"));
  auto result = donkey::read_pdb(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  std::vector<donkey::Diagnostic> unmapped;
  const donkey::TypeTable table = donkey::types_from_pdb(result.value(), &unmapped);
  for (const donkey::Diagnostic& diagnostic : unmapped) {
    ADD_FAILURE() << diagnostic.code << ": " << diagnostic.message;
  }
  auto valid = table.validate();
  EXPECT_TRUE(valid.has_value()) << valid.diagnostic().code << ": " << valid.diagnostic().message;

  const donkey::TypeDefinition* point = table.find(donkey::TypeId(0x1004));
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(point->kind, donkey::TypeKind::Struct);
  EXPECT_EQ(point->name, "point");
  EXPECT_EQ(point->provenance, donkey::TypeProvenance::Pdb);
  EXPECT_EQ(point->size, 12U);
  ASSERT_EQ(point->fields.size(), 3U);
  EXPECT_EQ(point->fields[1].name, "y");
  EXPECT_EQ(point->fields[1].offset, 4U);
  const donkey::TypeDefinition* field_int = table.find(point->fields[1].type);
  ASSERT_NE(field_int, nullptr);
  EXPECT_EQ(field_int->kind, donkey::TypeKind::Integer);
  EXPECT_EQ(field_int->size, 4U);
  EXPECT_TRUE(field_int->is_signed);
  const donkey::TypeDefinition* field_long = table.find(point->fields[2].type);
  ASSERT_NE(field_long, nullptr);
  EXPECT_EQ(field_long->name, "long");
  EXPECT_EQ(field_long->size, 4U);

  const donkey::TypeDefinition* pointer = table.find(donkey::TypeId(0x1005));
  ASSERT_NE(pointer, nullptr);
  EXPECT_EQ(pointer->kind, donkey::TypeKind::Pointer);
  EXPECT_EQ(pointer->target, donkey::TypeId(0x1004));
  EXPECT_EQ(pointer->size, 8U);

  const donkey::TypeDefinition* scale = table.find(donkey::TypeId(0x1007));
  ASSERT_NE(scale, nullptr);
  EXPECT_EQ(scale->kind, donkey::TypeKind::Function);
  ASSERT_EQ(scale->fields.size(), 2U);
  EXPECT_EQ(scale->fields[0].type, donkey::TypeId(0x1005));
  auto size = table.size_of(donkey::TypeId(0x1004));
  ASSERT_TRUE(size.has_value());
  EXPECT_EQ(size.value(), 12U);
}

// A class whose layout is not all read (here a base class or method made it incomplete) is not
// mapped as if it were complete. It is reported, and a pointer to it is not mapped either, so the
// table cannot hide the gap.
TEST(PdbTypes, AnIncompleteClassIsReportedAndNotMapped) {
  donkey::PdbInfo info;
  donkey::PdbType cls;
  cls.index = 0x1000;
  cls.kind = "class";
  cls.name = "widget";
  cls.size = 16;
  cls.members_complete = false;
  info.types.push_back(cls);
  donkey::PdbDerived pointer;
  pointer.index = 0x1001;
  pointer.kind = "pointer";
  pointer.referent = 0x1000;
  pointer.size = 8;
  info.derived.push_back(pointer);
  std::vector<donkey::Diagnostic> unmapped;
  const donkey::TypeTable table = donkey::types_from_pdb(info, &unmapped);
  EXPECT_EQ(table.find(donkey::TypeId(0x1000)), nullptr);
  EXPECT_EQ(table.find(donkey::TypeId(0x1001)), nullptr);
  ASSERT_EQ(unmapped.size(), 2U);
  EXPECT_EQ(unmapped[0].code, "pdb.type_unmapped");
}

// The enum of tests/fixtures/pdb/enum (G06): its enumerators are read with their values in
// field-list order (red 0, green 5, blue 6), and its underlying type is int.
TEST(PdbReader, ReadsEnumeratorsWithTheirValues) {
  const auto file = read_file(fixture("enum/enum.pdb"));
  auto result = donkey::read_pdb(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  const donkey::PdbType* color = nullptr;
  for (const donkey::PdbType& type : result.value().types) {
    if (!type.forward && type.name == "color") {
      color = &type;
    }
  }
  ASSERT_NE(color, nullptr);
  EXPECT_EQ(color->kind, "enum");
  EXPECT_EQ(color->index, 0x1005U);
  EXPECT_EQ(color->field_list, 0x1004U);
  EXPECT_EQ(color->underlying, 0x0074U);  // int
  ASSERT_TRUE(color->enumerators_complete);
  ASSERT_EQ(color->enumerators.size(), 3U);
  EXPECT_EQ(color->enumerators[0].name, "red");
  EXPECT_EQ(color->enumerators[0].value, 0);
  EXPECT_EQ(color->enumerators[1].name, "green");
  EXPECT_EQ(color->enumerators[1].value, 5);
  EXPECT_EQ(color->enumerators[2].name, "blue");
  EXPECT_EQ(color->enumerators[2].value, 6);
}

// The enum maps to an Enum type with its three enumerators, and the struct field of enum type
// refers to it. The struct is 8 bytes: the enum at 0 and the int at 4.
TEST(PdbTypes, MapsAnEnumWithItsEnumerators) {
  const auto file = read_file(fixture("enum/enum.pdb"));
  auto result = donkey::read_pdb(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  std::vector<donkey::Diagnostic> unmapped;
  const donkey::TypeTable table = donkey::types_from_pdb(result.value(), &unmapped);
  for (const donkey::Diagnostic& diagnostic : unmapped) {
    ADD_FAILURE() << diagnostic.code << ": " << diagnostic.message;
  }
  auto valid = table.validate();
  EXPECT_TRUE(valid.has_value()) << valid.diagnostic().code << ": " << valid.diagnostic().message;

  const donkey::TypeDefinition* color = table.find(donkey::TypeId(0x1005));
  ASSERT_NE(color, nullptr);
  EXPECT_EQ(color->kind, donkey::TypeKind::Enum);
  EXPECT_EQ(color->size, 4U);
  ASSERT_EQ(color->enumerators.size(), 3U);
  EXPECT_EQ(color->enumerators[1].name, "green");
  EXPECT_EQ(color->enumerators[1].value, 5);
  EXPECT_EQ(color->enumerators[2].value, 6);

  const donkey::TypeDefinition* paint = table.find(donkey::TypeId(0x1007));
  ASSERT_NE(paint, nullptr);
  EXPECT_EQ(paint->kind, donkey::TypeKind::Struct);
  EXPECT_EQ(paint->size, 8U);
  ASSERT_EQ(paint->fields.size(), 2U);
  EXPECT_EQ(paint->fields[0].type, donkey::TypeId(0x1005));
  EXPECT_EQ(paint->fields[1].offset, 4U);
}
