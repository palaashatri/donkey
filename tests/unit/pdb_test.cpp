#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/binary/pdb.h"

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
