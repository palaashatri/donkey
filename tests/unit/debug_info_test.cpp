#include "donkey/binary/debug_info.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/binary/image.h"

namespace {

// The debuggee and the module are compiled with -g by the test suite. Apple
// toolchains keep DWARF out of the executable (in .o files or a .dSYM) and
// MSVC writes PDB, so there the fixture honestly has none.
#define LOAD_WITH_DWARF(var, path)                                                    \
  auto var##_loaded = donkey::load_binary(path);                                      \
  ASSERT_TRUE(var##_loaded.has_value()) << var##_loaded.diagnostic().message;         \
  auto var##_result =                                                                 \
      donkey::read_debug_info(var##_loaded.value().image, var##_loaded.value().data); \
  if (!var##_result && var##_result.diagnostic().code == "dwarf.not_present") {       \
    GTEST_SKIP() << "the toolchain put no DWARF in " << path;                         \
  }                                                                                   \
  ASSERT_TRUE(var##_result.has_value()) << var##_result.diagnostic().code;            \
  const donkey::DebugInfo& var = var##_result.value()

const donkey::DebugFunction* named(const donkey::DebugInfo& info, const std::string& name) {
  for (const auto& f : info.functions) {
    if (f.name == name) {
      return &f;
    }
  }
  return nullptr;
}

std::uint64_t symbol_address(const donkey::BinaryImage& image, const std::string& name) {
  for (const auto& symbol : image.symbols) {
    if (!symbol.imported && (symbol.name == name || symbol.name == "_" + name)) {
      return symbol.address;
    }
  }
  return 0;
}

TEST(DebugInfo, DebuggeeFunctionsVariablesAndTypesWithProvenance) {
  LOAD_WITH_DWARF(info, DONKEY_TEST_DEBUGGEE_PATH);
  EXPECT_FALSE(info.partial);
  EXPECT_GE(info.compile_units, 1U);
  EXPECT_GE(info.min_version, 2U);
  EXPECT_LE(info.max_version, 5U);
  EXPECT_FALSE(info.producers.empty());

  const auto* tick = named(info, "donkey_debuggee_tick");
  ASSERT_NE(tick, nullptr);
  EXPECT_EQ(tick->address, symbol_address(info_loaded.value().image, "donkey_debuggee_tick"))
      << "DWARF and the symbol table must agree on the address";
  EXPECT_GT(tick->size, 0U);
  EXPECT_EQ(info.prototype(*tick), "void donkey_debuggee_tick(void)");
  EXPECT_NE(tick->file.find("debuggee.c"), std::string::npos);
  EXPECT_GT(tick->line, 0U);
  EXPECT_EQ(tick->provenance.format, "DWARF");
  EXPECT_EQ(tick->provenance.label().rfind("DWARF ", 0), 0U);

  const auto* main_fn = named(info, "main");
  ASSERT_NE(main_fn, nullptr);
  EXPECT_EQ(info.prototype(*main_fn), "int main(int argc, char ** argv)");
  ASSERT_EQ(main_fn->parameters.size(), 2U);
  EXPECT_EQ(main_fn->parameters[0].name, "argc");

  const auto* run = named(info, "run_module");
  ASSERT_NE(run, nullptr);
  EXPECT_EQ(info.prototype(*run), "int run_module(const char * path)");

  EXPECT_EQ(info.function_containing(tick->address + 1), tick);
  EXPECT_EQ(info.function_at(tick->address), tick);
  EXPECT_EQ(info.function_at(tick->address + 1), nullptr);

  const auto counter =
      std::find_if(info.variables.begin(), info.variables.end(),
                   [](const auto& v) { return v.name == "donkey_debuggee_counter"; });
  ASSERT_NE(counter, info.variables.end());
  EXPECT_EQ(info.type_name(counter->type), "volatile int");
  EXPECT_EQ(counter->address, symbol_address(info_loaded.value().image, "donkey_debuggee_counter"));
  const auto function_pointer =
      std::find_if(info.variables.begin(), info.variables.end(),
                   [](const auto& v) { return v.name == "donkey_debuggee_module_function"; });
  ASSERT_NE(function_pointer, info.variables.end());
  EXPECT_EQ(info.type_name(function_pointer->type), "volatile uint64_t");
}

TEST(DebugInfo, SharedLibraryPrototype) {
  LOAD_WITH_DWARF(info, DONKEY_TEST_MODULE_PATH);
  const auto* answer = named(info, "donkey_module_answer");
  ASSERT_NE(answer, nullptr);
  EXPECT_EQ(info.prototype(*answer), "int donkey_module_answer(int value)");
}

TEST(DebugInfo, ImagesWithoutDebugInformationSaySo) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-elf-x86_64");
  ASSERT_TRUE(loaded.has_value());
  auto info = donkey::read_debug_info(loaded.value().image, loaded.value().data);
  ASSERT_FALSE(info.has_value());
  EXPECT_EQ(info.diagnostic().code, "dwarf.not_present");
  EXPECT_EQ(info.diagnostic().status, donkey::Status::Unsupported);
}

// Malformed DWARF never crashes or reads out of bounds: truncations and
// byte mutations of the real debug sections either parse (possibly
// partially, with diagnostics) or fail with a code, deterministically.
TEST(DebugInfo, MalformedSectionsAreBoundedAndDeterministic) {
  auto loaded = donkey::load_binary(DONKEY_TEST_DEBUGGEE_PATH);
  ASSERT_TRUE(loaded.has_value());
  const donkey::BinaryImage& image = loaded.value().image;
  std::vector<const donkey::Section*> debug_sections;
  for (const auto& section : image.sections) {
    if (section.name == ".debug_info" || section.name == ".debug_abbrev" ||
        section.name == ".debug_str" || section.name == ".debug_line" ||
        section.name == ".debug_str_offsets" || section.name == ".debug_addr" ||
        section.name == ".debug_line_str") {
      debug_sections.push_back(&section);
    }
  }
  if (debug_sections.empty()) {
    GTEST_SKIP() << "no DWARF sections in this build of the debuggee";
  }
  const std::vector<std::byte> original(loaded.value().data.begin(), loaded.value().data.end());
  std::uint64_t state = 0x9E3779B97F4A7C15ULL;
  auto next = [&]() {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
  };
  for (int iteration = 0; iteration < 3000; ++iteration) {
    std::vector<std::byte> bytes = original;
    const donkey::Section* section = debug_sections[next() % debug_sections.size()];
    if (section->file_size == 0) {
      continue;
    }
    const int edits = 1 + static_cast<int>(next() % 4);
    for (int e = 0; e < edits; ++e) {
      const std::size_t at =
          static_cast<std::size_t>(section->file_offset + next() % section->file_size);
      bytes[at] = static_cast<std::byte>(next() & 0xFFU);
    }
    donkey::BinaryImage mutated_image = image;
    if (iteration % 7 == 0) {
      // Also shrink a section: its tail now looks truncated.
      for (auto& s : mutated_image.sections) {
        if (s.name == section->name) {
          s.file_size = next() % (s.file_size + 1);
        }
      }
    }
    auto first = donkey::read_debug_info(mutated_image, bytes);
    auto second = donkey::read_debug_info(mutated_image, bytes);
    ASSERT_EQ(first.has_value(), second.has_value()) << "iteration " << iteration;
    if (first) {
      EXPECT_EQ(first.value().functions.size(), second.value().functions.size());
      for (const auto& f : first.value().functions) {
        (void)first.value().prototype(f);
      }
      for (const auto& [offset, type] : first.value().types) {
        (void)first.value().type_name(offset);
      }
    } else {
      EXPECT_FALSE(first.diagnostic().code.empty());
    }
  }
}

TEST(DebugInfo, TypeRenderingIsBoundedOnCycles) {
  donkey::DebugInfo info;
  donkey::DebugType a;
  a.kind = donkey::DebugTypeKind::Pointer;
  a.target = 2;
  donkey::DebugType b;
  b.kind = donkey::DebugTypeKind::Const;
  b.target = 1;  // 1 -> 2 -> 1 ...
  info.types.emplace(1, a);
  info.types.emplace(2, b);
  EXPECT_NE(info.type_name(1).find("<type too deep>"), std::string::npos);
}

}  // namespace
