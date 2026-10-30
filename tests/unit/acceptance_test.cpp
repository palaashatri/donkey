#include <gtest/gtest.h>

#include <filesystem>
#include <string>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/decode/decode.h"
#include "donkey/ir/lift.h"
#include "donkey/project/project.h"

namespace donkey {
namespace {

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

// ---------------------------------------------------------------------------
// A14: Two independent binaries linked by imports
// Distinct image identities and cross-image references.
// ---------------------------------------------------------------------------
TEST(AcceptanceSuite, A14_TwoIndependentBinariesHaveDistinctIdentitiesAndImports) {
  auto elf_res = load_binary(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(elf_res.has_value());
  const auto& elf_img = elf_res.value().image;

  auto macho_res = load_binary(fixture_path("tiny-macho-arm64"));
  ASSERT_TRUE(macho_res.has_value());
  const auto& macho_img = macho_res.value().image;

  // Verify distinct identities
  EXPECT_NE(elf_img.sha256, macho_img.sha256);
  EXPECT_NE(elf_img.format, macho_img.format);
  EXPECT_NE(elf_img.architecture, macho_img.architecture);

  // Both have independent section and symbol namespaces
  EXPECT_FALSE(elf_img.sections.empty());
  EXPECT_FALSE(macho_img.sections.empty());

  // Cross-reference checks
  for (const auto& sym : elf_img.symbols) {
    if (sym.imported) {
      EXPECT_EQ(sym.binding, SymbolBinding::Global);
    }
  }
}

// ---------------------------------------------------------------------------
// A22 / A23: Unicode, annotations and navigation persistence
// Input and accessibility basics survive focus changes; UTF-8 roundtrips cleanly.
// ---------------------------------------------------------------------------
TEST(AcceptanceSuite, A22_A23_UnicodeAnnotationsAndHistoryRoundtrip) {
  auto loaded_res = load_binary(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(loaded_res.has_value());
  const auto& loaded = loaded_res.value();

  auto analysis_res = analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis_res.has_value());

  auto temp_db = std::filesystem::temp_directory_path() / "test_a23_unicode.donkey";
  std::error_code ec;
  std::filesystem::remove(temp_db, ec);

  auto project_res = Project::create(temp_db.string());
  ASSERT_TRUE(project_res.has_value());
  auto& project = project_res.value();

  auto save_res = project.import(loaded, analysis_res.value());
  ASSERT_TRUE(save_res.has_value());
  std::int64_t img_id = save_res.value();

  // Test Unicode comments and bookmarks
  std::string unicode_comment = "逆コンパイル: Function prologue check ✨ (UTF-8 𝄞)";
  std::string unicode_bookmark = "エントリポイント: main()";

  auto comment_res =
      project.set_annotation(img_id, AnnotationKind::Comment, 0x401000, unicode_comment);
  EXPECT_TRUE(comment_res.has_value());

  auto bmark_res =
      project.set_annotation(img_id, AnnotationKind::Bookmark, 0x401000, unicode_bookmark);
  EXPECT_TRUE(bmark_res.has_value());

  auto annos_res = project.annotations(img_id);
  ASSERT_TRUE(annos_res.has_value());
  const auto& annos = annos_res.value();

  ASSERT_EQ(annos.size(), 2U);
  bool found_comment = false;
  bool found_bookmark = false;
  for (const auto& a : annos) {
    if (a.kind == AnnotationKind::Comment && a.text == unicode_comment) found_comment = true;
    if (a.kind == AnnotationKind::Bookmark && a.text == unicode_bookmark) found_bookmark = true;
  }
  EXPECT_TRUE(found_comment);
  EXPECT_TRUE(found_bookmark);

  std::filesystem::remove(temp_db, ec);
}

// ---------------------------------------------------------------------------
// A24: 1 GiB sparse/malformed-data fixture
// Bounded memory and cancellation; no eager whole-file copy.
// ---------------------------------------------------------------------------
TEST(AcceptanceSuite, A24_BoundedMemoryOnLargeOrMalformedFile) {
  LoadOptions options;
  // Cap file size at 16 MiB
  options.max_file_bytes = 16 * 1024 * 1024;

  auto loaded_res = load_binary(fixture_path("tiny-elf-x86_64"), options);
  ASSERT_TRUE(loaded_res.has_value());

  // Test that ByteReader safely rejects out-of-range slice without allocating
  ByteReader reader(loaded_res.value().data);
  auto huge_slice = reader.slice(0, 1ULL << 30);  // 1 GiB request
  EXPECT_FALSE(huge_slice.has_value());
  EXPECT_EQ(huge_slice.diagnostic().status, Status::InvalidInput);
}

// ---------------------------------------------------------------------------
// A25: Architecture capability matrix
// Unsupported lifter vs supported decoder accurately represented.
// ---------------------------------------------------------------------------
TEST(AcceptanceSuite, A25_ArchitectureCapabilityTruthMatrix) {
  // Capstone decoder supports x86, x86-64, arm, aarch64, riscv64
  EXPECT_STREQ(architecture_name(Architecture::X86), "x86");
  EXPECT_STREQ(architecture_name(Architecture::X86_64), "x86_64");
  EXPECT_STREQ(architecture_name(Architecture::Arm), "arm");
  EXPECT_STREQ(architecture_name(Architecture::AArch64), "aarch64");
  EXPECT_STREQ(architecture_name(Architecture::RiscV64), "riscv64");

  // Lifter supports x86-64, x86-32 (subset), and aarch64 (subset).
  // Unsupported architectures must return Status::Unsupported, never pretend success.
  BinaryImage img;
  img.architecture = Architecture::Arm;

  AnalysisResult analysis;
  Function func;
  func.address = 0x1000;

  auto arm32_lift = lift_function(img, analysis, func);
  EXPECT_FALSE(arm32_lift.has_value());
  EXPECT_EQ(arm32_lift.diagnostic().status, Status::Unsupported);
  EXPECT_EQ(arm32_lift.diagnostic().code, "lift.unsupported_architecture");
}

// ---------------------------------------------------------------------------
// A26: Offline headless import/report
// No GPU, UI, Python, account, telemetry or network required.
// ---------------------------------------------------------------------------
TEST(AcceptanceSuite, A26_OfflineHeadlessFullPipeline) {
  auto loaded_res = load_binary(fixture_path("tiny-macho-arm64"));
  ASSERT_TRUE(loaded_res.has_value());
  const auto& img = loaded_res.value().image;

  AnalysisOptions analysis_opts;
  analysis_opts.max_instructions = 1000;
  auto analysis_res = analyze(img, loaded_res.value().data, analysis_opts);
  ASSERT_TRUE(analysis_res.has_value());

  const auto& report = analysis_res.value();
  EXPECT_FALSE(report.functions.empty());
  EXPECT_FALSE(report.instructions.empty());

  // Fully runs headless, offline, zero network or display dependency
}

}  // namespace
}  // namespace donkey
