#include "donkey/patch/patch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "donkey/core/sha256.h"

namespace donkey {
namespace {

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

std::vector<uint8_t> read_file_bytes(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
}

TEST(PatchTest, RejectsEmptyReplacement) {
  PatchManager manager;
  const uint8_t orig[] = {0x90};
  auto res = manager.stage_patch(0x10, orig, {});
  EXPECT_FALSE(res.has_value());
  EXPECT_EQ(res.diagnostic().code, "patch.empty_replacement");
}

TEST(PatchTest, InBufferApplyAndRevertWithCallback) {
  std::vector<uint8_t> buffer = {0x55, 0x48, 0x89, 0xe5, 0x90, 0xc3};
  PatchManager manager;

  bool invalidated = false;
  uint64_t inv_offset = 0;
  size_t inv_size = 0;
  manager.set_invalidation_callback([&](uint64_t offset, size_t size) {
    invalidated = true;
    inv_offset = offset;
    inv_size = size;
  });

  const uint8_t expected_orig[] = {0x90};
  const uint8_t repl[] = {0xcc};
  auto stage_res = manager.stage_patch(4, expected_orig, repl, "Breakpoint patch", "tester");
  ASSERT_TRUE(stage_res.has_value());
  uint64_t patch_id = stage_res.value();

  // Test mismatch detection
  std::vector<uint8_t> bad_buffer = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  auto bad_apply = manager.apply_patch(patch_id, bad_buffer);
  EXPECT_FALSE(bad_apply.has_value());
  EXPECT_EQ(bad_apply.diagnostic().code, "patch.original_bytes_mismatch");

  // Apply to real buffer
  auto apply_res = manager.apply_patch(patch_id, buffer);
  ASSERT_TRUE(apply_res.has_value());
  EXPECT_EQ(buffer[4], 0xcc);
  EXPECT_TRUE(invalidated);
  EXPECT_EQ(inv_offset, 4U);
  EXPECT_EQ(inv_size, 1U);

  // Preview diffs
  auto diffs = manager.preview();
  ASSERT_EQ(diffs.size(), 1U);
  EXPECT_EQ(diffs[0].file_offset, 4U);
  EXPECT_EQ(diffs[0].before_bytes, std::vector<uint8_t>({0x90}));
  EXPECT_EQ(diffs[0].after_bytes, std::vector<uint8_t>({0xcc}));

  // Revert
  invalidated = false;
  auto revert_res = manager.revert_patch(patch_id, buffer);
  ASSERT_TRUE(revert_res.has_value());
  EXPECT_EQ(buffer[4], 0x90);
  EXPECT_TRUE(invalidated);
  EXPECT_TRUE(manager.preview().empty());
}

TEST(PatchTest, ExportPatchedBinaryVerifiesA21) {
  // Acceptance scenario A21: Hex patch + export fixture
  // Original unchanged; patched output hash and bytes verified.
  std::string src = fixture_path("tiny-macho-arm64");
  auto src_bytes = read_file_bytes(src);
  std::string orig_sha256 = Sha256::hex(std::as_bytes(std::span(src_bytes)));

  std::string temp_out = std::filesystem::temp_directory_path() / "test_patched_macho";
  std::error_code ec;
  std::filesystem::remove(temp_out, ec);

  PatchManager manager;
  // Offset 0 in Mach-O is magic 0xfeedfacf (little endian: cf fa ed fe)
  const uint8_t orig_magic[] = {0xcf, 0xfa, 0xed, 0xfe};
  const uint8_t repl_magic[] = {0xde, 0xad, 0xbe, 0xef};

  auto stage_res = manager.stage_patch(0, orig_magic, repl_magic, "Patch Mach-O magic", "A21_QA");
  ASSERT_TRUE(stage_res.has_value());
  uint64_t patch_id = stage_res.value();

  // Mark applied
  auto* entry = const_cast<PatchEntry*>(manager.find_patch(patch_id));
  ASSERT_NE(entry, nullptr);
  entry->applied = true;

  // Refusal to overwrite original without force
  auto overwrite_fail = manager.export_patched_binary(src, src, false);
  EXPECT_FALSE(overwrite_fail.has_value());
  EXPECT_EQ(overwrite_fail.diagnostic().code, "patch.refuse_overwrite_source");

  // Export to new path
  auto exp_res = manager.export_patched_binary(src, temp_out, false);
  ASSERT_TRUE(exp_res.has_value()) << exp_res.diagnostic().message;
  const auto& exp = exp_res.value();

  EXPECT_EQ(exp.path, temp_out);
  EXPECT_FALSE(exp.sha256.empty());
  EXPECT_NE(exp.sha256, orig_sha256);

  // Original file must be completely untouched
  auto after_bytes = read_file_bytes(src);
  std::string after_src_sha256 = Sha256::hex(std::as_bytes(std::span(after_bytes)));
  EXPECT_EQ(after_src_sha256, orig_sha256);

  // Patched file must have replacement bytes at offset 0
  auto patched_bytes = read_file_bytes(temp_out);
  ASSERT_GE(patched_bytes.size(), 4U);
  EXPECT_EQ(patched_bytes[0], 0xde);
  EXPECT_EQ(patched_bytes[1], 0xad);
  EXPECT_EQ(patched_bytes[2], 0xbe);
  EXPECT_EQ(patched_bytes[3], 0xef);

  // Rest of patched file must match original
  auto orig_bytes = read_file_bytes(src);
  ASSERT_EQ(patched_bytes.size(), orig_bytes.size());
  EXPECT_EQ(std::memcmp(patched_bytes.data() + 4, orig_bytes.data() + 4, orig_bytes.size() - 4), 0);

  // Clean up
  std::filesystem::remove(temp_out, ec);
}

}  // namespace
}  // namespace donkey
