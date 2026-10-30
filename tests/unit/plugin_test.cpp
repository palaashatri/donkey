#include "donkey/plugin/plugin.h"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

namespace donkey {
namespace {

TEST(PluginTest, InspectManifestValidPlugin) {
  auto res = PluginHost::inspect_manifest(TEST_PLUGIN_VALID_PATH);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;

  const auto& manifest = res.value();
  EXPECT_EQ(manifest.id, "org.donkey.test.valid");
  EXPECT_EQ(manifest.name, "Valid Test Plugin");
  EXPECT_EQ(manifest.version, "1.0.0");
  EXPECT_EQ(manifest.abi_version_major, 1U);
  EXPECT_EQ(manifest.abi_version_minor, 0U);
  EXPECT_EQ(manifest.requested_capabilities, DONKEY_CAP_ANALYSIS);
}

TEST(PluginTest, RejectsBadAbiVersionExplicitly) {
  // Acceptance scenario A20: Plugin bad-version
  auto res = PluginHost::inspect_manifest(TEST_PLUGIN_BAD_ABI_PATH);
  EXPECT_FALSE(res.has_value());
  EXPECT_EQ(res.diagnostic().code, "plugin.abi_version_mismatch");
  EXPECT_EQ(res.diagnostic().status, Status::InvalidInput);
}

TEST(PluginTest, TrustedExecutionSucceedsWhenGranted) {
  auto res = PluginHost::execute_trusted(TEST_PLUGIN_VALID_PATH, "{}", DONKEY_CAP_ANALYSIS);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  EXPECT_TRUE(res.value().success);
  EXPECT_NE(res.value().output_json.find("\"status\":\"ok\""), std::string::npos);
}

TEST(PluginTest, TrustedExecutionFailsWhenCapabilityDenied) {
  // Deny analysis capability
  auto res = PluginHost::execute_trusted(TEST_PLUGIN_VALID_PATH, "{}", DONKEY_CAP_NONE);
  EXPECT_FALSE(res.has_value());
  EXPECT_EQ(res.diagnostic().code, "plugin.capability_denied");
  EXPECT_EQ(res.diagnostic().status, Status::PermissionDenied);
}

TEST(PluginTest, IsolatedExecutionSucceeds) {
#if !defined(__unix__) && !defined(__APPLE__)
  GTEST_SKIP() << "OS process isolation not supported on this platform";
#endif
  auto res = PluginHost::execute_isolated(TEST_PLUGIN_VALID_PATH, "{}", DONKEY_CAP_ANALYSIS, 3);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  EXPECT_TRUE(res.value().success);
  EXPECT_NE(res.value().output_json.find("\"status\":\"ok\""), std::string::npos);
}

TEST(PluginTest, IsolatedCrashFixtureVerifiesA20) {
  // Acceptance scenario A20: Plugin crash fixture
  // Explicit crash isolation and core supervisor survival.
#if !defined(__unix__) && !defined(__APPLE__)
  GTEST_SKIP() << "OS process isolation not supported on this platform";
#endif
  auto res = PluginHost::execute_isolated(TEST_PLUGIN_CRASH_PATH, "{}", DONKEY_CAP_NONE, 3);
  ASSERT_TRUE(res.has_value());

  const auto& exec = res.value();
  EXPECT_FALSE(exec.success);
  EXPECT_TRUE(exec.crashed);
  EXPECT_EQ(exec.error_code, "plugin.crashed");
  // Supervisor process is running cleanly and safely!
}

TEST(PluginTest, IsolatedHangFixtureTimesOutCleanly) {
  // Untrusted plugin hanging in infinite loop is terminated by supervisor.
#if !defined(__unix__) && !defined(__APPLE__)
  GTEST_SKIP() << "OS process isolation not supported on this platform";
#endif
  auto res = PluginHost::execute_isolated(TEST_PLUGIN_HANG_PATH, "{}", DONKEY_CAP_NONE, 1);
  ASSERT_TRUE(res.has_value());

  const auto& exec = res.value();
  EXPECT_FALSE(exec.success);
  EXPECT_TRUE(exec.timed_out);
  EXPECT_EQ(exec.error_code, "plugin.timeout");
}

TEST(PluginTest, InspectManifestIsolatedValidPlugin) {
#if !defined(__unix__) && !defined(__APPLE__)
  GTEST_SKIP() << "OS process isolation not supported on this platform";
#endif
  auto res = PluginHost::inspect_manifest_isolated(TEST_PLUGIN_VALID_PATH, 3);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;

  const auto& manifest = res.value();
  EXPECT_EQ(manifest.id, "org.donkey.test.valid");
  EXPECT_EQ(manifest.name, "Valid Test Plugin");
  EXPECT_EQ(manifest.version, "1.0.0");
  EXPECT_EQ(manifest.abi_version_major, 1U);
  EXPECT_EQ(manifest.abi_version_minor, 0U);
  EXPECT_EQ(manifest.requested_capabilities, DONKEY_CAP_ANALYSIS);
}

TEST(PluginTest, InspectManifestIsolatedCatchesCrashInLibraryConstructor) {
  // Acceptance scenario: A library whose static constructor crashes (SIGSEGV)
  // must never crash the parent process when inspected in isolation.
#if !defined(__unix__) && !defined(__APPLE__)
  GTEST_SKIP() << "OS process isolation not supported on this platform";
#endif
  auto res = PluginHost::inspect_manifest_isolated(TEST_PLUGIN_CTOR_CRASH_PATH, 3);
  EXPECT_FALSE(res.has_value());
  EXPECT_TRUE(res.diagnostic().code == "plugin.crashed" ||
              res.diagnostic().code == "plugin.worker_terminated");
}

TEST(PluginTest, IsolatedNonTerminatedOutputIsSafelyBounded) {
  // Acceptance scenario: Plugin returns buffer without null-terminator.
  // Supervisor must handle safely without memory out-of-bounds.
#if !defined(__unix__) && !defined(__APPLE__)
  GTEST_SKIP() << "OS process isolation not supported on this platform";
#endif
  auto res =
      PluginHost::execute_isolated(TEST_PLUGIN_NON_TERMINATED_PATH, "{}", DONKEY_CAP_NONE, 3);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  const auto& exec = res.value();
  EXPECT_TRUE(exec.success);
  EXPECT_FALSE(exec.crashed);
  EXPECT_FALSE(exec.output_json.empty());
}

TEST(PluginTest, IpcResponseRejectsTruncatedHeader) {
  // Response smaller than sizeof(int)
  std::vector<char> tiny = {0x00, 0x00};
  auto res = PluginHost::parse_worker_response(0, tiny);
  ASSERT_TRUE(res.has_value());
  EXPECT_FALSE(res.value().success);
  EXPECT_EQ(res.value().error_code, "plugin.worker_failed");

  // Response has sizeof(int) == 0, but is missing uint32_t length prefix
  std::vector<char> no_len(4, 0);
  auto res2 = PluginHost::parse_worker_response(0, no_len);
  ASSERT_TRUE(res2.has_value());
  EXPECT_FALSE(res2.value().success);
  EXPECT_EQ(res2.value().error_code, "plugin.ipc_error");
}

TEST(PluginTest, IpcResponseRejectsTruncatedPayload) {
  // Header declares 50 bytes output, but buffer only provides 10 bytes
  std::vector<char> truncated(sizeof(int) + sizeof(uint32_t) + 10, 'A');
  int exec_rc = 0;
  uint32_t declared_len = 50;
  std::memcpy(truncated.data(), &exec_rc, sizeof(exec_rc));
  std::memcpy(truncated.data() + sizeof(int), &declared_len, sizeof(declared_len));

  auto res = PluginHost::parse_worker_response(0, truncated);
  ASSERT_TRUE(res.has_value());
  EXPECT_FALSE(res.value().success);
  EXPECT_EQ(res.value().error_code, "plugin.ipc_error");
}

TEST(PluginTest, IpcResponseRejectsExcessPayload) {
  // Header declares 5 bytes output, but buffer provides 10 bytes
  std::vector<char> excess(sizeof(int) + sizeof(uint32_t) + 10, 'B');
  int exec_rc = 0;
  uint32_t declared_len = 5;
  std::memcpy(excess.data(), &exec_rc, sizeof(exec_rc));
  std::memcpy(excess.data() + sizeof(int), &declared_len, sizeof(declared_len));

  auto res = PluginHost::parse_worker_response(0, excess);
  ASSERT_TRUE(res.has_value());
  EXPECT_FALSE(res.value().success);
  EXPECT_EQ(res.value().error_code, "plugin.ipc_error");
}

TEST(PluginTest, IpcResponseAcceptsExactPayload) {
  std::string expected_json = R"({"result": "ok"})";
  std::vector<char> valid(sizeof(int) + sizeof(uint32_t) + expected_json.size());
  int exec_rc = 0;
  uint32_t declared_len = static_cast<uint32_t>(expected_json.size());
  std::memcpy(valid.data(), &exec_rc, sizeof(exec_rc));
  std::memcpy(valid.data() + sizeof(int), &declared_len, sizeof(declared_len));
  std::memcpy(valid.data() + sizeof(int) + sizeof(uint32_t), expected_json.data(),
              expected_json.size());

  auto res = PluginHost::parse_worker_response(0, valid);
  ASSERT_TRUE(res.has_value());
  EXPECT_TRUE(res.value().success);
  EXPECT_EQ(res.value().output_json, expected_json);
}

}  // namespace
}  // namespace donkey
