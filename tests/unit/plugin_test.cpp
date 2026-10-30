#include "donkey/plugin/plugin.h"

#include <gtest/gtest.h>

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
  auto res = PluginHost::execute_isolated(TEST_PLUGIN_VALID_PATH, "{}", DONKEY_CAP_ANALYSIS, 3);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  EXPECT_TRUE(res.value().success);
  EXPECT_NE(res.value().output_json.find("\"status\":\"ok\""), std::string::npos);
}

TEST(PluginTest, IsolatedCrashFixtureVerifiesA20) {
  // Acceptance scenario A20: Plugin crash fixture
  // Explicit crash isolation and core supervisor survival.
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
  auto res = PluginHost::execute_isolated(TEST_PLUGIN_HANG_PATH, "{}", DONKEY_CAP_NONE, 1);
  ASSERT_TRUE(res.has_value());

  const auto& exec = res.value();
  EXPECT_FALSE(exec.success);
  EXPECT_TRUE(exec.timed_out);
  EXPECT_EQ(exec.error_code, "plugin.timeout");
}

}  // namespace
}  // namespace donkey
