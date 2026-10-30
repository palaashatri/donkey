#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/debug/debug.h"

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace {

using donkey::debug::AddressTranslator;
using donkey::debug::Breakpoint;
using donkey::debug::DebugAdapter;
using donkey::debug::LaunchConfig;
using donkey::debug::SessionState;
using donkey::debug::StopReason;

TEST(Debug, StateMachineTransitionsCleanly) {
  auto adapter = donkey::debug::create_debug_adapter(/*mock=*/true);
  ASSERT_NE(adapter, nullptr);
  EXPECT_EQ(adapter->state(), SessionState::Disconnected);

  LaunchConfig cfg;
  cfg.binary_path = "/tmp/test_binary";
  cfg.stop_at_entry = true;

  auto launched = adapter->launch(cfg);
  ASSERT_TRUE(launched.has_value()) << launched.diagnostic().message;
  EXPECT_EQ(adapter->state(), SessionState::Stopped);

  auto event = adapter->poll_events();
  ASSERT_TRUE(event.has_value());
  EXPECT_EQ(event.value().reason, StopReason::Entrypoint);

  // Resume runs towards completion or breakpoint
  auto resumed = adapter->resume();
  ASSERT_TRUE(resumed.has_value());
  // If no breakpoint set, simulation completes and exits
  EXPECT_EQ(adapter->state(), SessionState::Exited);

  // Terminate transitions cleanly to Exited
  auto terminated = adapter->terminate();
  ASSERT_TRUE(terminated.has_value());
  EXPECT_EQ(adapter->state(), SessionState::Exited);
}

TEST(Debug, BreakpointsAndSingleStep) {
  auto adapter = donkey::debug::create_debug_adapter(/*mock=*/true);
  ASSERT_NE(adapter, nullptr);

  LaunchConfig cfg;
  cfg.binary_path = "/tmp/test_binary";
  cfg.stop_at_entry = true;
  ASSERT_TRUE(adapter->launch(cfg).has_value());

  // Step once
  auto stepped = adapter->step_into();
  ASSERT_TRUE(stepped.has_value()) << stepped.diagnostic().message;
  EXPECT_EQ(adapter->state(), SessionState::Stopped);
  auto ev = adapter->poll_events();
  EXPECT_EQ(ev.value().reason, StopReason::SingleStep);

  // Read registers to see IP moved
  auto regs = adapter->read_registers();
  ASSERT_TRUE(regs.has_value());
  std::uint64_t rip_val = 0;
  for (const auto& r : regs.value()) {
    if (r.name == "rip") {
      rip_val = r.value;
    }
  }
  EXPECT_NE(rip_val, 0U);

  // Set a breakpoint at rip + 8
  const std::uint64_t bp_addr = rip_val + 8;
  auto bp_res = adapter->set_breakpoint(bp_addr);
  ASSERT_TRUE(bp_res.has_value());
  EXPECT_EQ(bp_res.value().address, bp_addr);
  EXPECT_TRUE(bp_res.value().enabled);

  // Resume; should hit the breakpoint
  auto cont = adapter->resume();
  ASSERT_TRUE(cont.has_value());
  EXPECT_EQ(adapter->state(), SessionState::Stopped);
  ev = adapter->poll_events();
  EXPECT_EQ(ev.value().reason, StopReason::Breakpoint);
  EXPECT_EQ(ev.value().address, bp_addr);

  // Remove breakpoint
  auto removed = adapter->remove_breakpoint(bp_res.value().id);
  ASSERT_TRUE(removed.has_value());
  EXPECT_TRUE(removed.value());
}

TEST(Debug, RegisterAndMemoryAccess) {
  auto adapter = donkey::debug::create_debug_adapter(/*mock=*/true);
  ASSERT_NE(adapter, nullptr);

  LaunchConfig cfg;
  cfg.binary_path = "/tmp/test_binary";
  ASSERT_TRUE(adapter->launch(cfg).has_value());

  // Write register
  auto wreg = adapter->write_register("rax", 0xcafebabe);
  ASSERT_TRUE(wreg.has_value());

  auto regs = adapter->read_registers();
  ASSERT_TRUE(regs.has_value());
  std::uint64_t rax_val = 0;
  for (const auto& r : regs.value()) {
    if (r.name == "rax") {
      rax_val = r.value;
    }
  }
  EXPECT_EQ(rax_val, 0xcafebabeULL);

  // Memory read and write
  std::byte write_buf[] = {std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};
  auto wmem = adapter->write_memory(0x10000, write_buf);
  ASSERT_TRUE(wmem.has_value());
  EXPECT_EQ(wmem.value(), 4U);

  auto rmem = adapter->read_memory(0x10000, 4);
  ASSERT_TRUE(rmem.has_value());
  ASSERT_EQ(rmem.value().size(), 4U);
  EXPECT_EQ(rmem.value()[0], std::byte{0xde});
  EXPECT_EQ(rmem.value()[1], std::byte{0xad});
  EXPECT_EQ(rmem.value()[2], std::byte{0xbe});
  EXPECT_EQ(rmem.value()[3], std::byte{0xef});

  // Out of bounds memory read returns diagnostic without crashing
  auto bad_read = adapter->read_memory(0xffffffff00000000ULL, 16);
  ASSERT_FALSE(bad_read.has_value());
  EXPECT_EQ(bad_read.diagnostic().code, "debug.invalid_address");
}

TEST(Debug, MockAdapterLaunchStepAndCleanupStateMachine) {
  // Exercises the simulation adapter only. Real-process acceptance for A18
  // lives in native_debug_test.cpp.
  auto adapter = donkey::debug::create_debug_adapter(/*mock=*/true);
  ASSERT_NE(adapter, nullptr);

  LaunchConfig cfg;
  cfg.binary_path = "/bin/ls";
  cfg.arguments = {"-la"};
  cfg.stop_at_entry = true;

  auto res = adapter->launch(cfg);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  EXPECT_EQ(adapter->state(), SessionState::Stopped);

  auto frames = adapter->call_stack();
  ASSERT_TRUE(frames.has_value());
  EXPECT_FALSE(frames.value().empty());
  EXPECT_EQ(frames.value()[0].index, 0U);

  auto threads = adapter->threads();
  ASSERT_TRUE(threads.has_value());
  EXPECT_FALSE(threads.value().empty());
  EXPECT_TRUE(threads.value()[0].is_current);

  // Single step
  ASSERT_TRUE(adapter->step_into().has_value());

  // Terminate cleanly
  ASSERT_TRUE(adapter->terminate().has_value());
  EXPECT_EQ(adapter->state(), SessionState::Exited);

  // Detach
  ASSERT_TRUE(adapter->detach().has_value());
  EXPECT_EQ(adapter->state(), SessionState::Detached);
}

TEST(Debug, MockAdapterAddressTranslation) {
  // Translator arithmetic with a simulated slide. Real ASLR translation (A19)
  // is checked against a live process in native_debug_test.cpp.
  // Static image base: 0x100000000
  // ASLR runtime base: 0x100040000 (+0x40000 slide)
  const std::uint64_t kStaticBase = 0x100000000;
  const std::uint64_t kRuntimeBase = 0x100040000;

  auto adapter = donkey::debug::create_debug_adapter(/*mock=*/true, kRuntimeBase);
  ASSERT_NE(adapter, nullptr);

  const auto& translator = adapter->address_translator();
  EXPECT_EQ(translator.static_base, kStaticBase);
  EXPECT_EQ(translator.runtime_base, kRuntimeBase);

  // Translate runtime address to static address
  const std::uint64_t runtime_ip = kRuntimeBase + 0x1234;
  const std::uint64_t static_ip = translator.runtime_to_static(runtime_ip);
  EXPECT_EQ(static_ip, kStaticBase + 0x1234);

  // Translate static address back to runtime address
  EXPECT_EQ(translator.static_to_runtime(static_ip), runtime_ip);

  // Launch and verify call stack uses translated static address
  LaunchConfig cfg;
  cfg.binary_path = "/tmp/test_binary";
  cfg.stop_at_entry = true;
  ASSERT_TRUE(adapter->launch(cfg).has_value());

  auto frames = adapter->call_stack();
  ASSERT_TRUE(frames.has_value());
  ASSERT_FALSE(frames.value().empty());
  EXPECT_EQ(frames.value()[0].instruction_pointer, runtime_ip - 0x234);
  EXPECT_EQ(frames.value()[0].static_address, kStaticBase + 0x1000);
}

TEST(Debug, NativeAdapterRejectsBadRequestsWithoutSideEffects) {
  auto adapter = donkey::debug::create_debug_adapter(/*mock=*/false);
  ASSERT_NE(adapter, nullptr);
  const bool native = adapter->capabilities().can_launch;
  auto expect_code = [&](const donkey::Diagnostic& diagnostic, const char* code) {
    if (native) {
      EXPECT_EQ(diagnostic.code, code) << diagnostic.message;
    } else {
      EXPECT_EQ(diagnostic.code, "debug.unsupported_platform") << diagnostic.message;
    }
  };

  LaunchConfig cfg;
  cfg.binary_path = "";
  auto launch_res = adapter->launch(cfg);
  ASSERT_FALSE(launch_res.has_value());
  expect_code(launch_res.diagnostic(), "debug.invalid_path");

  auto rm_res = adapter->remove_breakpoint(0xdeadbeef);
  ASSERT_FALSE(rm_res.has_value());
  expect_code(rm_res.diagnostic(), "debug.breakpoint_not_found");

  auto attach_zero = adapter->attach(0);
  ASSERT_FALSE(attach_zero.has_value());
  expect_code(attach_zero.diagnostic(), "debug.invalid_pid");

#if !defined(_WIN32)
  // Attaching to init must be refused for an unprivileged user. Never try it
  // as root: it would really stop pid 1.
  if (::geteuid() != 0) {
    auto attach_init = adapter->attach(1);
    ASSERT_FALSE(attach_init.has_value());
    expect_code(attach_init.diagnostic(), "debug.permission_denied");
  }
#endif

  EXPECT_FALSE(adapter->read_memory(0x1000, 4).has_value());
  EXPECT_FALSE(adapter->read_registers().has_value());
  EXPECT_FALSE(adapter->step_into().has_value());
}

}  // namespace
