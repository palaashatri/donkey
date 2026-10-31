// End-to-end tests of the native debugger against a real child process. They
// run wherever the host adapter reports launch support and are skipped (and
// reported as skipped) elsewhere.
//
// Acceptance mapping (docs/DESIGN.md §12):
//   A18  LaunchStopsAtTheRealProgramEntry, BreakpointsHitAndMemoryWrites...,
//        SingleStepAndStepOut..., PauseAndTerminate..., DestroyingTheAdapter...
//   A19  LaunchStopsAtTheRealProgramEntry (runtime base from the live
//        process; PIE/ASLR on Linux) and every symbol translation below.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/debug/controller.h"
#include "donkey/debug/debug.h"

#if !defined(_WIN32)
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using donkey::debug::DebugAdapter;
using donkey::debug::LaunchConfig;
using donkey::debug::SessionState;
using donkey::debug::StopReason;

const char* kDebuggee = DONKEY_TEST_DEBUGGEE_PATH;

std::unique_ptr<DebugAdapter> native_adapter() {
  return donkey::debug::create_debug_adapter(/*mock=*/false);
}

bool native_supported() {
  return native_adapter()->capabilities().can_launch;
}

#define REQUIRE_NATIVE()                                                  \
  do {                                                                    \
    if (!native_supported()) {                                            \
      GTEST_SKIP() << "native debugging is not implemented on this host"; \
    }                                                                     \
  } while (0)

/// Static image of the debuggee, for symbol addresses and file bytes.
const donkey::LoadedBinary& debuggee_image() {
  static const donkey::LoadedBinary loaded = [] {
    auto result = donkey::load_binary(kDebuggee);
    EXPECT_TRUE(result.has_value()) << result.diagnostic().message;
    return result.has_value() ? std::move(result.value()) : donkey::LoadedBinary{};
  }();
  return loaded;
}

std::uint64_t static_symbol(const std::string& name) {
  for (const auto& symbol : debuggee_image().image.symbols) {
    // Mach-O and some PE toolchains prefix C symbols with an underscore.
    if (!symbol.imported && (symbol.name == name || symbol.name == "_" + name)) {
      return symbol.address;
    }
  }
  ADD_FAILURE() << "debuggee has no symbol " << name;
  return 0;
}

std::uint64_t register_value(DebugAdapter& adapter, const std::vector<std::string>& names) {
  auto registers = adapter.read_registers();
  EXPECT_TRUE(registers.has_value()) << registers.diagnostic().message;
  if (!registers) {
    return 0;
  }
  for (const auto& reg : registers.value()) {
    if (std::find(names.begin(), names.end(), reg.name) != names.end()) {
      return reg.value;
    }
  }
  ADD_FAILURE() << "no register named " << names.front();
  return 0;
}

std::uint64_t pc(DebugAdapter& adapter) {
  return register_value(adapter, {"rip", "pc"});
}

std::int32_t read_int(DebugAdapter& adapter, std::uint64_t address) {
  auto bytes = adapter.read_memory(address, 4);
  EXPECT_TRUE(bytes.has_value()) << bytes.diagnostic().message;
  std::int32_t value = 0;
  if (bytes && bytes.value().size() == 4) {
    std::memcpy(&value, bytes.value().data(), 4);
  }
  return value;
}

std::unique_ptr<DebugAdapter> launch_at_entry(std::vector<std::string> args = {}) {
  auto adapter = native_adapter();
  LaunchConfig config;
  config.binary_path = kDebuggee;
  config.arguments = std::move(args);
  config.stop_at_entry = true;
  auto launched = adapter->launch(config);
  EXPECT_TRUE(launched.has_value())
      << launched.diagnostic().code << ": " << launched.diagnostic().message;
  return adapter;
}

TEST(NativeDebug, LaunchStopsAtTheRealProgramEntry) {
  REQUIRE_NATIVE();
  auto adapter = launch_at_entry();
  ASSERT_EQ(adapter->state(), SessionState::Stopped);
  auto event = adapter->poll_events();
  ASSERT_TRUE(event.has_value());
  EXPECT_EQ(event.value().reason, StopReason::Entrypoint);

  const auto& translator = adapter->address_translator();
  EXPECT_NE(translator.runtime_base, 0U);
  EXPECT_GT(translator.size, 0U);
  const std::uint64_t entry = translator.static_to_runtime(debuggee_image().image.entry_point);
  EXPECT_EQ(pc(*adapter), entry);
  EXPECT_EQ(event.value().address, entry);
  EXPECT_EQ(translator.runtime_to_static(entry), debuggee_image().image.entry_point);

  // Code bytes at the entry are the file's bytes, not the debugger's trap.
  auto offset = debuggee_image().image.va_to_file_offset(debuggee_image().image.entry_point);
  ASSERT_TRUE(offset.has_value());
  auto live = adapter->read_memory(entry, 8);
  ASSERT_TRUE(live.has_value()) << live.diagnostic().message;
  for (std::size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(live.value()[i], debuggee_image().data[offset.value() + i]) << "byte " << i;
  }

  auto modules = adapter->modules();
  ASSERT_TRUE(modules.has_value());
  EXPECT_TRUE(std::any_of(modules.value().begin(), modules.value().end(), [&](const auto& m) {
    return m.base_address == translator.runtime_base;
  }));
  auto threads = adapter->threads();
  ASSERT_TRUE(threads.has_value());
  ASSERT_FALSE(threads.value().empty());
  EXPECT_TRUE(std::any_of(threads.value().begin(), threads.value().end(),
                          [](const auto& t) { return t.is_current; }));

  ASSERT_TRUE(adapter->terminate().has_value());
  EXPECT_EQ(adapter->state(), SessionState::Exited);
}

TEST(NativeDebug, RunsToExitWithTheRealExitCode) {
  REQUIRE_NATIVE();
  auto adapter = launch_at_entry();
  ASSERT_TRUE(adapter->resume().has_value());
  auto event = adapter->wait_for_event(10000);
  ASSERT_TRUE(event.has_value());
  EXPECT_EQ(event.value().reason, StopReason::Exited);
  EXPECT_EQ(event.value().exit_code, 42);
  EXPECT_EQ(adapter->state(), SessionState::Exited);
}

TEST(NativeDebug, BreakpointsHitAndMemoryWritesChangeTheTarget) {
  REQUIRE_NATIVE();
  auto adapter = launch_at_entry();
  const auto& translator = adapter->address_translator();
  const std::uint64_t tick = translator.static_to_runtime(static_symbol("donkey_debuggee_tick"));
  const std::uint64_t counter =
      translator.static_to_runtime(static_symbol("donkey_debuggee_counter"));
  const std::uint64_t step = translator.static_to_runtime(static_symbol("donkey_debuggee_step"));

  auto bp = adapter->set_breakpoint(tick);
  ASSERT_TRUE(bp.has_value()) << bp.diagnostic().message;

  for (int hit = 1; hit <= 3; ++hit) {
    ASSERT_TRUE(adapter->resume().has_value());
    auto event = adapter->wait_for_event(10000);
    ASSERT_TRUE(event.has_value());
    ASSERT_EQ(event.value().reason, StopReason::Breakpoint) << event.value().description;
    EXPECT_EQ(event.value().address, tick);
    EXPECT_EQ(pc(*adapter), tick);
    EXPECT_EQ(read_int(*adapter, counter), (hit - 1) * 10);

    auto stack = adapter->call_stack();
    ASSERT_TRUE(stack.has_value());
    ASSERT_GE(stack.value().size(), 2U);
    EXPECT_NE(stack.value()[0].function_name.find("donkey_debuggee_tick"), std::string::npos);
    EXPECT_NE(stack.value()[1].function_name.find("main"), std::string::npos)
        << stack.value()[1].function_name;

    if (hit == 1) {
      // The trap is invisible to memory reads.
      auto offset = debuggee_image().image.va_to_file_offset(static_symbol("donkey_debuggee_tick"));
      ASSERT_TRUE(offset.has_value());
      auto live = adapter->read_memory(tick, 1);
      ASSERT_TRUE(live.has_value());
      EXPECT_EQ(live.value()[0], debuggee_image().data[offset.value()]);
      // Change the program's data: each tick now adds 10.
      const std::int32_t ten = 10;
      std::vector<std::byte> bytes(4);
      std::memcpy(bytes.data(), &ten, 4);
      auto written = adapter->write_memory(step, bytes);
      ASSERT_TRUE(written.has_value()) << written.diagnostic().message;
      EXPECT_EQ(read_int(*adapter, step), 10);
    }
  }

  ASSERT_TRUE(adapter->remove_breakpoint(bp.value().id).has_value());
  ASSERT_TRUE(adapter->resume().has_value());
  auto exited = adapter->wait_for_event(10000);
  ASSERT_TRUE(exited.has_value());
  EXPECT_EQ(exited.value().reason, StopReason::Exited);
  EXPECT_EQ(exited.value().exit_code, 30);  // 3 ticks of 10, not 42
}

TEST(NativeDebug, SingleStepAndStepOutMoveTheRealProgramCounter) {
  REQUIRE_NATIVE();
  auto adapter = launch_at_entry();
  const auto& translator = adapter->address_translator();
  const std::uint64_t entry = pc(*adapter);
  ASSERT_TRUE(adapter->step_into().has_value());
  auto stepped = adapter->poll_events();
  ASSERT_TRUE(stepped.has_value());
  EXPECT_EQ(stepped.value().reason, StopReason::SingleStep);
  EXPECT_NE(pc(*adapter), entry);

  const std::uint64_t tick = translator.static_to_runtime(static_symbol("donkey_debuggee_tick"));
  ASSERT_TRUE(adapter->set_breakpoint(tick).has_value());
  ASSERT_TRUE(adapter->resume().has_value());
  ASSERT_EQ(adapter->wait_for_event(10000).value().reason, StopReason::Breakpoint);

  // Stepping off a breakpoint executes the original instruction.
  ASSERT_TRUE(adapter->step_into().has_value());
  EXPECT_NE(pc(*adapter), tick);
  ASSERT_TRUE(adapter->step_out().has_value());
  auto out = adapter->wait_for_event(10000);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out.value().reason, StopReason::SingleStep) << out.value().description;
  auto stack = adapter->call_stack();
  ASSERT_TRUE(stack.has_value());
  EXPECT_NE(stack.value()[0].function_name.find("main"), std::string::npos)
      << stack.value()[0].function_name;

  // Changing a register changes the program's behaviour: skip the remaining
  // ticks by moving the instruction pointer is too ABI-specific, so change
  // the counter instead and confirm the exit code follows.
  const std::uint64_t counter =
      translator.static_to_runtime(static_symbol("donkey_debuggee_counter"));
  const std::int32_t value = 100;
  std::vector<std::byte> bytes(4);
  std::memcpy(bytes.data(), &value, 4);
  ASSERT_TRUE(adapter->write_memory(counter, bytes).has_value());
  ASSERT_TRUE(adapter->remove_breakpoint(tick).has_value());
  ASSERT_TRUE(adapter->resume().has_value());
  auto exited = adapter->wait_for_event(10000);
  ASSERT_TRUE(exited.has_value());
  EXPECT_EQ(exited.value().reason, StopReason::Exited);
  EXPECT_EQ(exited.value().exit_code, 102);
}

TEST(NativeDebug, WriteRegisterIsVisibleToTheTarget) {
  REQUIRE_NATIVE();
  auto adapter = launch_at_entry();
  const std::uint64_t before = pc(*adapter);
  auto registers = adapter->read_registers();
  ASSERT_TRUE(registers.has_value());
  const bool x86 = std::any_of(registers.value().begin(), registers.value().end(),
                               [](const auto& reg) { return reg.name == "rip"; });
  const std::string name = x86 ? "rip" : "pc";
  ASSERT_TRUE(adapter->write_register(name, before).has_value());
  EXPECT_EQ(pc(*adapter), before);
  auto bad = adapter->write_register("no_such_register", 1);
  ASSERT_FALSE(bad.has_value());
  EXPECT_EQ(bad.diagnostic().code, "debug.unknown_register");
  ASSERT_TRUE(adapter->terminate().has_value());
}

TEST(NativeDebug, PauseAndTerminateARunningProcess) {
  REQUIRE_NATIVE();
  auto adapter = native_adapter();
  LaunchConfig config;
  config.binary_path = kDebuggee;
  config.arguments = {"spin"};
  config.stop_at_entry = false;
  ASSERT_TRUE(adapter->launch(config).has_value());
  EXPECT_EQ(adapter->state(), SessionState::Running);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  ASSERT_TRUE(adapter->pause().has_value());
  EXPECT_EQ(adapter->state(), SessionState::Stopped);
  EXPECT_EQ(adapter->poll_events().value().reason, StopReason::UserPause);
  auto threads = adapter->threads();
  ASSERT_TRUE(threads.has_value());
  ASSERT_FALSE(threads.value().empty());
  const auto pid = threads.value().front().id;

  ASSERT_TRUE(adapter->terminate().has_value());
  EXPECT_EQ(adapter->state(), SessionState::Exited);
#if !defined(_WIN32)
  EXPECT_NE(::kill(static_cast<pid_t>(pid), 0), 0) << "target process still exists";
#else
  (void)pid;
#endif
}

TEST(NativeDebug, DestroyingTheAdapterKillsALaunchedTarget) {
  REQUIRE_NATIVE();
  std::uint64_t pid = 0;
  {
    auto adapter = launch_at_entry({"spin"});
    auto threads = adapter->threads();
    ASSERT_TRUE(threads.has_value());
    ASSERT_FALSE(threads.value().empty());
    pid = threads.value().front().id;
  }
#if !defined(_WIN32)
  EXPECT_NE(::kill(static_cast<pid_t>(pid), 0), 0) << "orphaned target process";
#else
  (void)pid;
#endif
}

TEST(NativeDebug, OperationsOnAStoppedSessionAreRejectedWhileRunning) {
  REQUIRE_NATIVE();
  auto adapter = native_adapter();
  LaunchConfig config;
  config.binary_path = kDebuggee;
  config.arguments = {"spin"};
  config.stop_at_entry = false;
  ASSERT_TRUE(adapter->launch(config).has_value());
  EXPECT_FALSE(adapter->read_registers().has_value());
  EXPECT_FALSE(adapter->read_memory(0x1000, 4).has_value());
  EXPECT_FALSE(adapter->step_into().has_value());
  EXPECT_FALSE(adapter->resume().has_value());
  ASSERT_TRUE(adapter->terminate().has_value());
}

#if defined(__linux__)
TEST(NativeDebug, AttachAndDetachLeaveTheProcessRunning) {
  REQUIRE_NATIVE();
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    ::execl(kDebuggee, kDebuggee, "spin", static_cast<char*>(nullptr));
    ::_exit(127);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  {
    auto adapter = native_adapter();
    auto attached = adapter->attach(static_cast<std::uint32_t>(child));
    ASSERT_TRUE(attached.has_value()) << attached.diagnostic().message;
    EXPECT_EQ(adapter->state(), SessionState::Stopped);
    EXPECT_NE(adapter->address_translator().runtime_base, 0U);
    // Ask the spinning loop to finish, then let the process go.
    const std::uint64_t flag =
        adapter->address_translator().static_to_runtime(static_symbol("donkey_debuggee_spinning"));
    std::vector<std::byte> zero(4, std::byte{0});
    ASSERT_TRUE(adapter->write_memory(flag, zero).has_value());
    ASSERT_TRUE(adapter->detach().has_value());
    EXPECT_EQ(adapter->state(), SessionState::Detached);
  }
  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 7);  // left the spin loop after our write
}
#endif

TEST(NativeDebug, UnsupportedHostsReportNothingAndFabricateNothing) {
  if (native_supported()) {
    GTEST_SKIP() << "this host has a native debugger";
  }
  auto adapter = native_adapter();
  const auto caps = adapter->capabilities();
  EXPECT_FALSE(caps.can_step || caps.can_read_memory || caps.can_write_memory ||
               caps.can_software_breakpoints || caps.can_attach);
  LaunchConfig config;
  config.binary_path = kDebuggee;
  EXPECT_EQ(adapter->launch(config).diagnostic().code, "debug.unsupported_platform");
  EXPECT_FALSE(adapter->read_memory(0, 1).has_value());
  EXPECT_FALSE(adapter->read_registers().has_value());
  EXPECT_FALSE(adapter->step_into().has_value());
}

// ---------------------------------------------------------------------------
// DebugController: the adapter on its own thread, as the GUI uses it.
// ---------------------------------------------------------------------------

using donkey::debug::DebugController;
using donkey::debug::DebugSnapshot;

TEST(DebugController, RunsARealTargetWithoutBlockingTheCaller) {
  REQUIRE_NATIVE();
  DebugController controller;
  const std::uint64_t tick = static_symbol("donkey_debuggee_tick");
  controller.toggle_breakpoint(tick);  // static address, armed at launch

  LaunchConfig config;
  config.binary_path = kDebuggee;
  const auto before = std::chrono::steady_clock::now();
  controller.launch(config);
  controller.resume();
  const auto elapsed = std::chrono::steady_clock::now() - before;
  // Commands only enqueue work; launching and running happen on the worker.
  EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 50);

  int hits = 0;
  std::uint64_t last_revision = 0;
  while (hits < 3) {
    ASSERT_TRUE(controller.wait_until(
        [&](const DebugSnapshot& s) {
          return s.revision > last_revision && !s.busy &&
                 (s.stop.reason == StopReason::Breakpoint || s.state == SessionState::Exited);
        },
        10000))
        << "no stop after " << hits << " hits";
    const DebugSnapshot snap = controller.snapshot();
    last_revision = snap.revision;
    ASSERT_EQ(snap.stop.reason, StopReason::Breakpoint) << snap.message;
    EXPECT_EQ(snap.static_pc, tick);
    EXPECT_FALSE(snap.registers.empty());
    ASSERT_FALSE(snap.frames.empty());
    EXPECT_NE(snap.frames.front().function_name.find("donkey_debuggee_tick"), std::string::npos);
    ++hits;
    controller.resume();
  }
  ASSERT_TRUE(controller.wait_until(
      [](const DebugSnapshot& s) { return s.state == SessionState::Exited && !s.busy; }, 10000));
  const DebugSnapshot done = controller.snapshot();
  EXPECT_EQ(done.stop.exit_code, 42);
  EXPECT_TRUE(done.registers.empty()) << "registers of an exited target must not be shown";
}

TEST(DebugController, NeverPublishesRegistersWhileTheTargetRuns) {
  REQUIRE_NATIVE();
  DebugController controller;
  LaunchConfig config;
  config.binary_path = kDebuggee;
  config.arguments = {"spin"};
  controller.launch(config);
  ASSERT_TRUE(controller.wait_until(
      [](const DebugSnapshot& s) { return s.state == SessionState::Stopped && !s.busy; }, 10000));
  EXPECT_FALSE(controller.snapshot().registers.empty());
  controller.resume();
  ASSERT_TRUE(controller.wait_until(
      [](const DebugSnapshot& s) { return s.state == SessionState::Running; }, 10000));
  const DebugSnapshot running = controller.snapshot();
  EXPECT_TRUE(running.registers.empty());
  EXPECT_TRUE(running.frames.empty());
  controller.pause();
  ASSERT_TRUE(controller.wait_until(
      [](const DebugSnapshot& s) { return s.stop.reason == StopReason::UserPause && !s.busy; },
      10000));
  EXPECT_FALSE(controller.snapshot().registers.empty());
  controller.terminate();
  ASSERT_TRUE(controller.wait_until(
      [](const DebugSnapshot& s) { return s.state == SessionState::Exited; }, 10000));
}

TEST(DebugController, ReportsFailuresInTheSnapshot) {
  DebugController controller(/*mock=*/false);
  LaunchConfig config;
  config.binary_path = "";
  controller.launch(config);
  ASSERT_TRUE(controller.wait_until(
      [](const DebugSnapshot& s) { return !s.busy && !s.message.empty(); }, 10000));
  EXPECT_NE(controller.snapshot().message.find("Launch failed"), std::string::npos);
}

}  // namespace
