#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "donkey/debug/debug.h"

namespace donkey::debug {

/// Everything a front end shows about a debug session, published by the
/// controller after every state change. A snapshot is a value: once copied it
/// never changes, so the render thread can draw it without locks.
struct DebugSnapshot {
  std::uint64_t revision = 0;  ///< increases with every publication
  SessionState state = SessionState::Disconnected;
  bool busy = false;  ///< a command is executing on the worker
  StopInfo stop;
  std::uint64_t static_pc = 0;  ///< stop address in static image terms
  AddressTranslator translator;
  DebugCapabilities capabilities;
  /// Registers, frames, threads and modules describe the current stop. They
  /// are cleared as soon as the target resumes, so stale values are never
  /// shown as current.
  std::vector<RegisterValue> registers;
  std::vector<StackFrame> frames;
  std::vector<DebugThread> threads;
  std::vector<DebugModule> modules;
  /// Breakpoints the user asked for, in static image addresses.
  std::vector<std::uint64_t> breakpoints;
  /// Result of the last memory read request.
  std::uint64_t memory_address = 0;
  std::vector<std::byte> memory;
  /// Last error, empty after a successful command.
  std::string message;
};

/// Runs a DebugAdapter on its own thread. ptrace and the Win32 debug API bind
/// a debuggee to the OS thread that started it, and stepping or waiting can
/// take time, so no front end may call the adapter directly from a UI thread.
/// Every public method only enqueues work and returns immediately.
class DebugController {
 public:
  /// `mock` selects the simulation adapter (see create_debug_adapter).
  explicit DebugController(bool mock = false);
  ~DebugController();

  DebugController(const DebugController&) = delete;
  DebugController& operator=(const DebugController&) = delete;

  /// Launch `config` and arm the static breakpoints already set.
  void launch(LaunchConfig config);
  void attach(std::uint32_t pid);
  void resume();
  void pause();
  void step_into();
  void step_over();
  void step_out();
  void terminate();
  void detach();
  /// Breakpoints are kept in static addresses and translated through the
  /// live ASLR base whenever a target is running; they survive relaunch.
  void toggle_breakpoint(std::uint64_t static_address);
  void read_memory(std::uint64_t runtime_address, std::size_t size);

  [[nodiscard]] DebugSnapshot snapshot() const;
  [[nodiscard]] DebugCapabilities capabilities() const noexcept { return capabilities_; }

  /// Block until a snapshot satisfies `predicate` or `timeout_ms` passes.
  /// For tests and scripted front ends, never for a render loop.
  bool wait_until(const std::function<bool(const DebugSnapshot&)>& predicate, int timeout_ms);

 private:
  using Command = std::function<void()>;

  void enqueue(Command command);
  void run();
  void publish(const std::string& message = {});
  void report(const Result<bool>& result, const char* action);

  bool mock_;
  DebugCapabilities capabilities_;
  std::unique_ptr<DebugAdapter> adapter_;   // created and used only on worker_
  std::vector<std::uint64_t> breakpoints_;  // worker-owned copy

  mutable std::mutex mutex_;
  std::condition_variable wake_;
  mutable std::condition_variable published_;
  std::deque<Command> queue_;
  bool stopping_ = false;
  DebugSnapshot snapshot_;
  std::thread worker_;
};

}  // namespace donkey::debug
