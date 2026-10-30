#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "donkey/debug/debug.h"

namespace donkey::debug {

class MockDebugAdapter : public DebugAdapter {
 public:
  explicit MockDebugAdapter(std::uint64_t simulated_aslr_base = 0);
  ~MockDebugAdapter() override = default;

  [[nodiscard]] DebugCapabilities capabilities() const noexcept override;
  [[nodiscard]] Result<bool> launch(const LaunchConfig& config) override;
  [[nodiscard]] Result<bool> attach(std::uint32_t pid) override;
  [[nodiscard]] Result<bool> detach() override;
  [[nodiscard]] Result<bool> terminate() override;
  [[nodiscard]] Result<bool> resume() override;
  [[nodiscard]] virtual Result<bool> pause() override;
  [[nodiscard]] Result<bool> step_into() override;
  [[nodiscard]] Result<bool> step_over() override;
  [[nodiscard]] Result<bool> step_out() override;
  [[nodiscard]] Result<Breakpoint> set_breakpoint(std::uint64_t address) override;
  [[nodiscard]] Result<bool> remove_breakpoint(std::uint64_t id_or_address) override;
  [[nodiscard]] Result<std::vector<std::byte>> read_memory(std::uint64_t address,
                                                           std::size_t size) override;
  [[nodiscard]] Result<std::size_t> write_memory(std::uint64_t address,
                                                 std::span<const std::byte> data) override;
  [[nodiscard]] Result<std::vector<RegisterValue>> read_registers() override;
  [[nodiscard]] Result<bool> write_register(const std::string& name, std::uint64_t value) override;
  [[nodiscard]] Result<std::vector<StackFrame>> call_stack() override;
  [[nodiscard]] Result<std::vector<DebugThread>> threads() override;
  [[nodiscard]] virtual Result<std::vector<DebugModule>> modules() override;
  [[nodiscard]] Result<StopInfo> poll_events() override;
  [[nodiscard]] SessionState state() const noexcept override { return state_; }
  [[nodiscard]] const AddressTranslator& address_translator() const noexcept override {
    return translator_;
  }

  void set_permission_denied(bool deny) { fail_permission_ = deny; }

 private:
  SessionState state_ = SessionState::Disconnected;
  AddressTranslator translator_;
  std::unordered_map<std::uint64_t, Breakpoint> breakpoints_;
  std::unordered_map<std::string, std::uint64_t> registers_;
  std::vector<std::byte> memory_;
  std::uint64_t memory_base_ = 0x10000;
  std::uint64_t current_pc_ = 0;
  std::uint64_t entry_pc_ = 0;
  std::uint64_t next_bp_id_ = 1;
  bool fail_permission_ = false;
  StopInfo pending_event_;
};

/// Native OS debugger for the host. Real execution control exists on Linux
/// (ptrace; x86-64 and AArch64) and Windows (Win32 debug API; x64). On other
/// hosts every operation fails with `debug.unsupported_platform` and
/// `capabilities()` reports nothing; it never fabricates success.
///
/// Thread affinity: ptrace and the Win32 debug API bind a debuggee to the OS
/// thread that launched or attached it, so every call on one adapter must
/// come from that same thread.
class LocalDebugAdapter : public DebugAdapter {
 public:
  LocalDebugAdapter();
  ~LocalDebugAdapter() override;

  [[nodiscard]] DebugCapabilities capabilities() const noexcept override;
  [[nodiscard]] Result<bool> launch(const LaunchConfig& config) override;
  [[nodiscard]] Result<bool> attach(std::uint32_t pid) override;
  [[nodiscard]] Result<bool> detach() override;
  [[nodiscard]] Result<bool> terminate() override;
  [[nodiscard]] Result<bool> resume() override;
  [[nodiscard]] Result<bool> pause() override;
  [[nodiscard]] Result<bool> step_into() override;
  [[nodiscard]] Result<bool> step_over() override;
  [[nodiscard]] Result<bool> step_out() override;
  [[nodiscard]] Result<Breakpoint> set_breakpoint(std::uint64_t address) override;
  [[nodiscard]] Result<bool> remove_breakpoint(std::uint64_t id_or_address) override;
  [[nodiscard]] Result<std::vector<std::byte>> read_memory(std::uint64_t address,
                                                           std::size_t size) override;
  [[nodiscard]] Result<std::size_t> write_memory(std::uint64_t address,
                                                 std::span<const std::byte> data) override;
  [[nodiscard]] Result<std::vector<RegisterValue>> read_registers() override;
  [[nodiscard]] Result<bool> write_register(const std::string& name, std::uint64_t value) override;
  [[nodiscard]] Result<std::vector<StackFrame>> call_stack() override;
  [[nodiscard]] Result<std::vector<DebugThread>> threads() override;
  [[nodiscard]] Result<std::vector<DebugModule>> modules() override;
  [[nodiscard]] Result<StopInfo> poll_events() override;
  [[nodiscard]] Result<StopInfo> wait_for_event(int timeout_ms) override;
  [[nodiscard]] SessionState state() const noexcept override;
  [[nodiscard]] const AddressTranslator& address_translator() const noexcept override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace donkey::debug
