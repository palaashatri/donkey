#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "donkey/core/result.h"

namespace donkey::debug {

enum class SessionState : std::uint8_t {
  Disconnected = 0,
  Launching,
  Attaching,
  Running,
  Stopped,
  Terminating,
  Detached,
  Exited,
  Error,
};

const char* session_state_name(SessionState state) noexcept;

enum class StopReason : std::uint8_t {
  None = 0,
  Entrypoint,
  Breakpoint,
  SingleStep,
  Signal,
  Exception,
  UserPause,
  Exited,
};

const char* stop_reason_name(StopReason reason) noexcept;

struct RegisterValue {
  std::string name;
  std::uint64_t value = 0;
  std::uint8_t size = 8;
};

struct StackFrame {
  std::uint32_t index = 0;
  std::uint64_t instruction_pointer = 0;
  std::uint64_t stack_pointer = 0;
  std::uint64_t frame_pointer = 0;
  std::string module_name;
  std::string function_name;
  std::uint64_t static_address = 0;
};

struct DebugThread {
  std::uint64_t id = 0;
  std::string name;
  bool is_current = false;
  StopReason stop_reason = StopReason::None;
};

struct DebugModule {
  std::string name;
  std::string path;
  std::uint64_t base_address = 0;
  std::uint64_t size = 0;
};

struct Breakpoint {
  std::uint64_t id = 0;
  std::uint64_t address = 0;
  bool enabled = true;
  std::uint64_t hit_count = 0;
  std::string condition;
};

struct StopInfo {
  StopReason reason = StopReason::None;
  std::uint64_t thread_id = 0;
  std::uint64_t address = 0;
  std::string description;
  int exit_code = 0;
};

struct LaunchConfig {
  std::string binary_path;
  std::vector<std::string> arguments;
  std::string working_directory;
  std::vector<std::pair<std::string, std::string>> environment;
  bool stop_at_entry = true;
};

struct DebugCapabilities {
  bool can_launch = true;
  bool can_attach = false;
  bool can_step = true;
  bool can_read_memory = true;
  bool can_write_memory = true;
  bool can_software_breakpoints = true;
  bool can_hardware_breakpoints = false;
};

/// Translates target runtime addresses into static binary image addresses
/// and vice versa for ASLR and relocated images (Acceptance A18, A19).
struct AddressTranslator {
  std::uint64_t runtime_base = 0;
  std::uint64_t static_base = 0;
  std::uint64_t size = 0;

  [[nodiscard]] std::uint64_t runtime_to_static(std::uint64_t runtime_va) const noexcept {
    if (size > 0 && runtime_va >= runtime_base && runtime_va < runtime_base + size) {
      return static_base + (runtime_va - runtime_base);
    }
    return runtime_va;
  }

  [[nodiscard]] std::uint64_t static_to_runtime(std::uint64_t static_va) const noexcept {
    if (size > 0 && static_va >= static_base && static_va < static_base + size) {
      return runtime_base + (static_va - static_base);
    }
    return static_va;
  }
};

class DebugAdapter {
 public:
  virtual ~DebugAdapter() = default;

  [[nodiscard]] virtual DebugCapabilities capabilities() const noexcept = 0;
  [[nodiscard]] virtual Result<bool> launch(const LaunchConfig& config) = 0;
  [[nodiscard]] virtual Result<bool> attach(std::uint32_t pid) = 0;
  [[nodiscard]] virtual Result<bool> detach() = 0;
  [[nodiscard]] virtual Result<bool> terminate() = 0;
  [[nodiscard]] virtual Result<bool> resume() = 0;
  [[nodiscard]] virtual Result<bool> pause() = 0;
  [[nodiscard]] virtual Result<bool> step_into() = 0;
  [[nodiscard]] virtual Result<bool> step_over() = 0;
  [[nodiscard]] virtual Result<bool> step_out() = 0;
  [[nodiscard]] virtual Result<Breakpoint> set_breakpoint(std::uint64_t address) = 0;
  [[nodiscard]] virtual Result<bool> remove_breakpoint(std::uint64_t id_or_address) = 0;
  [[nodiscard]] virtual Result<std::vector<std::byte>> read_memory(std::uint64_t address,
                                                                   std::size_t size) = 0;
  [[nodiscard]] virtual Result<std::size_t> write_memory(std::uint64_t address,
                                                         std::span<const std::byte> data) = 0;
  [[nodiscard]] virtual Result<std::vector<RegisterValue>> read_registers() = 0;
  [[nodiscard]] virtual Result<bool> write_register(const std::string& name,
                                                    std::uint64_t value) = 0;
  [[nodiscard]] virtual Result<std::vector<StackFrame>> call_stack() = 0;
  [[nodiscard]] virtual Result<std::vector<DebugThread>> threads() = 0;
  [[nodiscard]] virtual Result<std::vector<DebugModule>> modules() = 0;
  [[nodiscard]] virtual Result<StopInfo> poll_events() = 0;
  [[nodiscard]] virtual SessionState state() const noexcept = 0;
  [[nodiscard]] virtual const AddressTranslator& address_translator() const noexcept = 0;
};

/// Create a debug adapter. When `mock` is true, returns a deterministic in-process
/// simulation adapter suitable for automated CI and hermetic acceptance tests (A18, A19).
[[nodiscard]] std::unique_ptr<DebugAdapter> create_debug_adapter(
    bool mock = false, std::uint64_t simulated_aslr_base = 0);

}  // namespace donkey::debug
