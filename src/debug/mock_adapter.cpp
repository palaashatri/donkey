#include <algorithm>
#include <cstring>

#include "debug_internal.h"

namespace donkey::debug {

MockDebugAdapter::MockDebugAdapter(std::uint64_t simulated_aslr_base) {
  translator_.static_base = 0x100000000;
  translator_.runtime_base = simulated_aslr_base != 0 ? simulated_aslr_base : 0x100000000;
  translator_.size = 0x100000;  // 1 MiB address space

  entry_pc_ = translator_.runtime_base + 0x1000;
  current_pc_ = entry_pc_;

  registers_["rip"] = current_pc_;
  registers_["rsp"] = 0x7ffe0000;
  registers_["rbp"] = 0x7ffe0020;
  registers_["rax"] = 0;
  registers_["rbx"] = 0;
  registers_["rcx"] = 0;
  registers_["rdx"] = 0;
  registers_["rsi"] = 0;
  registers_["rdi"] = 0;
  registers_["r8"] = 0;
  registers_["r9"] = 0;
  registers_["rflags"] = 0x246;

  memory_.resize(0x20000, std::byte{0});
  // Write some identifiable bytes at memory_base_
  for (std::size_t i = 0; i < 256; ++i) {
    memory_[i] = static_cast<std::byte>(i & 0xff);
  }
}

DebugCapabilities MockDebugAdapter::capabilities() const noexcept {
  DebugCapabilities caps;
  caps.can_launch = true;
  caps.can_attach = true;
  caps.can_step = true;
  caps.can_read_memory = true;
  caps.can_write_memory = true;
  caps.can_software_breakpoints = true;
  caps.can_hardware_breakpoints = false;
  return caps;
}

Result<bool> MockDebugAdapter::launch(const LaunchConfig& config) {
  if (fail_permission_) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::PermissionDenied, "debug.permission_denied",
                            "process launch permission was denied by system policy");
  }

  if (config.binary_path.empty()) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_path",
                            "binary path cannot be empty");
  }

  current_pc_ = entry_pc_;
  registers_["rip"] = current_pc_;

  if (config.stop_at_entry) {
    state_ = SessionState::Stopped;
    pending_event_.reason = StopReason::Entrypoint;
    pending_event_.thread_id = 1;
    pending_event_.address = current_pc_;
    pending_event_.description = "stopped at process entrypoint";
  } else {
    state_ = SessionState::Running;
    pending_event_.reason = StopReason::None;
  }
  return true;
}

Result<bool> MockDebugAdapter::attach(std::uint32_t pid) {
  if (fail_permission_) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::PermissionDenied, "debug.permission_denied",
                            "attach denied: missing entitlements or process isolation");
  }
  if (pid == 0) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_pid", "cannot attach to pid 0");
  }
  state_ = SessionState::Stopped;
  pending_event_.reason = StopReason::UserPause;
  pending_event_.thread_id = 1;
  pending_event_.address = current_pc_;
  pending_event_.description = "attached to process";
  return true;
}

Result<bool> MockDebugAdapter::detach() {
  state_ = SessionState::Detached;
  pending_event_.reason = StopReason::None;
  return true;
}

Result<bool> MockDebugAdapter::terminate() {
  state_ = SessionState::Exited;
  pending_event_.reason = StopReason::Exited;
  pending_event_.exit_code = 0;
  pending_event_.description = "process exited normally";
  return true;
}

Result<bool> MockDebugAdapter::resume() {
  if (state_ != SessionState::Stopped) {
    return make_error<bool>(Status::InvalidInput, "debug.invalid_state",
                            "cannot resume when not stopped");
  }

  // Advance PC until next breakpoint or finish
  state_ = SessionState::Running;
  for (int step = 0; step < 10; ++step) {
    current_pc_ += 4;
    registers_["rip"] = current_pc_;
    auto it = breakpoints_.find(current_pc_);
    if (it != breakpoints_.end() && it->second.enabled) {
      it->second.hit_count++;
      state_ = SessionState::Stopped;
      pending_event_.reason = StopReason::Breakpoint;
      pending_event_.thread_id = 1;
      pending_event_.address = current_pc_;
      pending_event_.description = "hit breakpoint";
      return true;
    }
  }

  // If no breakpoint was hit, reach completion
  state_ = SessionState::Exited;
  pending_event_.reason = StopReason::Exited;
  pending_event_.exit_code = 0;
  pending_event_.description = "process exited";
  return true;
}

Result<bool> MockDebugAdapter::pause() {
  if (state_ != SessionState::Running) {
    return make_error<bool>(Status::InvalidInput, "debug.invalid_state",
                            "cannot pause when not running");
  }
  state_ = SessionState::Stopped;
  pending_event_.reason = StopReason::UserPause;
  pending_event_.thread_id = 1;
  pending_event_.address = current_pc_;
  pending_event_.description = "paused by user";
  return true;
}

Result<bool> MockDebugAdapter::step_into() {
  if (state_ != SessionState::Stopped) {
    return make_error<bool>(Status::InvalidInput, "debug.invalid_state",
                            "cannot step when not stopped");
  }
  current_pc_ += 4;
  registers_["rip"] = current_pc_;
  pending_event_.reason = StopReason::SingleStep;
  pending_event_.thread_id = 1;
  pending_event_.address = current_pc_;
  pending_event_.description = "stepped instruction";
  return true;
}

Result<bool> MockDebugAdapter::step_over() {
  return step_into();
}

Result<bool> MockDebugAdapter::step_out() {
  return step_into();
}

Result<Breakpoint> MockDebugAdapter::set_breakpoint(std::uint64_t address) {
  Breakpoint bp;
  bp.id = next_bp_id_++;
  bp.address = address;
  bp.enabled = true;
  bp.hit_count = 0;
  breakpoints_[address] = bp;
  return bp;
}

Result<bool> MockDebugAdapter::remove_breakpoint(std::uint64_t id_or_address) {
  for (auto it = breakpoints_.begin(); it != breakpoints_.end(); ++it) {
    if (it->second.id == id_or_address || it->first == id_or_address) {
      breakpoints_.erase(it);
      return true;
    }
  }
  return make_error<bool>(Status::InvalidInput, "debug.breakpoint_not_found",
                          "breakpoint does not exist");
}

Result<std::vector<std::byte>> MockDebugAdapter::read_memory(std::uint64_t address,
                                                             std::size_t size) {
  if (address < memory_base_ || (address - memory_base_ + size) > memory_.size()) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "debug.invalid_address",
                                              "memory read out of simulated bounds", address);
  }
  const std::size_t offset = static_cast<std::size_t>(address - memory_base_);
  std::vector<std::byte> result(memory_.begin() + offset, memory_.begin() + offset + size);
  return result;
}

Result<std::size_t> MockDebugAdapter::write_memory(std::uint64_t address,
                                                   std::span<const std::byte> data) {
  if (address < memory_base_ || (address - memory_base_ + data.size()) > memory_.size()) {
    return make_error<std::size_t>(Status::InvalidInput, "debug.invalid_address",
                                   "memory write out of simulated bounds", address);
  }
  const std::size_t offset = static_cast<std::size_t>(address - memory_base_);
  std::memcpy(memory_.data() + offset, data.data(), data.size());
  return data.size();
}

Result<std::vector<RegisterValue>> MockDebugAdapter::read_registers() {
  std::vector<RegisterValue> result;
  for (const auto& [name, val] : registers_) {
    result.push_back(RegisterValue{name, val, 8});
  }
  std::sort(result.begin(), result.end(),
            [](const auto& a, const auto& b) { return a.name < b.name; });
  return result;
}

Result<bool> MockDebugAdapter::write_register(const std::string& name, std::uint64_t value) {
  auto it = registers_.find(name);
  if (it == registers_.end()) {
    return make_error<bool>(Status::InvalidInput, "debug.unknown_register",
                            "register not recognized");
  }
  it->second = value;
  if (name == "rip") {
    current_pc_ = value;
  }
  return true;
}

Result<std::vector<StackFrame>> MockDebugAdapter::call_stack() {
  std::vector<StackFrame> frames;
  StackFrame f0;
  f0.index = 0;
  f0.instruction_pointer = current_pc_;
  f0.stack_pointer = registers_["rsp"];
  f0.frame_pointer = registers_["rbp"];
  f0.module_name = "test_target";
  f0.function_name = "target_func";
  f0.static_address = translator_.runtime_to_static(current_pc_);
  frames.push_back(f0);

  StackFrame f1;
  f1.index = 1;
  f1.instruction_pointer = entry_pc_;
  f1.stack_pointer = registers_["rsp"] + 0x20;
  f1.frame_pointer = registers_["rbp"] + 0x40;
  f1.module_name = "test_target";
  f1.function_name = "main";
  f1.static_address = translator_.runtime_to_static(entry_pc_);
  frames.push_back(f1);

  return frames;
}

Result<std::vector<DebugThread>> MockDebugAdapter::threads() {
  std::vector<DebugThread> list;
  DebugThread t;
  t.id = 1;
  t.name = "main_thread";
  t.is_current = true;
  t.stop_reason = pending_event_.reason;
  list.push_back(t);
  return list;
}

Result<std::vector<DebugModule>> MockDebugAdapter::modules() {
  std::vector<DebugModule> list;
  DebugModule m;
  m.name = "test_target";
  m.path = "/tmp/test_target";
  m.base_address = translator_.runtime_base;
  m.size = translator_.size;
  list.push_back(m);
  return list;
}

Result<StopInfo> MockDebugAdapter::poll_events() {
  return pending_event_;
}

}  // namespace donkey::debug
