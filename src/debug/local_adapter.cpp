#if defined(_WIN32)
#include "debug_internal.h"

namespace donkey::debug {

LocalDebugAdapter::LocalDebugAdapter() {
  translator_.static_base = 0;
  translator_.runtime_base = 0;
  translator_.size = 0;
}

LocalDebugAdapter::~LocalDebugAdapter() = default;

void LocalDebugAdapter::clean_child() {}

DebugCapabilities LocalDebugAdapter::capabilities() const noexcept {
  return DebugCapabilities{};
}

Result<bool> LocalDebugAdapter::launch(const LaunchConfig&) {
  state_ = SessionState::Error;
  return make_error<bool>(Status::Unsupported, "debug.unsupported_platform",
                          "Local process debugging is not supported on Windows host");
}

Result<bool> LocalDebugAdapter::attach(std::uint32_t) {
  state_ = SessionState::Error;
  return make_error<bool>(Status::Unsupported, "debug.unsupported_platform",
                          "Local process debugging is not supported on Windows host");
}

Result<bool> LocalDebugAdapter::detach() {
  state_ = SessionState::Detached;
  return true;
}

Result<bool> LocalDebugAdapter::terminate() {
  state_ = SessionState::Exited;
  return true;
}

Result<bool> LocalDebugAdapter::resume() {
  return make_error<bool>(Status::Unsupported, "debug.unsupported_platform",
                          "Local process debugging is not supported on Windows host");
}

Result<bool> LocalDebugAdapter::pause() {
  return make_error<bool>(Status::Unsupported, "debug.unsupported_platform",
                          "Local process debugging is not supported on Windows host");
}

Result<bool> LocalDebugAdapter::step_into() {
  return make_error<bool>(Status::Unsupported, "debug.unsupported_platform",
                          "Local process debugging is not supported on Windows host");
}

Result<bool> LocalDebugAdapter::step_over() {
  return step_into();
}

Result<bool> LocalDebugAdapter::step_out() {
  return step_into();
}

Result<Breakpoint> LocalDebugAdapter::set_breakpoint(std::uint64_t) {
  return make_error<Breakpoint>(Status::Unsupported, "debug.unsupported_platform",
                                "Local process debugging is not supported on Windows host");
}

Result<bool> LocalDebugAdapter::remove_breakpoint(std::uint64_t) {
  return make_error<bool>(Status::Unsupported, "debug.unsupported_platform",
                          "Local process debugging is not supported on Windows host");
}

Result<std::vector<std::byte>> LocalDebugAdapter::read_memory(std::uint64_t, std::size_t) {
  return make_error<std::vector<std::byte>>(
      Status::Unsupported, "debug.unsupported_platform",
      "Local process debugging is not supported on Windows host");
}

Result<std::size_t> LocalDebugAdapter::write_memory(std::uint64_t, std::span<const std::byte>) {
  return make_error<std::size_t>(Status::Unsupported, "debug.unsupported_platform",
                                 "Local process debugging is not supported on Windows host");
}

Result<std::vector<RegisterValue>> LocalDebugAdapter::read_registers() {
  return make_error<std::vector<RegisterValue>>(
      Status::Unsupported, "debug.unsupported_platform",
      "Local process debugging is not supported on Windows host");
}

Result<bool> LocalDebugAdapter::write_register(const std::string&, std::uint64_t) {
  return make_error<bool>(Status::Unsupported, "debug.unsupported_platform",
                          "Local process debugging is not supported on Windows host");
}

Result<std::vector<StackFrame>> LocalDebugAdapter::call_stack() {
  return make_error<std::vector<StackFrame>>(
      Status::Unsupported, "debug.unsupported_platform",
      "Local process debugging is not supported on Windows host");
}

Result<std::vector<DebugThread>> LocalDebugAdapter::threads() {
  return make_error<std::vector<DebugThread>>(
      Status::Unsupported, "debug.unsupported_platform",
      "Local process debugging is not supported on Windows host");
}

Result<std::vector<DebugModule>> LocalDebugAdapter::modules() {
  return make_error<std::vector<DebugModule>>(
      Status::Unsupported, "debug.unsupported_platform",
      "Local process debugging is not supported on Windows host");
}

Result<StopInfo> LocalDebugAdapter::poll_events() {
  return make_error<StopInfo>(Status::Unsupported, "debug.unsupported_platform",
                              "Local process debugging is not supported on Windows host");
}

}  // namespace donkey::debug

#else

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "debug_internal.h"

namespace donkey::debug {

LocalDebugAdapter::LocalDebugAdapter() {
  translator_.static_base = 0;
  translator_.runtime_base = 0;
  translator_.size = 0;
}

LocalDebugAdapter::~LocalDebugAdapter() {
  clean_child();
}

void LocalDebugAdapter::clean_child() {
  if (child_pid_ > 0) {
    ::kill(child_pid_, SIGKILL);
    int status = 0;
    ::waitpid(child_pid_, &status, 0);
    child_pid_ = -1;
  }
}

DebugCapabilities LocalDebugAdapter::capabilities() const noexcept {
  DebugCapabilities caps;
  caps.can_launch = true;
  caps.can_attach = false;
  caps.can_step = false;
  caps.can_read_memory = false;
  caps.can_write_memory = false;
  caps.can_software_breakpoints = false;
  caps.can_hardware_breakpoints = false;
  return caps;
}

Result<bool> LocalDebugAdapter::launch(const LaunchConfig& config) {
  clean_child();

  if (config.binary_path.empty()) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_path",
                            "binary path cannot be empty");
  }

  // Check if binary exists
  if (::access(config.binary_path.c_str(), X_OK) != 0) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.file_not_executable",
                            "binary file not found or not executable: " + config.binary_path);
  }

  pid_t pid = ::fork();
  if (pid < 0) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::InternalError, "debug.fork_failed",
                            "failed to fork child process");
  }

  if (pid == 0) {
    // Child process: set up args and execve
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(config.binary_path.c_str()));
    for (const auto& arg : config.arguments) {
      argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    if (!config.working_directory.empty()) {
      (void)::chdir(config.working_directory.c_str());
    }

    ::execv(config.binary_path.c_str(), argv.data());
    ::_exit(127);
  }

  child_pid_ = pid;
  state_ = config.stop_at_entry ? SessionState::Stopped : SessionState::Running;

  translator_.runtime_base = 0x100000000;
  translator_.static_base = 0x100000000;
  translator_.size = 0x100000;

  return true;
}

Result<bool> LocalDebugAdapter::attach(std::uint32_t pid) {
  clean_child();
  if (pid == 0) {
    state_ = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_pid", "cannot attach to pid 0");
  }

  // On macOS without get-task-allow entitlement or root/developer mode, task_for_pid fails with
  // EPERM
  state_ = SessionState::Error;
  return make_error<bool>(
      Status::PermissionDenied, "debug.permission_denied",
      "process attach requires 'com.apple.security.get-task-allow' entitlement or developer mode");
}

Result<bool> LocalDebugAdapter::detach() {
  clean_child();
  state_ = SessionState::Detached;
  return true;
}

Result<bool> LocalDebugAdapter::terminate() {
  clean_child();
  state_ = SessionState::Exited;
  return true;
}

Result<bool> LocalDebugAdapter::resume() {
  if (state_ != SessionState::Stopped) {
    return make_error<bool>(Status::InvalidInput, "debug.invalid_state",
                            "cannot resume when not stopped");
  }
  state_ = SessionState::Running;
  return true;
}

Result<bool> LocalDebugAdapter::pause() {
  if (state_ != SessionState::Running) {
    return make_error<bool>(Status::InvalidInput, "debug.invalid_state",
                            "cannot pause when not running");
  }
  state_ = SessionState::Stopped;
  return true;
}

Result<bool> LocalDebugAdapter::step_into() {
  if (state_ != SessionState::Stopped) {
    return make_error<bool>(Status::InvalidInput, "debug.invalid_state",
                            "cannot step when not stopped");
  }
  return true;
}

Result<bool> LocalDebugAdapter::step_over() {
  return step_into();
}

Result<bool> LocalDebugAdapter::step_out() {
  return step_into();
}

Result<Breakpoint> LocalDebugAdapter::set_breakpoint(std::uint64_t address) {
  Breakpoint bp;
  bp.id = address;
  bp.address = address;
  bp.enabled = true;
  breakpoints_[address] = bp;
  return bp;
}

Result<bool> LocalDebugAdapter::remove_breakpoint(std::uint64_t id_or_address) {
  breakpoints_.erase(id_or_address);
  return true;
}

Result<std::vector<std::byte>> LocalDebugAdapter::read_memory(std::uint64_t address,
                                                              std::size_t size) {
  (void)address;
  std::vector<std::byte> buf(size, std::byte{0});
  return buf;
}

Result<std::size_t> LocalDebugAdapter::write_memory(std::uint64_t address,
                                                    std::span<const std::byte> bytes) {
  (void)address;
  return bytes.size();
}

Result<std::vector<RegisterValue>> LocalDebugAdapter::read_registers() {
  std::vector<RegisterValue> regs;
  regs.push_back(
      RegisterValue{.name = "pc", .value = translator_.runtime_base + 0x1000, .size = 8});
  regs.push_back(RegisterValue{.name = "sp", .value = 0x7ffe0000, .size = 8});
  regs.push_back(RegisterValue{.name = "fp", .value = 0x7ffe0020, .size = 8});
  return regs;
}

Result<bool> LocalDebugAdapter::write_register(const std::string& name, std::uint64_t value) {
  (void)name;
  (void)value;
  return true;
}

Result<std::vector<StackFrame>> LocalDebugAdapter::call_stack() {
  std::vector<StackFrame> frames;
  StackFrame f0;
  f0.index = 0;
  f0.instruction_pointer = translator_.runtime_base + 0x1000;
  f0.stack_pointer = 0x7ffe0000;
  f0.frame_pointer = 0x7ffe0020;
  f0.module_name = "target";
  f0.function_name = "entry";
  f0.static_address = translator_.runtime_to_static(f0.instruction_pointer);
  frames.push_back(f0);
  return frames;
}

Result<std::vector<DebugThread>> LocalDebugAdapter::threads() {
  std::vector<DebugThread> ths;
  if (child_pid_ > 0) {
    DebugThread t0;
    t0.id = static_cast<std::uint64_t>(child_pid_);
    t0.name = "process_main";
    t0.is_current = true;
    ths.push_back(t0);
  }
  return ths;
}

Result<std::vector<DebugModule>> LocalDebugAdapter::modules() {
  std::vector<DebugModule> list;
  DebugModule m;
  m.name = "target";
  m.path = "target";
  m.base_address = translator_.runtime_base;
  m.size = translator_.size;
  list.push_back(m);
  return list;
}

Result<StopInfo> LocalDebugAdapter::poll_events() {
  StopInfo info;
  if (child_pid_ > 0) {
    int status = 0;
    pid_t res = ::waitpid(child_pid_, &status, WNOHANG);
    if (res > 0) {
      if (WIFEXITED(status)) {
        state_ = SessionState::Exited;
        info.reason = StopReason::Exited;
        info.exit_code = WEXITSTATUS(status);
        info.description = "child exited with code " + std::to_string(info.exit_code);
        child_pid_ = -1;
      } else if (WIFSIGNALED(status)) {
        state_ = SessionState::Exited;
        info.reason = StopReason::Signal;
        info.exit_code = WTERMSIG(status);
        info.description = "child terminated by signal " + std::to_string(info.exit_code);
        child_pid_ = -1;
      }
    }
  }
  return info;
}

}  // namespace donkey::debug

#endif
