#include "donkey/debug/debug.h"

#include "debug_internal.h"

namespace donkey::debug {

const char* session_state_name(SessionState state) noexcept {
  switch (state) {
    case SessionState::Disconnected:
      return "Disconnected";
    case SessionState::Launching:
      return "Launching";
    case SessionState::Attaching:
      return "Attaching";
    case SessionState::Running:
      return "Running";
    case SessionState::Stopped:
      return "Stopped";
    case SessionState::Terminating:
      return "Terminating";
    case SessionState::Detached:
      return "Detached";
    case SessionState::Exited:
      return "Exited";
    case SessionState::Error:
      return "Error";
  }
  return "Unknown";
}

const char* stop_reason_name(StopReason reason) noexcept {
  switch (reason) {
    case StopReason::None:
      return "None";
    case StopReason::Entrypoint:
      return "Entrypoint";
    case StopReason::Breakpoint:
      return "Breakpoint";
    case StopReason::SingleStep:
      return "SingleStep";
    case StopReason::Signal:
      return "Signal";
    case StopReason::Exception:
      return "Exception";
    case StopReason::UserPause:
      return "UserPause";
    case StopReason::Exited:
      return "Exited";
  }
  return "None";
}

std::unique_ptr<DebugAdapter> create_debug_adapter(bool mock, std::uint64_t simulated_aslr_base) {
  if (mock) {
    return std::make_unique<MockDebugAdapter>(simulated_aslr_base);
  }
  return std::make_unique<LocalDebugAdapter>();
}

}  // namespace donkey::debug
