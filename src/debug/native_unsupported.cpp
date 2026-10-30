// Native debugging is not implemented on this host (for example macOS, which
// needs Mach task ports and a signed debugger entitlement, or FreeBSD). Every
// operation fails with `debug.unsupported_platform`; nothing is simulated.

#if !(defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))) && \
    !(defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__)))

#include "debug_internal.h"

namespace donkey::debug {

namespace {

constexpr const char* kMessage =
    "native process debugging is not implemented on this host; it is available on Linux "
    "(x86-64, AArch64) and Windows (x64)";

template <typename T>
Result<T> unsupported() {
  return make_error<T>(Status::Unsupported, "debug.unsupported_platform", kMessage);
}

}  // namespace

struct LocalDebugAdapter::Impl {
  SessionState state = SessionState::Disconnected;
  AddressTranslator translator;
};

LocalDebugAdapter::LocalDebugAdapter() : impl_(std::make_unique<Impl>()) {}
LocalDebugAdapter::~LocalDebugAdapter() = default;

SessionState LocalDebugAdapter::state() const noexcept {
  return impl_->state;
}
const AddressTranslator& LocalDebugAdapter::address_translator() const noexcept {
  return impl_->translator;
}

DebugCapabilities LocalDebugAdapter::capabilities() const noexcept {
  DebugCapabilities caps;
  caps.can_launch = false;
  caps.can_attach = false;
  caps.can_step = false;
  caps.can_read_memory = false;
  caps.can_write_memory = false;
  caps.can_software_breakpoints = false;
  caps.can_hardware_breakpoints = false;
  return caps;
}

Result<bool> LocalDebugAdapter::launch(const LaunchConfig&) {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::attach(std::uint32_t) {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::detach() {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::terminate() {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::resume() {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::pause() {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::step_into() {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::step_over() {
  return unsupported<bool>();
}
Result<bool> LocalDebugAdapter::step_out() {
  return unsupported<bool>();
}
Result<Breakpoint> LocalDebugAdapter::set_breakpoint(std::uint64_t) {
  return unsupported<Breakpoint>();
}
Result<bool> LocalDebugAdapter::remove_breakpoint(std::uint64_t) {
  return unsupported<bool>();
}
Result<std::vector<std::byte>> LocalDebugAdapter::read_memory(std::uint64_t, std::size_t) {
  return unsupported<std::vector<std::byte>>();
}
Result<std::size_t> LocalDebugAdapter::write_memory(std::uint64_t, std::span<const std::byte>) {
  return unsupported<std::size_t>();
}
Result<std::vector<RegisterValue>> LocalDebugAdapter::read_registers() {
  return unsupported<std::vector<RegisterValue>>();
}
Result<bool> LocalDebugAdapter::write_register(const std::string&, std::uint64_t) {
  return unsupported<bool>();
}
Result<std::vector<StackFrame>> LocalDebugAdapter::call_stack() {
  return unsupported<std::vector<StackFrame>>();
}
Result<std::vector<DebugThread>> LocalDebugAdapter::threads() {
  return unsupported<std::vector<DebugThread>>();
}
Result<std::vector<DebugModule>> LocalDebugAdapter::modules() {
  return unsupported<std::vector<DebugModule>>();
}
Result<StopInfo> LocalDebugAdapter::poll_events() {
  return unsupported<StopInfo>();
}
Result<StopInfo> LocalDebugAdapter::wait_for_event(int) {
  return unsupported<StopInfo>();
}

}  // namespace donkey::debug

#endif
