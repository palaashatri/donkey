#include "donkey/debug/controller.h"

#include <algorithm>
#include <chrono>
#include <utility>

namespace donkey::debug {

namespace {

constexpr int kPollMs = 20;

bool is_live(SessionState state) {
  return state == SessionState::Stopped || state == SessionState::Running;
}

}  // namespace

DebugController::DebugController(bool mock)
    : mock_(mock), capabilities_(create_debug_adapter(mock)->capabilities()) {
  snapshot_.capabilities = capabilities_;
  worker_ = std::thread([this]() { run(); });
}

DebugController::~DebugController() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
  }
  wake_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
}

void DebugController::enqueue(Command command) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_back(std::move(command));
    snapshot_.busy = true;
  }
  wake_.notify_all();
}

DebugSnapshot DebugController::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot_;
}

bool DebugController::wait_until(const std::function<bool(const DebugSnapshot&)>& predicate,
                                 int timeout_ms) {
  std::unique_lock<std::mutex> lock(mutex_);
  return published_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                             [&]() { return predicate(snapshot_); });
}

void DebugController::run() {
  // The adapter is created, used and destroyed on this thread only.
  adapter_ = create_debug_adapter(mock_);
  publish();
  while (true) {
    Command command;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      const bool running = adapter_->state() == SessionState::Running;
      if (running) {
        wake_.wait_for(lock, std::chrono::milliseconds(kPollMs),
                       [this]() { return stopping_ || !queue_.empty(); });
      } else {
        wake_.wait(lock, [this]() { return stopping_ || !queue_.empty(); });
      }
      if (stopping_) {
        break;
      }
      if (!queue_.empty()) {
        command = std::move(queue_.front());
        queue_.pop_front();
      }
    }
    if (command) {
      command();
      publish(snapshot().message);
      continue;
    }
    // Nothing queued and the target is running: look for a stop or exit.
    auto event = adapter_->poll_events();
    if (event && event.value().reason != StopReason::None) {
      publish();
    }
  }
  // Tear the session down here, on the thread that owns the debuggee.
  adapter_.reset();
}

void DebugController::publish(const std::string& message) {
  DebugSnapshot next;
  // Poll first: polling can itself observe a stop and change the state, and
  // the snapshot must never pair a stop with a stale "running" state.
  if (auto stop = adapter_->poll_events()) {
    next.stop = stop.value();
  }
  next.state = adapter_->state();
  next.capabilities = capabilities_;
  next.translator = adapter_->address_translator();
  next.breakpoints = breakpoints_;
  next.message = message;
  if (next.state == SessionState::Stopped) {
    if (auto registers = adapter_->read_registers()) {
      next.registers = std::move(registers.value());
    }
    if (auto frames = adapter_->call_stack()) {
      next.frames = std::move(frames.value());
    }
    if (auto threads = adapter_->threads()) {
      next.threads = std::move(threads.value());
    }
    if (auto modules = adapter_->modules()) {
      next.modules = std::move(modules.value());
    }
    next.static_pc = !next.frames.empty() ? next.frames.front().static_address
                                          : next.translator.runtime_to_static(next.stop.address);
  }
  std::lock_guard<std::mutex> lock(mutex_);
  next.revision = snapshot_.revision + 1;
  next.memory_address = snapshot_.memory_address;
  next.memory = snapshot_.memory;
  next.busy = !queue_.empty();
  snapshot_ = std::move(next);
  published_.notify_all();
}

void DebugController::report(const Result<bool>& result, const char* action) {
  std::lock_guard<std::mutex> lock(mutex_);
  snapshot_.message = result ? std::string()
                             : std::string(action) + " failed: " + result.diagnostic().message +
                                   " [" + result.diagnostic().code + "]";
}

void DebugController::launch(LaunchConfig config) {
  enqueue([this, config = std::move(config)]() {
    auto launched = adapter_->launch(config);
    report(launched, "Launch");
    if (!launched) {
      return;
    }
    const AddressTranslator& translator = adapter_->address_translator();
    for (std::uint64_t address : breakpoints_) {
      auto bp = adapter_->set_breakpoint(translator.static_to_runtime(address));
      if (!bp) {
        report(
            make_error<bool>(bp.diagnostic().status, bp.diagnostic().code, bp.diagnostic().message),
            "Breakpoint");
      }
    }
  });
}

void DebugController::attach(std::uint32_t pid) {
  enqueue([this, pid]() { report(adapter_->attach(pid), "Attach"); });
}

void DebugController::resume() {
  enqueue([this]() { report(adapter_->resume(), "Continue"); });
}

void DebugController::pause() {
  enqueue([this]() { report(adapter_->pause(), "Pause"); });
}

void DebugController::step_into() {
  enqueue([this]() { report(adapter_->step_into(), "Step"); });
}

void DebugController::step_over() {
  enqueue([this]() { report(adapter_->step_over(), "Step over"); });
}

void DebugController::step_out() {
  enqueue([this]() { report(adapter_->step_out(), "Step out"); });
}

void DebugController::terminate() {
  enqueue([this]() { report(adapter_->terminate(), "Terminate"); });
}

void DebugController::detach() {
  enqueue([this]() { report(adapter_->detach(), "Detach"); });
}

void DebugController::toggle_breakpoint(std::uint64_t static_address) {
  enqueue([this, static_address]() {
    const bool live = is_live(adapter_->state());
    const std::uint64_t runtime =
        live ? adapter_->address_translator().static_to_runtime(static_address) : 0;
    const auto it = std::find(breakpoints_.begin(), breakpoints_.end(), static_address);
    if (it != breakpoints_.end()) {
      breakpoints_.erase(it);
      if (live) {
        report(adapter_->remove_breakpoint(runtime), "Remove breakpoint");
      }
      return;
    }
    breakpoints_.push_back(static_address);
    if (live) {
      auto bp = adapter_->set_breakpoint(runtime);
      report(bp ? Result<bool>(true)
                : make_error<bool>(bp.diagnostic().status, bp.diagnostic().code,
                                   bp.diagnostic().message),
             "Breakpoint");
    }
  });
}

void DebugController::read_memory(std::uint64_t runtime_address, std::size_t size) {
  enqueue([this, runtime_address, size]() {
    auto bytes = adapter_->read_memory(runtime_address, size);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      snapshot_.memory_address = runtime_address;
      snapshot_.memory = bytes ? std::move(bytes.value()) : std::vector<std::byte>();
    }
    report(bytes ? Result<bool>(true)
                 : make_error<bool>(bytes.diagnostic().status, bytes.diagnostic().code,
                                    bytes.diagnostic().message),
           "Read memory");
  });
}

}  // namespace donkey::debug
