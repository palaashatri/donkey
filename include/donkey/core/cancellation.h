#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

namespace donkey {

/// A thread-safe cancellation token used to request and observe cancellation
/// across asynchronous or long-running worker tasks.
class CancellationToken {
 public:
  CancellationToken() : cancelled_(std::make_shared<std::atomic<bool>>(false)) {}
  explicit CancellationToken(std::shared_ptr<std::atomic<bool>> flag)
      : cancelled_(std::move(flag)) {}

  [[nodiscard]] bool is_cancelled() const noexcept {
    return cancelled_ && cancelled_->load(std::memory_order_relaxed);
  }

  void cancel() const noexcept {
    if (cancelled_) {
      cancelled_->store(true, std::memory_order_relaxed);
    }
  }

  void reset() const noexcept {
    if (cancelled_) {
      cancelled_->store(false, std::memory_order_relaxed);
    }
  }

  [[nodiscard]] static CancellationToken none() { return CancellationToken(); }

 private:
  std::shared_ptr<std::atomic<bool>> cancelled_;
};

/// Resource bounds and deadlines for long-running operations.
struct ResourceBudget {
  std::uint64_t max_instructions = 1'000'000;
  std::uint64_t max_strings = 100'000;
  std::uint64_t max_functions = 100'000;
  std::uint64_t max_blocks = 500'000;
  std::chrono::milliseconds timeout{0};  // 0 = no timeout
};

}  // namespace donkey
