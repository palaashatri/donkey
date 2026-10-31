// JobScheduler (M3): visible-function requests run before background work,
// the worker limit is never exceeded, superseded and cancelled jobs never
// start, and shutdown with queued work is clean.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "donkey/core/scheduler.h"

namespace {

using donkey::CancellationToken;
using donkey::JobPriority;
using donkey::JobScheduler;

/// Holds the single worker busy until opened, so tests can queue work
/// deterministically behind it.
class Gate {
 public:
  void wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    entered_ = true;
    entered_cv_.notify_all();
    open_cv_.wait(lock, [this]() { return open_; });
  }
  void wait_entered() {
    std::unique_lock<std::mutex> lock(mutex_);
    entered_cv_.wait(lock, [this]() { return entered_; });
  }
  void open() {
    std::lock_guard<std::mutex> lock(mutex_);
    open_ = true;
    open_cv_.notify_all();
  }

 private:
  std::mutex mutex_;
  std::condition_variable entered_cv_;
  std::condition_variable open_cv_;
  bool entered_ = false;
  bool open_ = false;
};

TEST(JobScheduler, VisibleWorkRunsBeforeQueuedBackgroundWork) {
  JobScheduler scheduler(1);
  Gate gate;
  std::mutex order_mutex;
  std::vector<std::string> order;
  auto record = [&](std::string name) {
    return [&, name](const CancellationToken&) {
      std::lock_guard<std::mutex> lock(order_mutex);
      order.push_back(name);
    };
  };
  scheduler.submit(JobPriority::Normal, [&](const CancellationToken&) { gate.wait(); });
  gate.wait_entered();
  scheduler.submit(JobPriority::Background, record("prefetch-1"));
  scheduler.submit(JobPriority::Background, record("prefetch-2"));
  scheduler.submit(JobPriority::Normal, record("normal"));
  scheduler.submit(JobPriority::Visible, record("visible"));
  gate.open();
  scheduler.wait_idle();
  EXPECT_EQ(order, (std::vector<std::string>{"visible", "normal", "prefetch-1", "prefetch-2"}));
}

TEST(JobScheduler, NeverRunsMoreJobsThanWorkers) {
  JobScheduler scheduler(3);
  std::atomic<int> concurrent{0};
  std::atomic<int> max_seen{0};
  std::atomic<int> done{0};
  for (int i = 0; i < 60; ++i) {
    scheduler.submit(JobPriority::Normal, [&](const CancellationToken&) {
      const int now = ++concurrent;
      int previous = max_seen.load();
      while (now > previous && !max_seen.compare_exchange_weak(previous, now)) {
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
      --concurrent;
      ++done;
    });
  }
  scheduler.wait_idle();
  EXPECT_EQ(done.load(), 60);
  EXPECT_LE(max_seen.load(), 3);
  EXPECT_GE(max_seen.load(), 2) << "jobs should actually run in parallel";
  EXPECT_LE(scheduler.peak_running(), 3U);
  EXPECT_EQ(scheduler.running(), 0U);
  EXPECT_EQ(scheduler.queued(), 0U);
}

TEST(JobScheduler, NewerRequestWithTheSameKeySupersedesAQueuedOne) {
  JobScheduler scheduler(1);
  Gate gate;
  scheduler.submit(JobPriority::Normal, [&](const CancellationToken&) { gate.wait(); });
  gate.wait_entered();
  std::atomic<bool> old_ran{false};
  std::atomic<bool> new_ran{false};
  auto old_handle = scheduler.submit(
      JobPriority::Visible, [&](const CancellationToken&) { old_ran = true; }, "decompile");
  scheduler.submit(
      JobPriority::Visible, [&](const CancellationToken&) { new_ran = true; }, "decompile");
  EXPECT_TRUE(old_handle.token.is_cancelled());
  gate.open();
  scheduler.wait_idle();
  EXPECT_FALSE(old_ran.load());
  EXPECT_TRUE(new_ran.load());
}

TEST(JobScheduler, CancelRemovesQueuedJobsAndSignalsRunningOnes) {
  JobScheduler scheduler(1);
  std::atomic<bool> started{false};
  std::atomic<bool> observed_cancel{false};
  auto running = scheduler.submit(JobPriority::Normal, [&](const CancellationToken& token) {
    started = true;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!token.is_cancelled() && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    observed_cancel = token.is_cancelled();
  });
  std::atomic<bool> queued_ran{false};
  auto queued =
      scheduler.submit(JobPriority::Normal, [&](const CancellationToken&) { queued_ran = true; });
  while (!started.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  scheduler.cancel(queued.id);
  scheduler.cancel(running.id);
  scheduler.wait_idle();
  EXPECT_TRUE(observed_cancel.load());
  EXPECT_FALSE(queued_ran.load());
  EXPECT_TRUE(queued.token.is_cancelled());
}

TEST(JobScheduler, DestructionCancelsQueuedWorkAndJoins) {
  constexpr int kJobs = 10;
  std::vector<std::atomic<bool>> ran(kJobs);
  std::vector<CancellationToken> tokens;
  {
    JobScheduler scheduler(1);
    Gate gate;
    scheduler.submit(JobPriority::Normal, [&](const CancellationToken&) { gate.wait(); });
    gate.wait_entered();
    for (int i = 0; i < kJobs; ++i) {
      tokens.push_back(scheduler
                           .submit(JobPriority::Background,
                                   [&ran, i](const CancellationToken&) { ran[i] = true; })
                           .token);
    }
    gate.open();
    // The destructor runs with background jobs possibly still queued.
  }
  // Every job either ran or was cancelled; none is left dangling.
  for (int i = 0; i < kJobs; ++i) {
    EXPECT_TRUE(ran[i].load() || tokens[i].is_cancelled()) << "job " << i;
  }
}

}  // namespace
