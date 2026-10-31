#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "donkey/core/cancellation.h"

namespace donkey {

/// Higher runs first. Within one priority, jobs run in submission order.
enum class JobPriority : std::uint8_t {
  Background = 0,  ///< prefetch, indexing: only when nothing else waits
  Normal = 1,
  Visible = 2,  ///< what the user is looking at right now
};

/// A bounded pool of worker threads with a priority queue. Every job gets a
/// cancellation token it is expected to poll; cancelling a queued job removes
/// it without running it. Jobs submitted with the same non-empty key
/// supersede each other: a newer submission cancels an older one that has
/// not started yet.
class JobScheduler {
 public:
  using Job = std::function<void(const CancellationToken&)>;

  struct Handle {
    std::uint64_t id = 0;
    CancellationToken token;
  };

  /// `workers` is clamped to at least 1.
  explicit JobScheduler(std::size_t workers);
  /// Cancels queued and running jobs and joins the workers.
  ~JobScheduler();

  JobScheduler(const JobScheduler&) = delete;
  JobScheduler& operator=(const JobScheduler&) = delete;

  Handle submit(JobPriority priority, Job job, std::string key = {});
  /// Cancel one job: removed if still queued, token cancelled if running.
  void cancel(std::uint64_t id);
  /// Cancel every queued and running job.
  void cancel_all();
  /// Block until no job is queued or running (tests and shutdown only).
  void wait_idle();

  [[nodiscard]] std::size_t worker_count() const noexcept { return workers_.size(); }
  [[nodiscard]] std::size_t queued() const;
  [[nodiscard]] std::size_t running() const;
  /// Most jobs ever running at the same time (never above worker_count()).
  [[nodiscard]] std::size_t peak_running() const;

 private:
  struct Entry {
    std::uint64_t id = 0;
    std::uint64_t sequence = 0;
    JobPriority priority = JobPriority::Normal;
    std::string key;
    CancellationToken token;
    Job job;
  };

  void run();

  mutable std::mutex mutex_;
  std::condition_variable wake_;
  std::condition_variable idle_;
  std::vector<Entry> queue_;
  std::vector<Entry> active_;  ///< running jobs (id, key, token; job moved out)
  std::uint64_t next_id_ = 1;
  std::uint64_t next_sequence_ = 0;
  std::size_t running_ = 0;
  std::size_t peak_running_ = 0;
  bool stopping_ = false;
  std::vector<std::thread> workers_;
};

}  // namespace donkey
