#include "donkey/core/scheduler.h"

#include <algorithm>
#include <utility>

namespace donkey {

namespace {

/// True when `a` should run before `b`.
template <typename E>
bool runs_before(const E& a, const E& b) {
  if (a.priority != b.priority) {
    return a.priority > b.priority;
  }
  return a.sequence < b.sequence;
}

}  // namespace

JobScheduler::JobScheduler(std::size_t workers) {
  const std::size_t count = std::max<std::size_t>(workers, 1);
  workers_.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    workers_.emplace_back([this]() { run(); });
  }
}

JobScheduler::~JobScheduler() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
    for (Entry& entry : queue_) {
      entry.token.cancel();
    }
    queue_.clear();
    for (Entry& entry : active_) {
      entry.token.cancel();
    }
  }
  wake_.notify_all();
  for (std::thread& worker : workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
}

JobScheduler::Handle JobScheduler::submit(JobPriority priority, Job job, std::string key) {
  Handle handle;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!key.empty()) {
      // A newer request for the same key replaces one that has not started.
      for (auto it = queue_.begin(); it != queue_.end();) {
        if (it->key == key) {
          it->token.cancel();
          it = queue_.erase(it);
        } else {
          ++it;
        }
      }
    }
    Entry entry;
    entry.id = next_id_++;
    entry.sequence = next_sequence_++;
    entry.priority = priority;
    entry.key = std::move(key);
    entry.job = std::move(job);
    handle.id = entry.id;
    handle.token = entry.token;
    queue_.push_back(std::move(entry));
  }
  wake_.notify_one();
  return handle;
}

void JobScheduler::cancel(std::uint64_t id) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto it = queue_.begin(); it != queue_.end(); ++it) {
    if (it->id == id) {
      it->token.cancel();
      queue_.erase(it);
      idle_.notify_all();
      return;
    }
  }
  for (Entry& entry : active_) {
    if (entry.id == id) {
      entry.token.cancel();
      return;
    }
  }
}

void JobScheduler::cancel_all() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (Entry& entry : queue_) {
    entry.token.cancel();
  }
  queue_.clear();
  for (Entry& entry : active_) {
    entry.token.cancel();
  }
  idle_.notify_all();
}

void JobScheduler::wait_idle() {
  std::unique_lock<std::mutex> lock(mutex_);
  idle_.wait(lock, [this]() { return queue_.empty() && running_ == 0; });
}

std::size_t JobScheduler::queued() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return queue_.size();
}

std::size_t JobScheduler::running() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return running_;
}

std::size_t JobScheduler::peak_running() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return peak_running_;
}

void JobScheduler::run() {
  while (true) {
    Job job;
    CancellationToken token;
    std::uint64_t id = 0;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      wake_.wait(lock, [this]() { return stopping_ || !queue_.empty(); });
      if (stopping_) {
        return;
      }
      auto best =
          std::min_element(queue_.begin(), queue_.end(),
                           [](const Entry& a, const Entry& b) { return runs_before(a, b); });
      Entry entry = std::move(*best);
      queue_.erase(best);
      job = std::move(entry.job);
      token = entry.token;
      id = entry.id;
      Entry record;
      record.id = entry.id;
      record.key = std::move(entry.key);
      record.token = entry.token;
      active_.push_back(std::move(record));
      ++running_;
      peak_running_ = std::max(peak_running_, running_);
    }
    if (!token.is_cancelled()) {
      job(token);
    }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      --running_;
      active_.erase(std::remove_if(active_.begin(), active_.end(),
                                   [id](const Entry& entry) { return entry.id == id; }),
                    active_.end());
      if (queue_.empty() && running_ == 0) {
        idle_.notify_all();
      }
    }
  }
}

}  // namespace donkey
