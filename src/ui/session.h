#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"

namespace donkey::ui {

/// A fully parsed image plus its analysis. Immutable once published, so the
/// render thread can read it without holding the session lock.
struct Document {
  LoadedBinary loaded;
  AnalysisResult analysis;
};

/// Loads and analyses files on a worker thread. The render thread never reads
/// a file or runs analysis itself.
class Session {
 public:
  Session() = default;
  ~Session();

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  /// Start loading `path`. Any in-flight load keeps running and its result is
  /// discarded if a newer request has replaced it.
  void open(const std::string& path);

  [[nodiscard]] bool busy() const noexcept { return busy_.load(); }
  [[nodiscard]] std::optional<std::string> take_error();
  [[nodiscard]] std::shared_ptr<const Document> document() const;
  [[nodiscard]] std::string path() const;
  [[nodiscard]] std::string status() const;

 private:
  void join_worker();

  mutable std::mutex mutex_;
  std::shared_ptr<const Document> document_;
  std::optional<std::string> error_;
  std::string path_;
  std::string status_ = "No file open";
  std::atomic<bool> busy_{false};
  std::thread worker_;
  std::atomic<std::uint64_t> generation_{0};
};

}  // namespace donkey::ui
