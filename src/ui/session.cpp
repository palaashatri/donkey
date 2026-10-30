#include "session.h"

#include <utility>

namespace donkey::ui {
namespace {

constexpr std::size_t kMaxInstructions = 200'000;
constexpr std::size_t kMaxStrings = 50'000;

}  // namespace

Session::~Session() {
  join_worker();
}

void Session::join_worker() {
  if (worker_.joinable()) {
    worker_.join();
  }
}

void Session::open(const std::string& path) {
  join_worker();
  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    path_ = path;
    status_ = "Loading " + path;
    error_.reset();
  }
  busy_.store(true);
  worker_ = std::thread([this, path, generation]() {
    auto loaded = load_binary(path);
    if (generation_.load() != generation) {
      return;
    }
    if (!loaded) {
      std::lock_guard<std::mutex> lock(mutex_);
      if (generation_.load() == generation) {
        error_ = loaded.diagnostic().message + " [" + loaded.diagnostic().code + "]";
        status_ = "Failed to load " + path;
        busy_.store(false);
      }
      return;
    }

    AnalysisOptions options;
    options.max_instructions = kMaxInstructions;
    options.max_strings = kMaxStrings;
    auto analysis = analyze(loaded.value().image, loaded.value().data, options);
    if (generation_.load() != generation) {
      return;
    }
    if (!analysis) {
      std::lock_guard<std::mutex> lock(mutex_);
      if (generation_.load() == generation) {
        error_ = analysis.diagnostic().message + " [" + analysis.diagnostic().code + "]";
        status_ = "Failed to analyse " + path;
        busy_.store(false);
      }
      return;
    }

    auto document = std::make_shared<Document>();
    document->loaded = std::move(loaded.value());
    document->analysis = std::move(analysis.value());

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() == generation) {
      document_ = std::move(document);
      status_ = "Loaded " + path;
      busy_.store(false);
    }
  });
}

std::optional<std::string> Session::take_error() {
  std::lock_guard<std::mutex> lock(mutex_);
  auto error = std::move(error_);
  error_.reset();
  return error;
}

std::shared_ptr<const Document> Session::document() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return document_;
}

std::string Session::path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return path_;
}

std::string Session::status() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return status_;
}

}  // namespace donkey::ui
