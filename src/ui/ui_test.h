#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <SDL3/SDL.h>

namespace donkey::ui {

class Session;
class Workspace;

/// What a UI test script can reach in the running application.
struct UiTestHost {
  SDL_Window* window = nullptr;
  Session* session = nullptr;
  Workspace* workspace = nullptr;
  /// Display scale to report instead of SDL's (a test cannot change the real
  /// monitor's scale); applied when the app handles the scale-change event.
  std::function<void(float)> set_scale_override;
  /// Number of times the renderer was torn down and recreated.
  int graphics_resets = 0;
  std::string renderer_name;
};

/// Runs a line-based script inside the real application loop (`donkey
/// --ui-script FILE`). Input is injected as SDL events through SDL_PushEvent,
/// so it takes the same path as a person's keyboard; assertions read the
/// workspace, session and Dear ImGui state. It records frame CPU time and
/// input-to-frame latency and writes p50/p95/p99 to a JSON report.
///
/// The command reference is in docs/UI_TESTING.md.
class UiScriptRunner {
 public:
  UiScriptRunner() = default;
  ~UiScriptRunner();

  UiScriptRunner(const UiScriptRunner&) = delete;
  UiScriptRunner& operator=(const UiScriptRunner&) = delete;

  /// Parse `path`. On failure returns false and sets `error`.
  bool load(const std::string& path, std::string& error);

  /// Run commands until one needs frames to pass. Call before polling events.
  void before_frame(UiTestHost& host);
  /// Record the frame that just finished: `cpu_ms` is NewFrame..draw
  /// submission and `submitted` the moment the draw was submitted.
  void after_frame(UiTestHost& host, double cpu_ms,
                   std::chrono::steady_clock::time_point submitted);

  [[nodiscard]] bool done() const noexcept { return done_; }
  [[nodiscard]] int exit_code() const noexcept { return failures_.empty() ? 0 : 1; }
  /// Write the JSON report. Returns false when the file cannot be written.
  bool write_report(const std::string& path, const UiTestHost& host) const;

 private:
  struct Command {
    int line = 0;
    std::string name;
    std::vector<std::string> args;
    std::string rest;  ///< everything after the command name, verbatim
  };

  void fail(const Command& command, const std::string& message);
  bool execute(const Command& command, UiTestHost& host);  ///< false: yield
  void push_key(const std::string& spec, UiTestHost& host, const Command& command);
  void push_text(const std::string& text, UiTestHost& host, bool composing);
  void push_window_event(SDL_EventType type, UiTestHost& host);
  void note_input();
  void stop_background_load();

  std::vector<Command> commands_;
  std::size_t next_ = 0;
  int wait_frames_ = 0;
  bool waiting_idle_ = false;
  std::chrono::steady_clock::time_point wait_deadline_{};
  const Command* waiting_command_ = nullptr;
  bool done_ = false;
  std::vector<std::string> failures_;
  std::vector<std::string> log_;
  std::uint64_t frames_ = 0;
  std::chrono::steady_clock::time_point last_frame_end_{};

  // Strings referenced by pushed SDL text events must outlive the event.
  std::deque<std::string> event_text_;

  // Measurements: label -> samples in milliseconds.
  std::map<std::string, std::vector<double>> samples_;
  std::string measuring_label_;
  int measuring_frames_ = 0;
  int sweep_frames_ = 0;
  int sweep_index_ = 0;
  int sweep_max_rows_ = 0;
  std::vector<std::chrono::steady_clock::time_point> pending_inputs_;
  std::size_t storage_baseline_ = 0;

  std::vector<std::thread> load_threads_;
  std::shared_ptr<std::atomic<bool>> load_stop_;
  std::shared_ptr<std::atomic<std::uint64_t>> load_runs_;
};

}  // namespace donkey::ui
