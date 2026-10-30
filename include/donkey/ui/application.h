#pragma once

#include <string>

namespace donkey::ui {

struct AppOptions {
  /// Optional binary opened on startup.
  std::string initial_path;
  /// Exit automatically after this many rendered frames (0 = run until closed).
  /// Used by the smoke test and screenshot tooling.
  int exit_after_frames = 0;
};

/// Run the desktop shell. Returns a process exit code. The headless core is
/// never a dependency of this function; the GUI is a client of it.
[[nodiscard]] int run(const AppOptions& options);

}  // namespace donkey::ui
