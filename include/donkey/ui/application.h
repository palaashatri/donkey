#pragma once

#include <string>

namespace donkey::ui {

struct AppOptions {
  /// Optional binary opened on startup.
  std::string initial_path;
  /// Optional project database opened on startup. Takes precedence over
  /// `initial_path` because the project names its own image.
  std::string initial_project;
  /// Exit automatically after this many rendered frames (0 = run until closed).
  /// Used by the smoke test and screenshot tooling.
  int exit_after_frames = 0;
};

/// Run the desktop shell. Returns a process exit code. The headless core is
/// never a dependency of this function; the GUI is a client of it.
[[nodiscard]] int run(const AppOptions& options);

}  // namespace donkey::ui
