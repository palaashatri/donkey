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
  /// "auto" (SDL_GPU, else SDL_Renderer), "gpu" or "software".
  std::string renderer = "auto";
  /// Directory for the saved dock layout; empty uses SDL's per-user
  /// preference path.
  std::string config_dir;
  /// Run this UI test script inside the real event loop (docs/UI_TESTING.md).
  std::string ui_script;
  /// Where the script run writes its JSON timing report.
  std::string ui_report;
};

/// Run the desktop shell. Returns a process exit code. The headless core is
/// never a dependency of this function; the GUI is a client of it.
[[nodiscard]] int run(const AppOptions& options);

}  // namespace donkey::ui
