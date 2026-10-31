#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/version.h"
#include "donkey/ui/application.h"

namespace {

void print_usage() {
  std::fprintf(stdout,
               "donkey - desktop binary workbench (early implementation)\n"
               "\n"
               "Usage:\n"
               "  donkey [<binary>] [--project <database>] [--renderer auto|gpu|software]\n"
               "         [--exit-after-frames N] [--config-dir DIR] [--version]\n"
               "         [--ui-script FILE [--ui-report FILE]]\n"
               "\n"
               "Opening a file or project only reads it; nothing is executed.\n");
}

}  // namespace

int main(int argc, char** argv) {
  donkey::ui::AppOptions options;
  for (int i = 1; i < argc; ++i) {
    const std::string_view argument(argv[i]);
    if (argument == "--help" || argument == "-h") {
      print_usage();
      return 0;
    }
    if (argument == "--version") {
      std::fprintf(stdout, "donkey %s\n", std::string(donkey::version()).c_str());
      return 0;
    }
    // Finder on older macOS releases passes a process serial number.
    if (argument.rfind("-psn_", 0) == 0) {
      continue;
    }
    if (argument == "--renderer") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "donkey: --renderer needs auto, gpu or software\n");
        return 2;
      }
      options.renderer = std::string(argv[++i]);
      if (options.renderer != "auto" && options.renderer != "gpu" &&
          options.renderer != "software") {
        std::fprintf(stderr, "donkey: --renderer needs auto, gpu or software\n");
        return 2;
      }
      continue;
    }
    if (argument == "--project") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "donkey: --project needs a database path\n");
        return 2;
      }
      options.initial_project = std::string(argv[++i]);
      continue;
    }
    if (argument == "--config-dir" || argument == "--ui-script" || argument == "--ui-report") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "donkey: %s needs a path\n", argv[i]);
        return 2;
      }
      std::string& target = argument == "--config-dir"  ? options.config_dir
                            : argument == "--ui-script" ? options.ui_script
                                                        : options.ui_report;
      target = std::string(argv[++i]);
      continue;
    }
    if (argument == "--exit-after-frames") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "donkey: --exit-after-frames needs a value\n");
        return 2;
      }
      options.exit_after_frames = std::atoi(argv[++i]);
      if (options.exit_after_frames <= 0) {
        std::fprintf(stderr, "donkey: invalid frame count\n");
        return 2;
      }
      continue;
    }
    if (!argument.empty() && argument.front() == '-') {
      std::fprintf(stderr, "donkey: unknown option '%.*s'\n", static_cast<int>(argument.size()),
                   argument.data());
      return 2;
    }
    if (!options.initial_path.empty()) {
      std::fprintf(stderr, "donkey: only one file can be opened at startup\n");
      return 2;
    }
    options.initial_path = std::string(argument);
  }
  return donkey::ui::run(options);
}
