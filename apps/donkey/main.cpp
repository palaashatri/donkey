#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "donkey/ui/application.h"

namespace {

void print_usage() {
  std::fprintf(stdout,
               "donkey - desktop binary workbench (early implementation)\n"
               "\n"
               "Usage:\n"
               "  donkey [<binary>] [--exit-after-frames N]\n"
               "\n"
               "Opening a file only reads it; nothing is executed.\n");
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
