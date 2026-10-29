#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

#include "donkey/core/version.h"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 2;

void print_usage(std::FILE* out) {
  std::fprintf(out,
               "donkey-cli %s - headless binary analysis\n"
               "\n"
               "Usage:\n"
               "  donkey-cli --version\n"
               "  donkey-cli --help\n"
               "\n"
               "Commands are added as their core APIs land; see docs/DESIGN.md section 9.2.\n",
               std::string(donkey::version()).c_str());
}

}  // namespace

int main(int argc, char** argv) {
  bool saw_version = false;
  bool saw_help = false;

  for (int i = 1; i < argc; ++i) {
    const std::string_view argument(argv[i]);
    if (argument == "--version" || argument == "-V") {
      saw_version = true;
    } else if (argument == "--help" || argument == "-h") {
      saw_help = true;
    } else {
      std::fprintf(stderr, "donkey-cli: unknown argument '%.*s'\n",
                   static_cast<int>(argument.size()), argument.data());
      print_usage(stderr);
      return kExitUsage;
    }
  }

  if (saw_version) {
    std::printf("donkey-cli %s\n", std::string(donkey::version()).c_str());
    return kExitOk;
  }
  if (saw_help) {
    print_usage(stdout);
    return kExitOk;
  }

  print_usage(stderr);
  return kExitUsage;
}
