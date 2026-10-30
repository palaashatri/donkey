#include <string_view>
#include <vector>

#include <cstdio>

#include "commands.h"
#include "donkey/core/version.h"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 2;

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string_view> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }

  if (arguments.empty()) {
    donkey::cli::print_usage(stderr);
    return kExitUsage;
  }

  const std::string_view command = arguments[0];
  const std::vector<std::string_view> rest(arguments.begin() + 1, arguments.end());

  if (command == "--version" || command == "-V") {
    std::printf("donkey-cli %s\n", std::string(donkey::version()).c_str());
    return kExitOk;
  }
  if (command == "--help" || command == "-h") {
    donkey::cli::print_usage(stdout);
    return kExitOk;
  }
  if (command == "info") {
    return donkey::cli::command_info(rest);
  }
  if (command == "disasm") {
    return donkey::cli::command_disasm(rest);
  }
  if (command == "strings") {
    return donkey::cli::command_strings(rest);
  }
  if (command == "functions") {
    return donkey::cli::command_functions(rest);
  }
  if (command == "cfg") {
    return donkey::cli::command_cfg(rest);
  }
  if (command == "decompile") {
    return donkey::cli::command_decompile(rest);
  }
  if (command == "xrefs") {
    return donkey::cli::command_xrefs(rest);
  }
  if (command == "analyze") {
    return donkey::cli::command_analyze(rest);
  }
  if (command == "project") {
    return donkey::cli::command_project(rest);
  }

  std::fprintf(stderr, "donkey-cli: unknown command '%.*s'\n", static_cast<int>(command.size()),
               command.data());
  donkey::cli::print_usage(stderr);
  return kExitUsage;
}
