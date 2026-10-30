#pragma once

#include <cstdio>
#include <string_view>
#include <vector>

namespace donkey::cli {

void print_usage(std::FILE* out);

int command_info(const std::vector<std::string_view>& arguments);
int command_disasm(const std::vector<std::string_view>& arguments);
int command_strings(const std::vector<std::string_view>& arguments);
int command_functions(const std::vector<std::string_view>& arguments);
int command_cfg(const std::vector<std::string_view>& arguments);
int command_xrefs(const std::vector<std::string_view>& arguments);
int command_analyze(const std::vector<std::string_view>& arguments);

}  // namespace donkey::cli
