#pragma once

// Register families shared by the IR printer and structurer: "eax", "ax"
// and "al" all belong to "rax"; "w3" to "x3". Used to tell whether a
// register named in a comparison was overwritten before its condition is
// rendered. x86 and AArch64 names do not collide except the x86 16-bit
// "sp", which is treated as its own family.

#include <string>

namespace donkey::internal {

inline std::string register_family(const std::string& name) {
  static const char* const kX86[][5] = {
      {"rax", "eax", "ax", "al", "ah"}, {"rbx", "ebx", "bx", "bl", "bh"},
      {"rcx", "ecx", "cx", "cl", "ch"}, {"rdx", "edx", "dx", "dl", "dh"},
      {"rsi", "esi", "si", "sil", ""},  {"rdi", "edi", "di", "dil", ""},
      {"rbp", "ebp", "bp", "bpl", ""},  {"rsp", "esp", "spl", "", ""},
  };
  for (const auto& row : kX86) {
    for (const char* alias : row) {
      if (alias[0] != '\0' && name == alias) {
        return row[0];
      }
    }
  }
  if (name.size() >= 2 && name[0] == 'r' && name[1] >= '0' && name[1] <= '9') {
    std::size_t digits = 1;
    while (digits < name.size() && name[digits] >= '0' && name[digits] <= '9') {
      ++digits;
    }
    return name.substr(0, digits);  // r8d, r8w, r8b -> r8
  }
  if (name.size() >= 2 && name[0] == 'w' && name[1] >= '0' && name[1] <= '9') {
    return "x" + name.substr(1);
  }
  if (name == "wzr") {
    return "xzr";
  }
  if (name == "wsp") {
    return "sp";
  }
  return name;
}

}  // namespace donkey::internal
