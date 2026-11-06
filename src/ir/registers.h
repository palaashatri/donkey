#pragma once

// Register families shared by the IR printer and structurer: "eax", "ax"
// and "al" all belong to "rax"; "w3" to "x3". Used to tell whether a
// register named in a comparison was overwritten before its condition is
// rendered. x86 and AArch64 names do not collide except the x86 16-bit
// "sp", which is treated as its own family.

#include <cstddef>
#include <cstdint>
#include <string>

namespace donkey::internal {

/// The width of an AArch64 scalar floating-point register: `s0`-`s31` are 4 bytes
/// and `d0`-`d31` 8 bytes, both views of `v0`-`v31`. Returns 0 for any other name.
inline std::uint8_t scalar_fp_width(const std::string& name) {
  if (name.size() < 2 || name.size() > 3 || (name[0] != 's' && name[0] != 'd')) {
    return 0;
  }
  unsigned index = 0;
  for (std::size_t i = 1; i < name.size(); ++i) {
    if (name[i] < '0' || name[i] > '9') {
      return 0;
    }
    index = index * 10 + static_cast<unsigned>(name[i] - '0');
  }
  if (index > 31) {
    return 0;
  }
  return name[0] == 's' ? 4 : 8;
}

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
  if (scalar_fp_width(name) != 0) {
    return "v" + name.substr(1);  // s3 and d3 are views of v3
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
