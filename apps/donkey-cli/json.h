#pragma once

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace donkey::cli {

inline std::string hex(std::uint64_t value) {
  char buffer[24];
  std::snprintf(buffer, sizeof(buffer), "0x%" PRIx64, value);
  return buffer;
}

inline std::string json_escape(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const char ch : input) {
    const auto byte = static_cast<unsigned char>(ch);
    switch (ch) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (byte < 0x20U) {
          char escaped[8];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", byte);
          out += escaped;
        } else {
          out.push_back(ch);
        }
    }
  }
  return out;
}

inline std::string quote(std::string_view input) {
  return "\"" + json_escape(input) + "\"";
}

}  // namespace donkey::cli
