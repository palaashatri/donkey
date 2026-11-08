#include "donkey/analysis/search.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>

namespace donkey {
namespace {

constexpr std::size_t kCancelStride = 1U << 20U;  // bytes between cancellation checks
constexpr std::size_t kInstructionStride = 4096;  // instructions between cancellation checks
constexpr std::size_t kMaxPatternTokens = 256;

struct PatternByte {
  bool wildcard = false;
  std::uint8_t value = 0;
};

Result<std::vector<PatternByte>> parse_pattern(std::string_view text, std::size_t max_length) {
  std::vector<PatternByte> bytes;
  std::size_t i = 0;
  while (i < text.size()) {
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i])) != 0) {
      ++i;
    }
    if (i >= text.size()) {
      break;
    }
    const std::size_t start = i;
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i])) == 0) {
      ++i;
    }
    const std::string_view token = text.substr(start, i - start);
    if (token == "??") {
      bytes.push_back(PatternByte{true, 0});
    } else if (token.size() == 2 && std::isxdigit(static_cast<unsigned char>(token[0])) != 0 &&
               std::isxdigit(static_cast<unsigned char>(token[1])) != 0) {
      const std::string pair(token);
      bytes.push_back(PatternByte{false, static_cast<std::uint8_t>(std::stoul(pair, nullptr, 16))});
    } else {
      return make_error<std::vector<PatternByte>>(
          Status::InvalidInput, "search.pattern",
          "'" + std::string(token) + "' is not a byte (two hex digits, or ?? for any byte)");
    }
    if (bytes.size() > max_length) {
      return make_error<std::vector<PatternByte>>(Status::InvalidInput, "search.pattern",
                                                  "the pattern is longer than " +
                                                      std::to_string(max_length) + " bytes");
    }
  }
  if (bytes.empty()) {
    return make_error<std::vector<PatternByte>>(Status::InvalidInput, "search.pattern",
                                                "the pattern is empty");
  }
  const bool fixed = std::any_of(bytes.begin(), bytes.end(),
                                 [](const PatternByte& b) { return !b.wildcard; });
  if (!fixed) {
    return make_error<std::vector<PatternByte>>(Status::InvalidInput, "search.pattern",
                                                "a pattern needs at least one fixed byte");
  }
  return bytes;
}

bool matches_at(std::span<const std::byte> bytes, const std::vector<PatternByte>& pattern) {
  for (std::size_t k = 0; k < pattern.size(); ++k) {
    if (!pattern[k].wildcard &&
        std::to_integer<std::uint8_t>(bytes[k]) != pattern[k].value) {
      return false;
    }
  }
  return true;
}

}  // namespace

std::vector<std::uint64_t> operand_numbers(std::string_view operands) {
  std::vector<std::uint64_t> numbers;
  const auto is_word = [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
  };
  for (std::size_t i = 0; i < operands.size(); ++i) {
    if (std::isdigit(static_cast<unsigned char>(operands[i])) == 0 ||
        (i > 0 && is_word(operands[i - 1]))) {
      continue;
    }
    std::size_t end = i;
    while (end < operands.size() && is_word(operands[end])) {
      ++end;
    }
    const std::string token(operands.substr(i, end - i));
    i = end - 1;
    const bool hex = token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X');
    const std::string digits = hex ? token.substr(2) : token;
    const int base = hex ? 16 : 10;
    const bool valid = !digits.empty() &&
                       std::all_of(digits.begin(), digits.end(), [base](char c) {
                         return base == 16 ? std::isxdigit(static_cast<unsigned char>(c)) != 0
                                           : std::isdigit(static_cast<unsigned char>(c)) != 0;
                       });
    if (!valid) {
      continue;
    }
    std::size_t consumed = 0;
    try {
      const unsigned long long value = std::stoull(digits, &consumed, base);
      if (consumed == digits.size()) {
        numbers.push_back(static_cast<std::uint64_t>(value));
      }
    } catch (const std::out_of_range&) {
      // A number wider than 64 bits is not an immediate this search can match.
    }
  }
  return numbers;
}

Result<SearchHits> search_bytes(const BinaryImage& image, std::span<const std::byte> file,
                                std::string_view pattern, const SearchOptions& options,
                                const CancellationToken& token) {
  auto parsed = parse_pattern(pattern, options.max_pattern_length);
  if (!parsed) {
    return make_error<SearchHits>(parsed.diagnostic().status, parsed.diagnostic().code,
                                  parsed.diagnostic().message);
  }
  const std::vector<PatternByte>& bytes = parsed.value();
  SearchHits hits;
  for (const Section& section : image.sections) {
    if (token.is_cancelled()) {
      hits.cancelled = true;
      return hits;
    }
    if (!section.has_file_data || section.compressed || section.file_size == 0) {
      continue;
    }
    if (section.file_offset >= file.size()) {
      continue;
    }
    const std::size_t begin = static_cast<std::size_t>(section.file_offset);
    const std::size_t end =
        static_cast<std::size_t>(std::min<std::uint64_t>(section.file_offset + section.file_size,
                                                         file.size()));
    if (end - begin < bytes.size()) {
      continue;
    }
    std::size_t last_check = begin;
    for (std::size_t at = begin; at + bytes.size() <= end; ++at) {
      if (at - last_check >= kCancelStride) {
        last_check = at;
        if (token.is_cancelled()) {
          hits.cancelled = true;
          return hits;
        }
      }
      if (!matches_at(file.subspan(at, bytes.size()), bytes)) {
        continue;
      }
      if (hits.addresses.size() >= options.max_hits) {
        hits.truncated = true;
        return hits;
      }
      hits.addresses.push_back(section.address + (at - section.file_offset));
    }
  }
  return hits;
}

Result<SearchHits> search_immediate(std::span<const Instruction> instructions, std::uint64_t value,
                                    const SearchOptions& options, const CancellationToken& token) {
  SearchHits hits;
  for (std::size_t i = 0; i < instructions.size(); ++i) {
    if (i % kInstructionStride == 0 && token.is_cancelled()) {
      hits.cancelled = true;
      return hits;
    }
    const std::vector<std::uint64_t> numbers = operand_numbers(instructions[i].operands);
    if (std::find(numbers.begin(), numbers.end(), value) == numbers.end()) {
      continue;
    }
    if (hits.addresses.size() >= options.max_hits) {
      hits.truncated = true;
      return hits;
    }
    hits.addresses.push_back(instructions[i].address);
  }
  return hits;
}

Result<SearchHits> search_text(std::span<const Instruction> instructions, std::string_view pattern,
                               const SearchOptions& options, const CancellationToken& token) {
  if (pattern.empty()) {
    return make_error<SearchHits>(Status::InvalidInput, "search.regex", "the pattern is empty");
  }
  if (pattern.size() > options.max_pattern_length) {
    return make_error<SearchHits>(Status::InvalidInput, "search.regex",
                                  "the pattern is longer than " +
                                      std::to_string(options.max_pattern_length) + " characters");
  }
  std::regex regex;
  try {
    regex = std::regex(std::string(pattern), std::regex::ECMAScript | std::regex::optimize);
  } catch (const std::regex_error& error) {
    return make_error<SearchHits>(Status::InvalidInput, "search.regex",
                                  std::string("the pattern does not compile: ") + error.what());
  }
  SearchHits hits;
  std::string text;
  for (std::size_t i = 0; i < instructions.size(); ++i) {
    if (i % kInstructionStride == 0 && token.is_cancelled()) {
      hits.cancelled = true;
      return hits;
    }
    text = instructions[i].mnemonic;
    text += ' ';
    text += instructions[i].operands;
    if (!std::regex_search(text, regex)) {
      continue;
    }
    if (hits.addresses.size() >= options.max_hits) {
      hits.truncated = true;
      return hits;
    }
    hits.addresses.push_back(instructions[i].address);
  }
  return hits;
}

}  // namespace donkey
