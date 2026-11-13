#pragma once

// Search over a loaded image (G17): byte patterns, immediate values and regular expressions over
// the disassembly. Each search is bounded by a hit limit and can be cancelled, so the desktop app
// can run it off the render thread. Nothing is executed and nothing is written.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/core/result.h"
#include "donkey/decode/decode.h"

namespace donkey {

struct SearchOptions {
  /// The most hits returned. A search that reaches the limit stops and reports `truncated`.
  std::size_t max_hits = 10000;
  /// A regular expression longer than this is refused, which bounds the cost of matching.
  std::size_t max_pattern_length = 256;
};

struct SearchHits {
  std::vector<std::uint64_t>
      addresses;           ///< in address order for bytes; in instruction order otherwise
  bool truncated = false;  ///< the hit limit was reached
  bool cancelled = false;  ///< the token was cancelled before the search finished
};

/// Byte pattern search over the file bytes of every section that has file data, reported at the
/// virtual address of each match. The pattern is hex byte pairs separated by spaces, and "??"
/// matches any byte: "48 8b ?? 24". A pattern must have at least one fixed byte, and at most
/// `max_pattern_length` bytes. Bad patterns are refused with `search.pattern`.
[[nodiscard]] Result<SearchHits> search_bytes(const BinaryImage& image,
                                              std::span<const std::byte> file,
                                              std::string_view pattern,
                                              const SearchOptions& options = {},
                                              const CancellationToken& token = {});

/// Immediate search: an instruction whose operand text contains a number equal to `value`. The
/// operand text does not say which numbers are immediates, so a displacement or an address written
/// in the operands can match as well, and a negative displacement matches its magnitude. Numbers
/// are read in decimal, or in hexadecimal with a 0x prefix.
[[nodiscard]] Result<SearchHits> search_immediate(std::span<const Instruction> instructions,
                                                  std::uint64_t value,
                                                  const SearchOptions& options = {},
                                                  const CancellationToken& token = {});

/// Regular expression search (ECMAScript) over each instruction's text, "mnemonic operands", such
/// as
/// "^call" or "rsp, 0x8$". A pattern longer than `max_pattern_length`, or one that does not
/// compile, is refused with `search.regex`.
[[nodiscard]] Result<SearchHits> search_text(std::span<const Instruction> instructions,
                                             std::string_view pattern,
                                             const SearchOptions& options = {},
                                             const CancellationToken& token = {});

/// The numbers in an operand text, as the immediate search reads them: a digit that does not follow
/// a letter, digit or underscore starts a number, in decimal or with a 0x prefix. Exposed for
/// tests.
[[nodiscard]] std::vector<std::uint64_t> operand_numbers(std::string_view operands);

}  // namespace donkey
