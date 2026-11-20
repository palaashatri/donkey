#include "donkey/ir/libc_models.h"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace donkey {
namespace {

constexpr std::array<LibcArgument, 1> kP{LibcArgument::Pointer};
constexpr std::array<LibcArgument, 2> kPP{LibcArgument::Pointer, LibcArgument::Pointer};
constexpr std::array<LibcArgument, 2> kPS{LibcArgument::Pointer, LibcArgument::Size};
constexpr std::array<LibcArgument, 2> kPI{LibcArgument::Pointer, LibcArgument::Int};
constexpr std::array<LibcArgument, 3> kPIS{LibcArgument::Pointer, LibcArgument::Int,
                                           LibcArgument::Size};
constexpr std::array<LibcArgument, 3> kPPS{LibcArgument::Pointer, LibcArgument::Pointer,
                                           LibcArgument::Size};

// In name order (find_libc_model searches it in order).
constexpr std::array<LibcModel, 10> kModels{{
    {"memchr", kPIS},
    {"memcpy", kPPS},
    {"memmove", kPPS},
    {"memset", kPIS},
    {"strchr", kPI},
    {"strcspn", kPP},
    {"strlen", kP},
    {"strnlen", kPS},
    {"strrchr", kPI},
    {"strspn", kPP},
}};

/// Byte access for one model run: every access is one step, and the first failure is kept.
class Bytes {
 public:
  Bytes(IrEvalMemory& memory, std::size_t& steps, std::size_t max_steps)
      : memory_(memory), steps_(steps), max_steps_(max_steps) {}

  bool read(std::uint64_t address, std::uint8_t& value) {
    if (!step()) {
      return false;
    }
    std::uint64_t v = 0;
    if (!memory_.read(address, 1, v)) {
      return fail("ir.eval_memory", "the C function reads unmapped memory");
    }
    value = static_cast<std::uint8_t>(v);
    return true;
  }

  bool write(std::uint64_t address, std::uint8_t value) {
    if (!step()) {
      return false;
    }
    if (!memory_.write(address, 1, value)) {
      return fail("ir.eval_memory", "the C function writes unmapped or read-only memory");
    }
    return true;
  }

  bool fail(const char* code, std::string message) {
    if (code_ == nullptr) {
      code_ = code;
      message_ = std::move(message);
    }
    return false;
  }

  [[nodiscard]] Result<std::uint64_t> error() const {
    return make_error<std::uint64_t>(Status::Unsupported,
                                     code_ != nullptr ? code_ : "ir.eval_model", message_);
  }

 private:
  bool step() {
    if (steps_ >= max_steps_) {
      return fail("ir.eval_step_limit", "the step limit was reached inside a C function");
    }
    ++steps_;
    return true;
  }

  IrEvalMemory& memory_;
  std::size_t& steps_;
  std::size_t max_steps_;
  const char* code_ = nullptr;
  std::string message_;
};

/// Whether [a, a + n) and [b, b + n) share a byte (n > 0), counting a range that wraps around the
/// address space as reaching everything above its start.
bool overlap(std::uint64_t a, std::uint64_t b, std::uint64_t n) {
  if (n == 0) {
    return false;
  }
  const std::uint64_t lo = std::min(a, b);
  const std::uint64_t hi = std::max(a, b);
  return hi - lo < n;
}

/// The bytes of the NUL-terminated set at `set`, as a membership table.
bool read_set(Bytes& bytes, std::uint64_t set, std::array<bool, 256>& in) {
  in.fill(false);
  for (std::uint64_t i = 0;; ++i) {
    std::uint8_t c = 0;
    if (!bytes.read(set + i, c)) {
      return false;
    }
    if (c == 0) {
      return true;
    }
    in[c] = true;
  }
}

}  // namespace

const LibcModel* find_libc_model(std::string_view name) noexcept {
  for (const LibcModel& model : kModels) {
    if (model.name == name) {
      return &model;
    }
  }
  return nullptr;
}

std::span<const LibcModel> libc_models() noexcept {
  return kModels;
}

Result<std::uint64_t> run_libc_model(const LibcModel& model,
                                     std::span<const std::uint64_t> arguments, IrEvalMemory& memory,
                                     std::size_t& steps, std::size_t max_steps) {
  if (arguments.size() != model.arguments.size()) {
    return make_error<std::uint64_t>(
        Status::InvalidInput, "ir.eval_model",
        "the call passes another number of arguments than " + std::string(model.name) + " takes");
  }
  Bytes bytes(memory, steps, max_steps);
  const std::string_view name = model.name;
  const std::uint64_t a = arguments[0];
  const std::uint64_t b = arguments.size() > 1 ? arguments[1] : 0;
  const std::uint64_t n = arguments.size() > 2 ? arguments[2] : 0;
  std::uint8_t c = 0;

  if (name == "strlen" || name == "strnlen") {
    const bool bounded = name == "strnlen";
    std::uint64_t length = 0;
    while (!bounded || length < b) {
      if (!bytes.read(a + length, c)) {
        return bytes.error();
      }
      if (c == 0) {
        break;
      }
      ++length;
    }
    return length;
  }
  // The character memchr, strchr and strrchr search for. ISO C converts the int to (unsigned)
  // char, but C libraries differ outside ASCII: Microsoft's strrchr does not find a character whose
  // int has bits above the low byte, where glibc's does (both measured by
  // LibcModels.AgreeWithTheHostCLibrary). Such a call is refused, not guessed.
  const auto ascii = [&](std::uint64_t value) {
    if (value > 0x7f) {
      bytes.fail("ir.eval_model",
                 std::string(name) + " of a character outside ASCII: C libraries differ there");
      return false;
    }
    return true;
  };
  if (name == "memchr") {
    if (!ascii(b)) {
      return bytes.error();
    }
    const auto wanted = static_cast<std::uint8_t>(b);
    for (std::uint64_t i = 0; i < n; ++i) {
      if (!bytes.read(a + i, c)) {
        return bytes.error();
      }
      if (c == wanted) {
        return a + i;
      }
    }
    return std::uint64_t{0};
  }
  if (name == "strchr" || name == "strrchr") {
    if (!ascii(b)) {
      return bytes.error();
    }
    const auto wanted = static_cast<std::uint8_t>(b);
    const bool last = name == "strrchr";
    std::uint64_t found = 0;
    for (std::uint64_t i = 0;; ++i) {
      if (!bytes.read(a + i, c)) {
        return bytes.error();
      }
      if (c == wanted) {
        found = a + i;
        if (!last) {
          return found;
        }
      }
      if (c == 0) {
        return found;  // the terminator is part of the string: strchr(s, 0) finds it
      }
    }
  }
  if (name == "strspn" || name == "strcspn") {
    std::array<bool, 256> in{};
    if (!read_set(bytes, b, in)) {
      return bytes.error();
    }
    const bool accept = name == "strspn";
    for (std::uint64_t i = 0;; ++i) {
      if (!bytes.read(a + i, c)) {
        return bytes.error();
      }
      if (c == 0 || in[c] != accept) {
        return i;
      }
    }
  }
  if (name == "memcpy" || name == "memmove") {
    if (name == "memcpy" && overlap(a, b, n)) {
      bytes.fail("ir.eval_model", "memcpy of overlapping bytes is undefined");
      return bytes.error();
    }
    // Read every byte before writing any: for memmove the copy is as if through a buffer.
    std::vector<std::uint8_t> buffer;
    for (std::uint64_t i = 0; i < n; ++i) {
      if (!bytes.read(b + i, c)) {
        return bytes.error();
      }
      buffer.push_back(c);
    }
    for (std::uint64_t i = 0; i < n; ++i) {
      if (!bytes.write(a + i, buffer[i])) {
        return bytes.error();
      }
    }
    return a;
  }
  if (name == "memset") {
    for (std::uint64_t i = 0; i < n; ++i) {
      if (!bytes.write(a + i, static_cast<std::uint8_t>(b))) {
        return bytes.error();
      }
    }
    return a;
  }
  return make_error<std::uint64_t>(Status::InternalError, "ir.eval_model",
                                   "no model runs " + std::string(name));
}

}  // namespace donkey
