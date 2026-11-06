// Concrete interpreter for lifted IR: the oracle the differential decompiler
// tests compare against real compiled code.

#include "donkey/ir/eval.h"

#include <algorithm>
#include <cstring>
#include <optional>
#include <unordered_map>

namespace donkey {
namespace {

std::uint64_t mask(std::uint8_t width) {
  return width >= 8 ? ~0ULL : ((1ULL << (width * 8U)) - 1U);
}

std::int64_t sign_extend(std::uint64_t value, std::uint8_t width);

/// NZCV in bits 3 to 0 (N, Z, C, V), as AArch64 sets them after a - b (add
/// false) or a + b (add true). C is the AArch64 carry: after a subtraction it is
/// set when there is no borrow.
std::uint8_t nzcv_of(bool add, std::uint64_t a, std::uint64_t b, std::uint8_t width) {
  const std::uint64_t m = mask(width);
  a &= m;
  b &= m;
  const std::uint64_t result = (add ? a + b : a - b) & m;
  const bool n = ((result >> (width * 8U - 1U)) & 1U) != 0;
  const bool z = result == 0;
  bool c = false;
  if (add) {
    c = width >= 8 ? (a + b) < a : ((a + b) >> (width * 8U)) != 0;
  } else {
    c = a >= b;
  }
  const std::int64_t sa = sign_extend(a, width);
  const std::int64_t sb = sign_extend(b, width);
  const bool result_negative = sign_extend(result, width) < 0;
  const bool v = add ? ((sa < 0) == (sb < 0)) && (result_negative != (sa < 0))
                     : ((sa < 0) != (sb < 0)) && (result_negative != (sa < 0));
  return static_cast<std::uint8_t>((n ? 8U : 0U) | (z ? 4U : 0U) | (c ? 2U : 0U) | (v ? 1U : 0U));
}

std::int64_t sign_extend(std::uint64_t value, std::uint8_t width) {
  if (width >= 8) {
    return static_cast<std::int64_t>(value);
  }
  const unsigned bits = width * 8U;
  const std::uint64_t sign = 1ULL << (bits - 1U);
  value &= mask(width);
  return static_cast<std::int64_t>((value ^ sign) - sign);
}

/// The bit operations on a `width`-byte value: trailing and leading zero counts
/// (both give the operand width for zero, as tzcnt and lzcnt do), population
/// count, and byte swap.
std::uint64_t bit_operation(IrOp op, std::uint64_t value, std::uint8_t width) {
  const unsigned bits = width * 8U;
  switch (op) {
    case IrOp::CountTrailingZeros: {
      unsigned count = 0;
      while (count < bits && ((value >> count) & 1U) == 0) {
        ++count;
      }
      return count;
    }
    case IrOp::CountLeadingZeros: {
      unsigned count = 0;
      while (count < bits && ((value >> (bits - 1U - count)) & 1U) == 0) {
        ++count;
      }
      return count;
    }
    case IrOp::PopCount: {
      std::uint64_t count = 0;
      for (unsigned bit = 0; bit < bits; ++bit) {
        count += (value >> bit) & 1U;
      }
      return count;
    }
    case IrOp::ByteSwap: {
      std::uint64_t swapped = 0;
      for (unsigned byte = 0; byte < width; ++byte) {
        swapped |= ((value >> (8U * byte)) & 0xffU) << (8U * (width - 1U - byte));
      }
      return swapped;
    }
    default:
      return 0;
  }
}

/// High 64 bits of the unsigned 128-bit product a * b.
std::uint64_t mul_high_unsigned(std::uint64_t a, std::uint64_t b) {
  const std::uint64_t a_lo = a & 0xffffffffULL;
  const std::uint64_t a_hi = a >> 32U;
  const std::uint64_t b_lo = b & 0xffffffffULL;
  const std::uint64_t b_hi = b >> 32U;
  const std::uint64_t low_low = a_lo * b_lo;
  const std::uint64_t low_high = a_lo * b_hi;
  const std::uint64_t high_low = a_hi * b_lo;
  const std::uint64_t high_high = a_hi * b_hi;
  const std::uint64_t middle =
      (low_low >> 32U) + (low_high & 0xffffffffULL) + (high_low & 0xffffffffULL);
  return high_high + (low_high >> 32U) + (high_low >> 32U) + (middle >> 32U);
}

/// High 64 bits of the signed 128-bit product a * b.
std::uint64_t mul_high_signed(std::uint64_t a, std::uint64_t b) {
  std::uint64_t high = mul_high_unsigned(a, b);
  if (static_cast<std::int64_t>(a) < 0) {
    high -= b;
  }
  if (static_cast<std::int64_t>(b) < 0) {
    high -= a;
  }
  return high;
}

/// The high part of the 2w-byte product of two w-byte operands.
std::uint64_t multiply_high(bool is_signed, std::uint64_t a, std::uint64_t b, std::uint8_t width) {
  if (width >= 8) {
    return is_signed ? mul_high_signed(a, b) : mul_high_unsigned(a, b);
  }
  // Operands of at most 4 bytes: the full product fits in 64 bits.
  const unsigned shift = width * 8U;
  if (is_signed) {
    const std::int64_t product = sign_extend(a, width) * sign_extend(b, width);
    return static_cast<std::uint64_t>(product >> shift);
  }
  return ((a & mask(width)) * (b & mask(width))) >> shift;
}

/// Restoring division of hi:lo by d. Requires d != 0 and hi < d, so that the
/// quotient fits in 64 bits.
void divide_unsigned_128(std::uint64_t hi, std::uint64_t lo, std::uint64_t d,
                         std::uint64_t& quotient, std::uint64_t& remainder) {
  std::uint64_t r = hi;
  std::uint64_t q = 0;
  for (int bit = 63; bit >= 0; --bit) {
    const bool shifted_out = (r >> 63U) != 0;  // 2r does not fit in 64 bits
    r = (r << 1U) | ((lo >> static_cast<unsigned>(bit)) & 1ULL);
    q <<= 1U;
    if (shifted_out || r >= d) {
      r -= d;  // wraps correctly when shifted_out: the true value is below d
      q |= 1ULL;
    }
  }
  quotient = q;
  remainder = r;
}

/// The x86 div (unsigned) or idiv (signed) at `width` bytes on the 128-bit
/// dividend hi:lo and the 64-bit divisor d, both already extended to 128 and
/// 64 bits by the caller. Returns false where x86 raises #DE: a zero divisor
/// or a quotient outside the range of `width` bytes.
bool divide_wide(bool is_signed, std::uint8_t width, std::uint64_t hi, std::uint64_t lo,
                 std::uint64_t d, std::uint64_t& quotient, std::uint64_t& remainder) {
  if (!is_signed) {
    if (d == 0 || hi >= d) {  // hi >= d: the quotient needs more than 64 bits
      return false;
    }
    divide_unsigned_128(hi, lo, d, quotient, remainder);
    return quotient <= mask(width);
  }
  const bool negative_dividend = (hi >> 63U) != 0;
  const bool negative_divisor = static_cast<std::int64_t>(d) < 0;
  std::uint64_t dividend_hi = hi;
  std::uint64_t dividend_lo = lo;
  if (negative_dividend) {  // two's complement negation of the 128-bit value
    dividend_lo = ~lo + 1U;
    dividend_hi = ~hi + (lo == 0 ? 1U : 0U);
  }
  const std::uint64_t magnitude = negative_divisor ? ~d + 1U : d;
  if (magnitude == 0 || dividend_hi >= magnitude) {
    return false;
  }
  std::uint64_t magnitude_quotient = 0;
  std::uint64_t magnitude_remainder = 0;
  divide_unsigned_128(dividend_hi, dividend_lo, magnitude, magnitude_quotient, magnitude_remainder);
  const bool negative_quotient = negative_dividend != negative_divisor;
  // Signed results range over [-2^(8w-1), 2^(8w-1) - 1]: the negative bound is reachable.
  const std::uint64_t limit = 1ULL << (width * 8U - 1U);
  if (negative_quotient ? magnitude_quotient > limit : magnitude_quotient >= limit) {
    return false;
  }
  quotient = negative_quotient ? ~magnitude_quotient + 1U : magnitude_quotient;
  remainder = negative_dividend ? ~magnitude_remainder + 1U : magnitude_remainder;
  return true;
}

/// Where a register name lives in the canonical register file.
struct Slot {
  std::string canonical;
  unsigned shift = 0;  ///< 8 for ah/bh/ch/dh
  bool zero = false;   ///< xzr / wzr
};

Slot x86_slot(const std::string& name) {
  static const std::unordered_map<std::string, Slot> kTable = [] {
    std::unordered_map<std::string, Slot> table;
    const char* legacy[][5] = {{"rax", "eax", "ax", "al", "ah"},
                               {"rbx", "ebx", "bx", "bl", "bh"},
                               {"rcx", "ecx", "cx", "cl", "ch"},
                               {"rdx", "edx", "dx", "dl", "dh"}};
    for (const auto& row : legacy) {
      for (int i = 0; i < 4; ++i) {
        table[row[i]] = Slot{row[0], 0, false};
      }
      table[row[4]] = Slot{row[0], 8, false};
    }
    const char* pointer[][4] = {{"rsi", "esi", "si", "sil"},
                                {"rdi", "edi", "di", "dil"},
                                {"rbp", "ebp", "bp", "bpl"},
                                {"rsp", "esp", "sp", "spl"}};
    for (const auto& row : pointer) {
      for (const char* alias : row) {
        table[alias] = Slot{row[0], 0, false};
      }
    }
    for (int n = 8; n <= 15; ++n) {
      const std::string base = "r" + std::to_string(n);
      for (const char* suffix : {"", "d", "w", "b"}) {
        table[base + suffix] = Slot{base, 0, false};
      }
    }
    return table;
  }();
  if (auto it = kTable.find(name); it != kTable.end()) {
    return it->second;
  }
  return Slot{name, 0, false};  // temporaries, flags
}

Slot aarch64_slot(const std::string& name) {
  if (name == "xzr" || name == "wzr") {
    return Slot{"xzr", 0, true};
  }
  if (name == "wsp") {
    return Slot{"sp", 0, false};
  }
  if (name == "fp") {
    return Slot{"x29", 0, false};
  }
  if (name == "lr") {
    return Slot{"x30", 0, false};
  }
  if (name.size() >= 2 && name[0] == 'w' &&
      std::all_of(name.begin() + 1, name.end(), [](char c) { return c >= '0' && c <= '9'; })) {
    return Slot{"x" + name.substr(1), 0, false};
  }
  return Slot{name, 0, false};
}

class Machine {
 public:
  Machine(const IrFunction& function, IrEvalMemory& memory, const IrEvalOptions& options)
      : f_(function), memory_(memory), options_(options) {
    aarch64_ = options.architecture == Architecture::AArch64;
  }

  std::optional<std::string> error_code;
  std::string error_message;

  Slot slot(const std::string& name) const {
    return aarch64_ ? aarch64_slot(name) : x86_slot(name);
  }

  std::uint64_t read_register(const std::string& name, std::uint8_t width) {
    const Slot s = slot(name);
    if (s.zero) {
      return 0;
    }
    const std::uint64_t full = registers_[s.canonical];
    return (full >> s.shift) & mask(width);
  }

  void write_register(const std::string& name, std::uint8_t width, std::uint64_t value) {
    const Slot s = slot(name);
    if (s.zero) {
      return;
    }
    std::uint64_t& full = registers_[s.canonical];
    const bool temporary = s.canonical.rfind("var_", 0) == 0;
    if (width >= 8 || temporary) {
      full = width >= 8 ? value : (value & mask(width));
    } else if (width == 4 && (aarch64_ || options_.architecture == Architecture::X86_64)) {
      full = value & 0xffffffffULL;  // 32-bit writes zero the upper half
    } else {
      const std::uint64_t field = mask(width) << s.shift;
      full = (full & ~field) | ((value << s.shift) & field);
    }
  }

  std::optional<std::uint64_t> address_of(const IrOperand& operand) {
    std::uint64_t address = operand.constant;
    if (!operand.reg.empty()) {
      address += read_register(operand.reg, 8);
    }
    if (!operand.index.empty()) {
      address += read_register(operand.index, 8) * static_cast<std::uint64_t>(operand.scale);
    }
    if (options_.architecture == Architecture::X86) {
      address &= 0xffffffffULL;
    }
    return address;
  }

  std::optional<std::uint64_t> value_of(const IrOperand& operand) {
    switch (operand.kind) {
      case IrOperandKind::Constant:
        return operand.constant & mask(operand.width == 0 ? 8 : operand.width);
      case IrOperandKind::Register:
        return read_register(operand.reg, operand.width == 0 ? 8 : operand.width);
      case IrOperandKind::Memory: {
        const auto address = address_of(operand);
        std::uint64_t value = 0;
        const std::uint8_t width = operand.width == 0 ? 8 : operand.width;
        if (!address || !memory_.read(*address, width, value)) {
          fail("ir.eval_memory", "read outside mapped memory");
          return std::nullopt;
        }
        return value;
      }
      default:
        fail("ir.eval_operand", "operand has no value");
        return std::nullopt;
    }
  }

  bool assign(const IrOperand& dest, std::uint8_t width, std::uint64_t value) {
    if (dest.kind == IrOperandKind::Register) {
      write_register(dest.reg, dest.width == 0 ? width : dest.width, value);
      return true;
    }
    if (dest.kind == IrOperandKind::Memory) {
      const auto address = address_of(dest);
      const std::uint8_t w = dest.width == 0 ? width : dest.width;
      if (!address || !memory_.write(*address, w, value & mask(w))) {
        fail("ir.eval_memory", "write outside writable memory");
        return false;
      }
      return true;
    }
    fail("ir.eval_operand", "assignment to a non-location");
    return false;
  }

  void fail(std::string code, std::string message) {
    if (!error_code) {
      error_code = std::move(code);
      error_message = std::move(message);
    }
  }

  /// Conditions over an explicit NZCV value (after a conditional compare). They
  /// follow AArch64: C is the carry, so lo is C clear and hs is C set.
  bool explicit_condition_holds(IrCondition condition) const {
    const bool n = (nzcv_ & 8U) != 0;
    const bool z = (nzcv_ & 4U) != 0;
    const bool c = (nzcv_ & 2U) != 0;
    const bool v = (nzcv_ & 1U) != 0;
    switch (condition) {
      case IrCondition::Equal:
      case IrCondition::Zero:
        return z;
      case IrCondition::NotEqual:
      case IrCondition::NonZero:
        return !z;
      case IrCondition::UnsignedLess:
        return !c;
      case IrCondition::UnsignedGreaterEqual:
        return c;
      case IrCondition::UnsignedGreater:
        return c && !z;
      case IrCondition::UnsignedLessEqual:
        return !c || z;
      case IrCondition::SignedLess:
        return n != v;
      case IrCondition::SignedGreaterEqual:
        return n == v;
      case IrCondition::SignedGreater:
        return !z && n == v;
      case IrCondition::SignedLessEqual:
        return z || n != v;
      case IrCondition::Negative:
        return n;
      case IrCondition::Positive:
        return !n;
      case IrCondition::Overflow:
        return v;
      case IrCondition::NoOverflow:
        return !v;
      case IrCondition::Carry:
        return c;
      case IrCondition::NoCarry:
        return !c;
      case IrCondition::None:
        return false;
    }
    return false;
  }

  bool condition_holds(IrCondition condition) const {
    if (explicit_flags_) {
      return explicit_condition_holds(condition);
    }
    const std::uint8_t w = flags_width_ == 0 ? 8 : flags_width_;
    const std::uint64_t a = flags_a_ & mask(w);
    const std::uint64_t b = flags_b_ & mask(w);
    if (flags_test_) {
      const std::uint64_t r = a & b;
      const std::int64_t sr = sign_extend(r, w);
      switch (condition) {
        case IrCondition::Equal:
        case IrCondition::Zero:
        case IrCondition::UnsignedLessEqual:
          return r == 0;
        case IrCondition::NotEqual:
        case IrCondition::NonZero:
        case IrCondition::UnsignedGreater:
          return r != 0;
        case IrCondition::Negative:
        case IrCondition::SignedLess:
          return sr < 0;
        case IrCondition::Positive:
        case IrCondition::SignedGreaterEqual:
          return sr >= 0;
        case IrCondition::SignedLessEqual:
          return sr <= 0;
        case IrCondition::SignedGreater:
          return sr > 0;
        case IrCondition::UnsignedLess:
        case IrCondition::Carry:
        case IrCondition::Overflow:
          return false;  // logical ops clear carry and overflow
        case IrCondition::UnsignedGreaterEqual:
        case IrCondition::NoCarry:
        case IrCondition::NoOverflow:
          return true;
        case IrCondition::None:
          return false;
      }
      return false;
    }
    const std::int64_t sa = sign_extend(a, w);
    const std::int64_t sb = sign_extend(b, w);
    const std::uint64_t diff = (a - b) & mask(w);
    const bool overflow = ((sa < 0) != (sb < 0)) && ((sign_extend(diff, w) < 0) != (sa < 0));
    const bool borrow = a < b;
    switch (condition) {
      case IrCondition::Equal:
      case IrCondition::Zero:
        return a == b;
      case IrCondition::NotEqual:
      case IrCondition::NonZero:
        return a != b;
      case IrCondition::UnsignedLess:
        return a < b;
      case IrCondition::UnsignedGreaterEqual:
        return a >= b;
      case IrCondition::UnsignedGreater:
        return a > b;
      case IrCondition::UnsignedLessEqual:
        return a <= b;
      case IrCondition::SignedLess:
        return sa < sb;
      case IrCondition::SignedGreaterEqual:
        return sa >= sb;
      case IrCondition::SignedGreater:
        return sa > sb;
      case IrCondition::SignedLessEqual:
        return sa <= sb;
      case IrCondition::Negative:
        return sign_extend(diff, w) < 0;
      case IrCondition::Positive:
        return sign_extend(diff, w) >= 0;
      case IrCondition::Overflow:
        return overflow;
      case IrCondition::NoOverflow:
        return !overflow;
      // x86 CF after a subtraction is the borrow; AArch64 C is its inverse.
      case IrCondition::Carry:
        return aarch64_ ? !borrow : borrow;
      case IrCondition::NoCarry:
        return aarch64_ ? borrow : !borrow;
      case IrCondition::None:
        return false;
    }
    return false;
  }

  std::optional<std::uint64_t> run() {
    std::size_t block = 0;
    std::size_t steps = 0;
    while (block < f_.blocks.size()) {
      const IrBlock& b = f_.blocks[block];
      std::optional<std::size_t> next_block = block + 1;  // fallthrough
      for (const IrStatement& s : b.statements) {
        if (++steps > options_.max_steps) {
          fail("ir.eval_step_limit", "step limit reached");
          return std::nullopt;
        }
        steps_ = steps;
        const std::uint8_t w = s.width == 0 ? 8 : s.width;
        auto binary = [&](auto op) -> bool {
          const auto x = value_of(s.a);
          const auto y = value_of(s.b);
          if (!x || !y) {
            return false;
          }
          return assign(s.dest, w, op(*x, *y) & mask(w));
        };
        const unsigned shift_mask = w >= 8 ? 63U : 31U;
        bool ok = true;
        bool jumped = false;
        switch (s.op) {
          case IrOp::Nop:
            break;
          case IrOp::Assign: {
            const auto v = value_of(s.a);
            ok = v.has_value() && assign(s.dest, w, *v);
            break;
          }
          case IrOp::Load: {
            const auto v = value_of(s.a);
            ok = v.has_value() && assign(s.dest, w, *v);
            break;
          }
          case IrOp::Store: {
            const auto v = value_of(s.b);
            ok = v.has_value() && assign(s.a, w, *v);
            break;
          }
          case IrOp::Lea: {
            const auto address = address_of(s.a);
            ok = address.has_value() && assign(s.dest, w, *address & mask(w));
            break;
          }
          case IrOp::Add:
            ok = binary([](std::uint64_t x, std::uint64_t y) { return x + y; });
            break;
          case IrOp::Sub:
            ok = binary([](std::uint64_t x, std::uint64_t y) { return x - y; });
            break;
          case IrOp::Mul:
            ok = binary([](std::uint64_t x, std::uint64_t y) { return x * y; });
            break;
          case IrOp::And:
            ok = binary([](std::uint64_t x, std::uint64_t y) { return x & y; });
            break;
          case IrOp::Or:
            ok = binary([](std::uint64_t x, std::uint64_t y) { return x | y; });
            break;
          case IrOp::Xor:
            ok = binary([](std::uint64_t x, std::uint64_t y) { return x ^ y; });
            break;
          case IrOp::Shl:
            ok = binary([&](std::uint64_t x, std::uint64_t y) { return x << (y & shift_mask); });
            break;
          case IrOp::Shr:
            ok = binary([&](std::uint64_t x, std::uint64_t y) {
              return (x & mask(w)) >> (y & shift_mask);
            });
            break;
          case IrOp::Sar:
            ok = binary([&](std::uint64_t x, std::uint64_t y) {
              return static_cast<std::uint64_t>(sign_extend(x, w) >>
                                                static_cast<int>(y & shift_mask));
            });
            break;
          case IrOp::ZeroExtend: {
            const auto v = value_of(s.a);
            ok = v.has_value() && assign(s.dest, w, *v & mask(s.a.width == 0 ? 8 : s.a.width));
            break;
          }
          case IrOp::SignExtend: {
            const auto v = value_of(s.a);
            ok =
                v.has_value() &&
                assign(s.dest, w,
                       static_cast<std::uint64_t>(sign_extend(*v, s.a.width == 0 ? 8 : s.a.width)) &
                           mask(w));
            break;
          }
          case IrOp::Compare:
          case IrOp::Test: {
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            ok = x.has_value() && y.has_value();
            if (ok) {
              flags_a_ = *x;
              flags_b_ = *y;
              flags_width_ = s.a.width != 0 ? s.a.width : w;
              flags_test_ = s.op == IrOp::Test;
              explicit_flags_ = false;
            }
            break;
          }
          case IrOp::CondCompare:
          case IrOp::CondCompareAdd: {
            // The condition is read from the flags before this statement.
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            ok = x.has_value() && y.has_value() && s.c.kind == IrOperandKind::Constant;
            if (ok) {
              const std::uint8_t width = s.width == 0 ? 8 : s.width;
              nzcv_ = condition_holds(s.condition)
                          ? nzcv_of(s.op == IrOp::CondCompareAdd, *x, *y, width)
                          : static_cast<std::uint8_t>(s.c.constant & 0xFU);
              explicit_flags_ = true;
            }
            break;
          }
          case IrOp::CondBranch:
            if (condition_holds(s.condition)) {
              next_block = s.b.block;
              jumped = true;
            }
            break;
          case IrOp::Branch:
            next_block = s.a.block;
            jumped = true;
            break;
          case IrOp::Switch: {
            const auto selector = value_of(s.dest);
            ok = selector.has_value();
            if (ok) {
              next_block = s.a.block;
              for (const IrSwitchCase& c : s.switch_cases) {
                if (c.value == *selector) {
                  next_block = c.target_block;
                }
              }
              jumped = true;
            }
            break;
          }
          case IrOp::Return:
            if (s.a.kind == IrOperandKind::None) {
              return 0;
            }
            return value_of(s.a);
          case IrOp::Call:
            fail("ir.eval_call", "calls are not interpreted");
            return std::nullopt;
          case IrOp::Unsupported:
            fail("ir.eval_unsupported", "unsupported statement: " + s.text);
            return std::nullopt;
          case IrOp::CondAssign:
            if (condition_holds(s.condition)) {
              const auto v = value_of(s.a);
              ok = v.has_value() && assign(s.dest, w, *v);
            }
            break;
          case IrOp::CountTrailingZeros:
          case IrOp::CountLeadingZeros:
          case IrOp::PopCount:
          case IrOp::ByteSwap: {
            const auto x = value_of(s.a);
            ok = x.has_value() && assign(s.dest, w, bit_operation(s.op, *x & mask(w), w) & mask(w));
            break;
          }
          case IrOp::AddCarry:
          case IrOp::SubBorrow: {
            // The carry (x86 CF, AArch64 C) and the borrow of a subtraction are
            // read through the same flag model that CondAssign uses. On AArch64
            // the subtraction borrow is the inverse of C.
            const bool add = s.op == IrOp::AddCarry;
            const bool in = add || !aarch64_ ? condition_holds(IrCondition::Carry)
                                             : condition_holds(IrCondition::NoCarry);
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            ok = x.has_value() && y.has_value();
            if (ok) {
              const std::uint64_t carry = in ? 1 : 0;
              const std::uint64_t result = add ? *x + *y + carry : *x - *y - carry;
              ok = assign(s.dest, w, result & mask(w));
            }
            break;
          }
          case IrOp::MulHighUnsigned:
          case IrOp::MulHighSigned: {
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            ok = x.has_value() && y.has_value() &&
                 assign(s.dest, w, multiply_high(s.op == IrOp::MulHighSigned, *x, *y, w) & mask(w));
            break;
          }
          case IrOp::DivUnsigned:
          case IrOp::DivSigned:
          case IrOp::RemUnsigned:
          case IrOp::RemSigned: {
            const auto high = value_of(s.a);
            const auto low = value_of(s.b);
            const auto divisor = value_of(s.c);
            ok = high.has_value() && low.has_value() && divisor.has_value();
            if (ok) {
              const bool is_signed = s.op == IrOp::DivSigned || s.op == IrOp::RemSigned;
              std::uint64_t hi = *high;
              std::uint64_t lo = *low;
              std::uint64_t d = *divisor;
              if (w < 8) {
                // The 2w-byte dividend and the w-byte divisor are extended into
                // the 128-bit and 64-bit operands that divide_wide takes.
                const std::uint64_t value = ((*high & mask(w)) << (w * 8U)) | (*low & mask(w));
                if (is_signed) {
                  const std::int64_t signed_value =
                      sign_extend(value, static_cast<std::uint8_t>(2 * w));
                  hi = signed_value < 0 ? ~0ULL : 0ULL;
                  lo = static_cast<std::uint64_t>(signed_value);
                  d = static_cast<std::uint64_t>(sign_extend(*divisor, w));
                } else {
                  hi = 0;
                  lo = value;
                  d = *divisor & mask(w);
                }
              }
              std::uint64_t quotient = 0;
              std::uint64_t remainder = 0;
              if (!divide_wide(is_signed, w, hi, lo, d, quotient, remainder)) {
                fail("ir.eval_fault", "divide by zero or quotient overflow");
                ok = false;
                break;
              }
              const bool wants_quotient = s.op == IrOp::DivUnsigned || s.op == IrOp::DivSigned;
              ok = assign(s.dest, w, (wants_quotient ? quotient : remainder) & mask(w));
            }
            break;
          }
        }
        if (!ok) {
          return std::nullopt;
        }
        if (jumped) {
          break;
        }
      }
      if (!next_block || *next_block >= f_.blocks.size()) {
        fail("ir.eval_fell_off", "control left the function without a return");
        return std::nullopt;
      }
      block = *next_block;
    }
    fail("ir.eval_fell_off", "control left the function without a return");
    return std::nullopt;
  }

  std::size_t steps_ = 0;
  std::unordered_map<std::string, std::uint64_t> registers_;

 private:
  const IrFunction& f_;
  IrEvalMemory& memory_;
  const IrEvalOptions& options_;
  bool aarch64_ = false;
  std::uint64_t flags_a_ = 0;
  std::uint64_t flags_b_ = 0;
  std::uint8_t flags_width_ = 0;
  bool flags_test_ = false;
  // Set by a conditional compare: the flags are then the NZCV value nzcv_, not
  // the operands of a compare.
  bool explicit_flags_ = false;
  std::uint8_t nzcv_ = 0;
};

}  // namespace

IrEvalMemory::IrEvalMemory(const BinaryImage& image, std::span<const std::byte> file) {
  for (const Section& section : image.sections) {
    if (section.virtual_size == 0 || section.virtual_size > 256ULL * 1024ULL * 1024ULL) {
      continue;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(section.virtual_size), 0);
    if (section.has_file_data && section.file_offset < file.size()) {
      const std::uint64_t available = std::min<std::uint64_t>(
          {section.file_size, section.virtual_size, file.size() - section.file_offset});
      std::memcpy(bytes.data(), file.data() + section.file_offset,
                  static_cast<std::size_t>(available));
    }
    // Images are read-only for the oracle: a store to .data is reported, so
    // tests of functions with global side effects say so instead of
    // silently diverging from the real process.
    add_region(section.address, std::move(bytes), false);
  }
}

bool IrEvalMemory::add_region(std::uint64_t base, std::vector<std::uint8_t> bytes, bool writable) {
  const std::uint64_t end = base + bytes.size();
  for (const Region& r : regions_) {
    if (base < r.base + r.bytes.size() && r.base < end) {
      return false;
    }
  }
  regions_.push_back(Region{base, std::move(bytes), writable});
  return true;
}

const IrEvalMemory::Region* IrEvalMemory::find(std::uint64_t address, std::size_t size) const {
  for (const Region& r : regions_) {
    if (address >= r.base && size <= r.bytes.size() && address - r.base <= r.bytes.size() - size) {
      return &r;
    }
  }
  return nullptr;
}

bool IrEvalMemory::read(std::uint64_t address, std::size_t size, std::uint64_t& value) const {
  const Region* r = find(address, size);
  if (r == nullptr || size > 8) {
    return false;
  }
  value = 0;
  for (std::size_t i = 0; i < size; ++i) {
    value |= static_cast<std::uint64_t>(r->bytes[static_cast<std::size_t>(address - r->base) + i])
             << (8U * i);
  }
  return true;
}

bool IrEvalMemory::write(std::uint64_t address, std::size_t size, std::uint64_t value) {
  Region* r = const_cast<Region*>(find(address, size));
  if (r == nullptr || !r->writable || size > 8) {
    return false;
  }
  for (std::size_t i = 0; i < size; ++i) {
    r->bytes[static_cast<std::size_t>(address - r->base) + i] =
        static_cast<std::uint8_t>(value >> (8U * i));
  }
  return true;
}

const std::vector<std::uint8_t>* IrEvalMemory::region(std::uint64_t base) const {
  for (const Region& r : regions_) {
    if (r.base == base) {
      return &r.bytes;
    }
  }
  return nullptr;
}

Result<IrEvalResult> evaluate_ir(const IrFunction& function,
                                 std::span<const std::uint64_t> arguments, IrEvalMemory& memory,
                                 const IrEvalOptions& options) {
  const std::uint64_t stack_base = options.stack_top - options.stack_size;
  if (!memory.add_region(stack_base, std::vector<std::uint8_t>(options.stack_size, 0xCC))) {
    return make_error<IrEvalResult>(Status::InvalidInput, "ir.eval_stack",
                                    "the stack region overlaps another region");
  }
  Machine machine(function, memory, options);
  // Leave room above the entry stack pointer for stack arguments.
  std::uint64_t sp = options.stack_top - 1024;
  const char* const sysv[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
  const char* const win64[] = {"rcx", "rdx", "r8", "r9"};
  std::size_t in_registers = 0;
  std::uint64_t stack_args = 0;  // address of the first stack argument
  const std::uint8_t pointer = options.architecture == Architecture::X86 ? 4 : 8;
  switch (options.convention) {
    case IrCallingConvention::SysV64:
      in_registers = std::min<std::size_t>(arguments.size(), 6);
      for (std::size_t i = 0; i < in_registers; ++i) {
        machine.write_register(sysv[i], 8, arguments[i]);
      }
      stack_args = sp + 8;  // above the return address
      break;
    case IrCallingConvention::Win64:
      in_registers = std::min<std::size_t>(arguments.size(), 4);
      for (std::size_t i = 0; i < in_registers; ++i) {
        machine.write_register(win64[i], 8, arguments[i]);
      }
      stack_args = sp + 8 + 32;  // return address + shadow space
      break;
    case IrCallingConvention::Aapcs64:
      in_registers = std::min<std::size_t>(arguments.size(), 8);
      for (std::size_t i = 0; i < in_registers; ++i) {
        machine.write_register("x" + std::to_string(i), 8, arguments[i]);
      }
      stack_args = sp;  // no return address on the stack
      break;
    case IrCallingConvention::Cdecl32:
      stack_args = sp + 4;
      break;
  }
  for (std::size_t i = in_registers; i < arguments.size(); ++i) {
    const std::uint64_t slot = stack_args + (i - in_registers) * (pointer == 4 ? 4 : 8);
    if (!memory.write(slot, pointer, arguments[i])) {
      return make_error<IrEvalResult>(Status::InternalError, "ir.eval_stack",
                                      "stack arguments do not fit");
    }
  }
  if (options.architecture == Architecture::AArch64) {
    machine.write_register("sp", 8, sp);
    machine.write_register("x30", 8, 0xdead0000ULL);
  } else {
    // The caller's return address.
    (void)memory.write(sp, pointer, 0xdead0000ULL);
    machine.write_register(options.architecture == Architecture::X86 ? "esp" : "rsp", pointer, sp);
  }
  const auto value = machine.run();
  if (!value) {
    return make_error<IrEvalResult>(
        Status::Unsupported, machine.error_code.value_or("ir.eval_failed"), machine.error_message);
  }
  return IrEvalResult{*value, machine.steps_};
}

}  // namespace donkey
