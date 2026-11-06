// Concrete interpreter for lifted IR: the oracle the differential decompiler
// tests compare against real compiled code.

#include "donkey/ir/eval.h"

#include "registers.h"

#include <algorithm>
#include <bit>
#include <cmath>
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

/// An addition with a carry in, as adcs computes it: the result and the NZCV that
/// the flags take. C is the carry out and V the signed overflow of a + b + carry.
struct AddWithCarry {
  std::uint64_t result = 0;
  std::uint8_t nzcv = 0;
};

AddWithCarry add_with_carry(std::uint64_t a, std::uint64_t b, bool carry_in, std::uint8_t width) {
  const std::uint64_t m = mask(width);
  a &= m;
  b &= m;
  const std::uint64_t in = carry_in ? 1U : 0U;
  std::uint64_t sum = 0;
  bool carry = false;
  if (width >= 8) {
    const std::uint64_t partial = a + b;
    const bool carry_from_pair = partial < a;
    sum = partial + in;
    // The two carries cannot both occur: a carry in needs partial == all ones.
    carry = carry_from_pair || sum < partial;
  } else {
    const std::uint64_t wide = a + b + in;
    sum = wide & m;
    carry = (wide >> (width * 8U)) != 0;
  }
  const std::uint64_t result = sum & m;
  const bool n = ((result >> (width * 8U - 1U)) & 1U) != 0;
  const bool z = result == 0;
  const bool a_negative = sign_extend(a, width) < 0;
  const bool b_negative = sign_extend(b, width) < 0;
  const bool result_negative = sign_extend(result, width) < 0;
  const bool v = (a_negative == b_negative) && (result_negative != a_negative);
  AddWithCarry out;
  out.result = result;
  out.nzcv =
      static_cast<std::uint8_t>((n ? 8U : 0U) | (z ? 4U : 0U) | (carry ? 2U : 0U) | (v ? 1U : 0U));
  return out;
}

// ---- floating point --------------------------------------------------------
// The bits of a float (width 4) or a double (width 8). Host arithmetic runs only
// on operands that are not NaN, in the operand's own precision, with the default
// round-to-nearest-even and no fast-math. NaN handling is explicit, so the
// result does not depend on the host's operand order.

bool fp_is_nan(std::uint64_t bits, std::uint8_t width) {
  if (width == 4) {
    return ((bits >> 23U) & 0xFFU) == 0xFFU && (bits & 0x7FFFFFU) != 0;
  }
  return ((bits >> 52U) & 0x7FFU) == 0x7FFU && (bits & 0xFFFFFFFFFFFFFULL) != 0;
}

/// A NaN with its quiet bit set and its payload kept.
std::uint64_t fp_quiet(std::uint64_t bits, std::uint8_t width) {
  return width == 4 ? ((bits | 0x400000ULL) & 0xFFFFFFFFULL) : (bits | (1ULL << 51U));
}

/// The NaN an invalid operation produces. x86 gives the negative "real indefinite"
/// NaN and AArch64 the positive default NaN; both were checked against native
/// execution (docs/SUPPORT_MATRIX.md, the floating-point corpus).
std::uint64_t fp_default_nan(IrFloatModel model, std::uint8_t width) {
  const bool negative = model == IrFloatModel::X86;
  if (width == 4) {
    return negative ? 0xFFC00000ULL : 0x7FC00000ULL;
  }
  return negative ? 0xFFF8000000000000ULL : 0x7FF8000000000000ULL;
}

/// The value of float or double bits, exactly, as a double.
double fp_as_double(std::uint64_t bits, std::uint8_t width) {
  if (width == 4) {
    return static_cast<double>(std::bit_cast<float>(static_cast<std::uint32_t>(bits)));
  }
  return std::bit_cast<double>(bits);
}

/// a + b, a - b, a * b or a / b. A NaN operand is returned quieted: the first one
/// when both are NaN, which both architectures do. An invalid operation (such as
/// inf - inf, or 0 / 0) returns the model's default NaN.
std::uint64_t fp_binary(IrOp op, std::uint64_t x, std::uint64_t y, std::uint8_t width,
                        IrFloatModel model) {
  if (fp_is_nan(x, width)) {
    return fp_quiet(x, width);
  }
  if (fp_is_nan(y, width)) {
    return fp_quiet(y, width);
  }
  if (width == 4) {
    const float a = std::bit_cast<float>(static_cast<std::uint32_t>(x));
    const float b = std::bit_cast<float>(static_cast<std::uint32_t>(y));
    const float r = op == IrOp::FAdd   ? a + b
                    : op == IrOp::FSub ? a - b
                    : op == IrOp::FMul ? a * b
                                       : a / b;
    return std::isnan(r) ? fp_default_nan(model, 4) : std::bit_cast<std::uint32_t>(r);
  }
  const double a = std::bit_cast<double>(x);
  const double b = std::bit_cast<double>(y);
  const double r = op == IrOp::FAdd   ? a + b
                   : op == IrOp::FSub ? a - b
                   : op == IrOp::FMul ? a * b
                                      : a / b;
  return std::isnan(r) ? fp_default_nan(model, 8) : std::bit_cast<std::uint64_t>(r);
}

/// a * b + c with one rounding (FMulAdd), or c - a * b (FMulSub). The rules were
/// checked against AArch64 hardware (qemu-aarch64). An inf times zero is invalid
/// whatever the addend is. Otherwise a NaN addend propagates first, then the NaN
/// product operands in order. The product of FMulSub is negated, so a NaN taken
/// from it has its sign flipped.
std::uint64_t fp_fused(IrOp op, std::uint64_t a, std::uint64_t b, std::uint64_t c,
                       std::uint8_t width, IrFloatModel model) {
  const bool subtract = op == IrOp::FMulSub;
  const std::uint64_t sign = width == 4 ? 0x80000000ULL : 0x8000000000000000ULL;
  if (!fp_is_nan(a, width) && !fp_is_nan(b, width)) {
    const double x = fp_as_double(a, width);
    const double y = fp_as_double(b, width);
    if ((std::isinf(x) && y == 0) || (x == 0 && std::isinf(y))) {
      return fp_default_nan(model, width);
    }
  }
  if (fp_is_nan(c, width)) {
    return fp_quiet(c, width);
  }
  if (fp_is_nan(a, width)) {
    return fp_quiet(a, width) ^ (subtract ? sign : 0);
  }
  if (fp_is_nan(b, width)) {
    return fp_quiet(b, width) ^ (subtract ? sign : 0);
  }
  if (width == 4) {
    const float x = std::bit_cast<float>(static_cast<std::uint32_t>(a));
    const float y = std::bit_cast<float>(static_cast<std::uint32_t>(b));
    const float z = std::bit_cast<float>(static_cast<std::uint32_t>(c));
    const float r = subtract ? std::fma(-x, y, z) : std::fma(x, y, z);
    return std::isnan(r) ? fp_default_nan(model, 4) : std::bit_cast<std::uint32_t>(r);
  }
  const double x = std::bit_cast<double>(a);
  const double y = std::bit_cast<double>(b);
  const double z = std::bit_cast<double>(c);
  const double r = subtract ? std::fma(-x, y, z) : std::fma(x, y, z);
  return std::isnan(r) ? fp_default_nan(model, 8) : std::bit_cast<std::uint64_t>(r);
}

/// The square root. A negative operand other than -0 is an invalid operation.
std::uint64_t fp_sqrt(std::uint64_t x, std::uint8_t width, IrFloatModel model) {
  if (fp_is_nan(x, width)) {
    return fp_quiet(x, width);
  }
  const double a = fp_as_double(x, width);
  if (a < 0) {
    return fp_default_nan(model, width);
  }
  if (width == 4) {
    return std::bit_cast<std::uint32_t>(std::sqrt(static_cast<float>(a)));
  }
  return std::bit_cast<std::uint64_t>(std::sqrt(a));
}

/// How two floating-point values compare. A NaN makes them unordered.
struct FpOrder {
  bool unordered = false;
  bool less = false;
  bool equal = false;
};

FpOrder fp_order(std::uint64_t x, std::uint64_t y, std::uint8_t width) {
  FpOrder order;
  if (fp_is_nan(x, width) || fp_is_nan(y, width)) {
    order.unordered = true;
    return order;
  }
  const double a = fp_as_double(x, width);
  const double b = fp_as_double(y, width);
  order.less = a < b;
  order.equal = a == b;
  return order;
}

/// The integer of `to` bytes that a float of `from` bytes truncates to. x86
/// cvttsd2si gives the "integer indefinite" (the minimum) for a NaN or an
/// out-of-range value. AArch64 fcvtzs gives 0 for a NaN and saturates otherwise.
std::uint64_t fp_to_int(std::uint64_t bits, std::uint8_t from, std::uint8_t to,
                        IrFloatModel model) {
  const double a = fp_as_double(bits, from);
  const std::uint64_t minimum = to == 8 ? 0x8000000000000000ULL : 0x80000000ULL;
  if (std::isnan(a)) {
    return model == IrFloatModel::X86 ? minimum : 0;
  }
  const double t = std::trunc(a);
  const double limit = to == 8 ? 9223372036854775808.0 : 2147483648.0;  // 2^63 and 2^31
  if (t >= -limit && t < limit) {
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(t)) & mask(to);
  }
  if (model == IrFloatModel::X86) {
    return minimum;
  }
  if (t > 0) {
    return to == 8 ? 0x7FFFFFFFFFFFFFFFULL : 0x7FFFFFFFULL;
  }
  return minimum;
}

/// An integer of `from` bytes as a float (width 4) or double (width 8), rounded to
/// nearest. An unsigned value of 8 bytes at or above 2^63 is halved with its
/// lowest bit kept as a sticky bit, converted, and doubled: one rounding, exact.
std::uint64_t int_to_fp(std::uint64_t value, std::uint8_t from, bool is_signed, std::uint8_t to) {
  const std::uint64_t v = value & mask(from);
  if (is_signed || from < 8 || (v >> 63U) == 0) {
    const std::int64_t s = is_signed ? sign_extend(v, from) : static_cast<std::int64_t>(v);
    return to == 4 ? std::bit_cast<std::uint32_t>(static_cast<float>(s))
                   : std::bit_cast<std::uint64_t>(static_cast<double>(s));
  }
  const auto half = static_cast<std::int64_t>((v >> 1U) | (v & 1U));
  return to == 4 ? std::bit_cast<std::uint32_t>(2.0F * static_cast<float>(half))
                 : std::bit_cast<std::uint64_t>(2.0 * static_cast<double>(half));
}

/// float to double. Exact for every value; a NaN keeps its sign and payload, and is
/// quieted, as both architectures do.
std::uint64_t fp_extend(std::uint64_t bits) {
  if (fp_is_nan(bits, 4)) {
    const std::uint64_t sign = (bits >> 31U) & 1U;
    const std::uint64_t frac = (bits & 0x7FFFFFULL) | 0x400000ULL;
    return (sign << 63U) | (0x7FFULL << 52U) | (frac << 29U);
  }
  return std::bit_cast<std::uint64_t>(fp_as_double(bits, 4));
}

/// double to float, rounded to nearest. A NaN keeps its sign and the top payload
/// bits, and is quieted.
std::uint64_t fp_truncate(std::uint64_t bits) {
  if (fp_is_nan(bits, 8)) {
    const std::uint64_t sign = (bits >> 63U) & 1U;
    const std::uint64_t frac = ((bits & 0xFFFFFFFFFFFFFULL) >> 29U) | 0x400000ULL;
    return (sign << 31U) | (0xFFULL << 23U) | frac;
  }
  return std::bit_cast<std::uint32_t>(static_cast<float>(std::bit_cast<double>(bits)));
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
  if (internal::scalar_fp_width(name) != 0) {
    return Slot{"v" + name.substr(1), 0, false};  // s and d are views of v
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
      // AArch64 has no parity flag; the lifter never asks for one.
      case IrCondition::Parity:
      case IrCondition::NoParity:
        return false;
      case IrCondition::None:
        return false;
    }
    return false;
  }

  /// The x86 condition codes after a ucomis*: ZF, PF and CF as the comparison set
  /// them, with SF and OF clear.
  bool fp_condition_holds(IrCondition condition) const {
    switch (condition) {
      case IrCondition::Equal:
      case IrCondition::Zero:
        return fp_zf_;
      case IrCondition::NotEqual:
      case IrCondition::NonZero:
        return !fp_zf_;
      case IrCondition::UnsignedLess:
      case IrCondition::Carry:
        return fp_cf_;
      case IrCondition::UnsignedGreaterEqual:
      case IrCondition::NoCarry:
        return !fp_cf_;
      case IrCondition::UnsignedGreater:
        return !fp_cf_ && !fp_zf_;
      case IrCondition::UnsignedLessEqual:
        return fp_cf_ || fp_zf_;
      case IrCondition::SignedLess:  // SF != OF, and both are clear
      case IrCondition::Negative:
      case IrCondition::Overflow:
        return false;
      case IrCondition::SignedGreaterEqual:  // SF == OF
      case IrCondition::Positive:
      case IrCondition::NoOverflow:
        return true;
      case IrCondition::SignedGreater:  // ZF clear and SF == OF
        return !fp_zf_;
      case IrCondition::SignedLessEqual:  // ZF set or SF != OF
        return fp_zf_;
      case IrCondition::Parity:
        return fp_pf_;
      case IrCondition::NoParity:
        return !fp_pf_;
      case IrCondition::None:
        return false;
    }
    return false;
  }

  bool condition_holds(IrCondition condition) const {
    if (fp_flags_) {
      return fp_condition_holds(condition);
    }
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
          return r == 0;
        case IrCondition::NotEqual:
        case IrCondition::NonZero:
          return r != 0;
        // A logical test clears the carry on both ISAs, so the unsigned
        // conditions depend on which ISA's meaning the IR condition has.
        // x86 ja is CF clear and ZF clear; AArch64 hi is C set and Z clear.
        case IrCondition::UnsignedGreater:
          return aarch64_ ? false : r != 0;
        // x86 jbe is CF or ZF; AArch64 ls is C clear or Z set.
        case IrCondition::UnsignedLessEqual:
          return aarch64_ ? true : r == 0;
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
        // AArch64 lo is C clear; x86 jb is CF set.
        case IrCondition::UnsignedLess:
          return aarch64_;
        case IrCondition::Carry:
        case IrCondition::Overflow:
          return false;  // logical ops clear carry and overflow
        // x86 PF is set when the low byte of the result has an even number of ones.
        // AArch64 has no parity flag, so the lifter never asks for one there.
        case IrCondition::Parity:
          return !aarch64_ && std::popcount(static_cast<unsigned>(r & 0xFFU)) % 2 == 0;
        case IrCondition::NoParity:
          return !aarch64_ && std::popcount(static_cast<unsigned>(r & 0xFFU)) % 2 != 0;
        // AArch64 hs is C set; x86 jae is CF clear.
        case IrCondition::UnsignedGreaterEqual:
          return !aarch64_;
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
      // x86 PF of the subtraction's low byte; AArch64 has no parity flag.
      case IrCondition::Parity:
        return !aarch64_ && std::popcount(static_cast<unsigned>(diff & 0xFFU)) % 2 == 0;
      case IrCondition::NoParity:
        return !aarch64_ && std::popcount(static_cast<unsigned>(diff & 0xFFU)) % 2 != 0;
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
              fp_flags_ = false;
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
              // IrCondition::None means unconditionally.
              const bool holds = s.condition == IrCondition::None || condition_holds(s.condition);
              nzcv_ = holds ? nzcv_of(s.op == IrOp::CondCompareAdd, *x, *y, width)
                            : static_cast<std::uint8_t>(s.c.constant & 0xFU);
              explicit_flags_ = true;
              fp_flags_ = false;
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
          case IrOp::AddCarryFlags: {
            // adcs, and sbcs with the lifter's NOT of b. The carry in is read from
            // the flags before this statement, and the flags after it are NZCV of
            // the addition.
            const bool in = condition_holds(IrCondition::Carry);
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            ok = x.has_value() && y.has_value();
            if (ok) {
              const AddWithCarry sum = add_with_carry(*x, *y, in, w);
              nzcv_ = sum.nzcv;
              explicit_flags_ = true;
              fp_flags_ = false;
              ok = assign(s.dest, w, sum.result);
            }
            break;
          }
          case IrOp::FAdd:
          case IrOp::FSub:
          case IrOp::FMul:
          case IrOp::FDiv: {
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            ok = x.has_value() && y.has_value() &&
                 assign(s.dest, w, fp_binary(s.op, *x, *y, w, s.float_model));
            break;
          }
          case IrOp::FMulAdd:
          case IrOp::FMulSub: {
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            const auto z = value_of(s.c);
            ok = x.has_value() && y.has_value() && z.has_value() &&
                 assign(s.dest, w, fp_fused(s.op, *x, *y, *z, w, s.float_model));
            break;
          }
          case IrOp::FSqrt: {
            const auto x = value_of(s.a);
            ok = x.has_value() && assign(s.dest, w, fp_sqrt(*x, w, s.float_model));
            break;
          }
          case IrOp::FNeg:
          case IrOp::FAbs: {
            const auto x = value_of(s.a);
            const std::uint64_t sign = w == 4 ? 0x80000000ULL : (1ULL << 63U);
            ok = x.has_value() &&
                 assign(s.dest, w, (s.op == IrOp::FNeg ? *x ^ sign : *x & ~sign) & mask(w));
            break;
          }
          case IrOp::FCompare: {
            // ucomis* (x86) sets ZF, PF and CF, and unordered sets all three. fcmp
            // (AArch64) sets NZCV: unordered 0011, equal 0110, less 1000, greater 0010.
            const auto x = value_of(s.a);
            const auto y = value_of(s.b);
            ok = x.has_value() && y.has_value();
            if (ok) {
              const FpOrder order = fp_order(*x, *y, w);
              if (s.float_model == IrFloatModel::X86) {
                fp_flags_ = true;
                explicit_flags_ = false;
                fp_zf_ = order.unordered || order.equal;
                fp_pf_ = order.unordered;
                fp_cf_ = order.unordered || order.less;
              } else {
                fp_flags_ = false;
                explicit_flags_ = true;
                nzcv_ = order.unordered ? 0x3U : order.equal ? 0x6U : order.less ? 0x8U : 0x2U;
              }
            }
            break;
          }
          case IrOp::IntToFloat:
          case IrOp::UIntToFloat: {
            const auto x = value_of(s.a);
            ok = x.has_value() &&
                 assign(s.dest, w, int_to_fp(*x, s.a.width, s.op == IrOp::IntToFloat, w));
            break;
          }
          case IrOp::FloatToInt: {
            const auto x = value_of(s.a);
            ok = x.has_value() && assign(s.dest, w, fp_to_int(*x, s.a.width, w, s.float_model));
            break;
          }
          case IrOp::FloatExtend: {
            const auto x = value_of(s.a);
            ok = x.has_value() && assign(s.dest, 8, fp_extend(*x));
            break;
          }
          case IrOp::FloatTruncate: {
            const auto x = value_of(s.a);
            ok = x.has_value() && assign(s.dest, 4, fp_truncate(*x));
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
  /// Set by a floating-point compare on x86 (ucomis*): ZF, PF and CF as it sets them.
  bool fp_flags_ = false;
  bool fp_zf_ = false;
  bool fp_pf_ = false;
  bool fp_cf_ = false;
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
  // Integer arguments go to the argument registers in order. A function with a
  // floating-point parameter takes each argument in the register that parameter was
  // read from: an XMM or SIMD&FP register is not a positional integer register.
  const bool named_parameters =
      std::any_of(function.parameters.begin(), function.parameters.end(), [](const IrParameter& p) {
        return p.abi_register.rfind("xmm", 0) == 0 ||
               internal::scalar_fp_width(p.abi_register) != 0 ||
               internal::is_simd_register(p.abi_register);
      });
  const bool register_convention = options.convention == IrCallingConvention::SysV64 ||
                                   options.convention == IrCallingConvention::Win64 ||
                                   options.convention == IrCallingConvention::Aapcs64;
  if (named_parameters && register_convention) {
    in_registers = std::min<std::size_t>(arguments.size(), function.parameters.size());
    for (std::size_t i = 0; i < in_registers; ++i) {
      const IrParameter& parameter = function.parameters[i];
      machine.write_register(parameter.abi_register, parameter.width == 0 ? 8 : parameter.width,
                             arguments[i]);
    }
    switch (options.convention) {
      case IrCallingConvention::SysV64:
        stack_args = sp + 8;
        break;
      case IrCallingConvention::Win64:
        stack_args = sp + 8 + 32;
        break;
      default:
        stack_args = sp;  // AAPCS64: no return address on the stack
        break;
    }
  } else
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
