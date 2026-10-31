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

std::int64_t sign_extend(std::uint64_t value, std::uint8_t width) {
  if (width >= 8) {
    return static_cast<std::int64_t>(value);
  }
  const unsigned bits = width * 8U;
  const std::uint64_t sign = 1ULL << (bits - 1U);
  value &= mask(width);
  return static_cast<std::int64_t>((value ^ sign) - sign);
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

  bool condition_holds(IrCondition condition) const {
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
