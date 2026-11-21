#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "donkey/ir/ir.h"
#include "lift_internal.h"
#include "registers.h"

namespace donkey::internal {
namespace {

/// A mask of the bytes of a value, bit i for byte i (little-endian, 8 bytes).
using ByteMask = std::uint8_t;

ByteMask low_bytes(std::uint8_t width) {
  return width == 0 || width >= 8 ? ByteMask{0xFF} : static_cast<ByteMask>((1U << width) - 1U);
}

/// What a register holds, relative to the function's entry: the value a register family had at
/// entry, an entry stack address plus a known offset, a stack address of unknown offset, or a value
/// the check does not follow (which may still be a stack address only when it says so).
///
/// `foreign` (for every kind but Entry) marks the bytes that may depend on a caller's value the
/// interpreter does not pass to a callee: the entry value of a register that is no argument. An
/// Entry value of such a register is foreign in all its bytes.
struct FrameValue {
  enum class Kind : std::uint8_t { Entry, Stack, StackUnknown, Unknown };
  Kind kind = Kind::Unknown;
  std::string family;       // Entry only
  std::int64_t offset = 0;  // Stack only
  ByteMask foreign = 0;

  static FrameValue entry(std::string family) {
    FrameValue value;
    value.kind = Kind::Entry;
    value.family = std::move(family);
    return value;
  }
  static FrameValue stack(std::int64_t offset) {
    FrameValue value;
    value.kind = Kind::Stack;
    value.offset = offset;
    return value;
  }
  static FrameValue unknown(bool may_be_stack, ByteMask foreign = 0) {
    FrameValue value;
    value.kind = may_be_stack ? Kind::StackUnknown : Kind::Unknown;
    value.foreign = foreign;
    return value;
  }
  [[nodiscard]] bool stackish() const { return kind == Kind::Stack || kind == Kind::StackUnknown; }
  bool operator==(const FrameValue& other) const {
    return kind == other.kind && family == other.family && offset == other.offset &&
           foreign == other.foreign;
  }
};

struct Slot {
  FrameValue value;
  std::uint8_t width = 0;
  bool operator==(const Slot& other) const { return value == other.value && width == other.width; }
};

/// The state at a program point: the registers that no longer hold their own entry value, the
/// stack slots stored at a known offset from the entry stack pointer, and whether stack memory the
/// slots no longer describe may hold foreign bytes.
struct FrameState {
  std::map<std::string, FrameValue> registers;  // absent: the family's own entry value
  std::map<std::int64_t, Slot> slots;
  bool foreign_memory = false;
  bool operator==(const FrameState& other) const {
    return registers == other.registers && slots == other.slots &&
           foreign_memory == other.foreign_memory;
  }
};

struct FrameAbi {
  std::string stack_pointer;
  std::set<std::string> callee_saved;  // must hold their entry value at a return
  std::set<std::string> caller_saved;  // unknown after a call
  /// The family `ret` jumps to on AArch64 (x30). Empty on x86-64, where the return address is the
  /// stack word at entry rsp, which no store may write.
  std::string link_register;
  /// The integer argument registers. A callee's result may depend on their entry values and on
  /// the stack pointer's; the entry value of any other register is the caller's, which the
  /// interpreter does not pass to a callee.
  std::set<std::string> arguments;
  std::string result;  // the integer result register
};

FrameAbi frame_abi(Architecture architecture) {
  FrameAbi abi;
  if (architecture == Architecture::AArch64) {
    abi.stack_pointer = "sp";
    for (int n = 19; n <= 29; ++n) {
      abi.callee_saved.insert("x" + std::to_string(n));
    }
    // AAPCS64 keeps the low 64 bits of v8-v15; the check follows 8-byte values only, so a callee
    // that writes one must reload the bits it saved.
    for (int n = 8; n <= 15; ++n) {
      abi.callee_saved.insert("v" + std::to_string(n));
    }
    abi.caller_saved = aapcs64_caller_saved_families();
    abi.link_register = "x30";
    for (int n = 0; n <= 7; ++n) {
      abi.arguments.insert("x" + std::to_string(n));
    }
    abi.result = "x0";
  } else {
    abi.stack_pointer = "rsp";
    abi.callee_saved = {"rbx", "rbp", "r12", "r13", "r14", "r15"};
    abi.caller_saved = sysv_caller_saved_families();
    abi.arguments = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    abi.result = "rax";
  }
  return abi;
}

FrameValue value_of(const FrameState& state, const std::string& family) {
  const auto found = state.registers.find(family);
  return found == state.registers.end() ? FrameValue::entry(family) : found->second;
}

void set_value(FrameState& state, const std::string& family, FrameValue value) {
  if (value.kind == FrameValue::Kind::Entry && value.family == family) {
    state.registers.erase(family);
  } else {
    state.registers[family] = std::move(value);
  }
}

/// The bytes of `value` that are foreign. `foreign_family` says which entry values are.
template <typename IsForeign>
ByteMask foreign_bytes(const FrameValue& value, const IsForeign& foreign_family) {
  if (value.kind == FrameValue::Kind::Entry) {
    return foreign_family(value.family) ? ByteMask{0xFF} : ByteMask{0};
  }
  return value.foreign;
}

FrameValue join_values(const FrameValue& a, const FrameValue& b, ByteMask a_foreign,
                       ByteMask b_foreign) {
  if (a == b) {
    return a;
  }
  return FrameValue::unknown(a.stackish() || b.stackish(),
                             static_cast<ByteMask>(a_foreign | b_foreign));
}

/// Where a memory operand points: a known offset from the entry stack pointer, somewhere on the
/// stack at an unknown offset, or memory that is not addressed from the stack pointer.
struct FrameAddress {
  enum class Kind : std::uint8_t { Known, StackAny, NotStack };
  Kind kind = Kind::NotStack;
  std::int64_t offset = 0;
};

FrameAddress address_of(const FrameState& state, const IrOperand& operand) {
  FrameAddress out;
  const FrameValue base = operand.reg.empty() ? FrameValue::unknown(false)
                                              : value_of(state, register_family(operand.reg));
  const FrameValue index = operand.index.empty() ? FrameValue::unknown(false)
                                                 : value_of(state, register_family(operand.index));
  if (base.kind == FrameValue::Kind::Stack && operand.index.empty()) {
    out.kind = FrameAddress::Kind::Known;
    out.offset = base.offset + static_cast<std::int64_t>(operand.constant);
  } else if (base.stackish() || index.stackish()) {
    out.kind = FrameAddress::Kind::StackAny;
  }
  return out;
}

FrameValue operand_value(const FrameState& state, const IrOperand& operand) {
  if (operand.kind == IrOperandKind::Register && !operand.reg.empty()) {
    return value_of(state, register_family(operand.reg));
  }
  return FrameValue::unknown(false);
}

bool full_width(const IrOperand& operand) {
  return operand.width == 0 || operand.width == 8;
}

/// Whether a write of `dest` replaces the whole register: an 8-byte write, or a 4-byte one, which
/// zero-extends on x86-64 and on AArch64. An 8- or 16-bit write keeps the rest.
bool keeps_whole_register(const IrOperand& dest) {
  return dest.width == 0 || dest.width >= 4;
}

/// `xor r, r` and `sub r, r` give zero, and `sbb r, r` minus the carry, whatever r holds.
bool reads_nothing_of_its_register(const IrStatement& statement) {
  return (statement.op == IrOp::Xor || statement.op == IrOp::Sub ||
          statement.op == IrOp::SubBorrow) &&
         statement.a.kind == IrOperandKind::Register &&
         statement.b.kind == IrOperandKind::Register && !statement.a.reg.empty() &&
         register_family(statement.a.reg) == register_family(statement.b.reg) &&
         statement.merged_width == 0 && keeps_whole_register(statement.dest);
}

/// The bytes of a constant that are not zero: an AND with a zero byte clears that byte.
ByteMask nonzero_bytes(std::uint64_t value) {
  ByteMask out = 0;
  for (int i = 0; i < 8; ++i) {
    if (((value >> (8 * i)) & 0xFFU) != 0) {
      out = static_cast<ByteMask>(out | (1U << i));
    }
  }
  return out;
}

/// Spreads foreign bytes upward from the lowest one, within `width`: a carry, a borrow or a
/// product carries a foreign byte into every byte above it.
ByteMask spread_up(ByteMask mask, std::uint8_t width) {
  if (mask == 0) {
    return 0;
  }
  ByteMask out = 0;
  for (int i = 0; i < 8; ++i) {
    if ((mask >> i) & 1U) {
      out = static_cast<ByteMask>(0xFFU << i);
      break;
    }
  }
  return static_cast<ByteMask>(out & low_bytes(width));
}

class FrameCheck {
 public:
  FrameCheck(const IrFunction& function, Architecture architecture, FrameContract contract)
      : function_(function), abi_(frame_abi(architecture)), contract_(contract) {}

  std::optional<std::string> run() {
    const std::size_t count = function_.blocks.size();
    if (count == 0) {
      return std::nullopt;
    }
    std::vector<std::optional<FrameState>> in(count);
    FrameState start;
    set_value(start, abi_.stack_pointer, FrameValue::stack(0));
    in[0] = start;
    std::vector<std::size_t> worklist{0};
    while (!worklist.empty()) {
      const std::size_t block = worklist.back();
      worklist.pop_back();
      FrameState state = *in[block];
      const auto& statements = function_.blocks[block].statements;
      bool path_ends = false;
      for (std::size_t s = 0; s < statements.size(); ++s) {
        const IrStatement& statement = statements[s];
        // A tail call: a jump to another function, lifted as a call and a return of the same
        // instruction. The callee returns to this function's caller, so the contract holds at the
        // jump (and on AArch64 nothing writes x30). Its arguments are read as a call's are.
        if (statement.op == IrOp::Call && !statement.no_return && s + 1 < statements.size() &&
            statements[s + 1].op == IrOp::Return &&
            statements[s + 1].source_address == statement.source_address) {
          if (auto failed = read_call(statement, state)) {
            return failed;
          }
          if (auto failed = check_return(state, false)) {
            return failed;
          }
          path_ends = true;
          break;
        }
        if (statement.op == IrOp::Return) {
          if (!statement.unreachable) {
            if (auto failed = check_return(state, true)) {
              return failed;
            }
          }
          path_ends = true;
          break;
        }
        if (statement.op == IrOp::Call && statement.no_return) {
          path_ends = true;  // nothing after the call runs
          break;
        }
        if (auto failed = transfer(statement, state)) {
          return failed;
        }
      }
      if (path_ends || statements.empty()) {
        continue;
      }
      std::vector<std::size_t> successors;
      const IrStatement& terminator = statements.back();
      if (terminator.op == IrOp::Branch && terminator.a.kind == IrOperandKind::Block) {
        successors.push_back(terminator.a.block);
      } else if (terminator.op == IrOp::CondBranch && terminator.b.kind == IrOperandKind::Block) {
        successors.push_back(terminator.b.block);
        successors.push_back(block + 1);
      } else if (terminator.op == IrOp::Switch && terminator.a.kind == IrOperandKind::Block) {
        successors.push_back(terminator.a.block);
        for (const IrSwitchCase& value : terminator.switch_cases) {
          successors.push_back(value.target_block);
        }
      } else {
        return "a block ends without a branch or a return";
      }
      for (const std::size_t successor : successors) {
        if (successor >= count) {
          return "a branch leaves the function";
        }
        if (!in[successor].has_value()) {
          in[successor] = state;
          worklist.push_back(successor);
          continue;
        }
        FrameState merged = join(*in[successor], state);
        if (!(merged == *in[successor])) {
          in[successor] = std::move(merged);
          worklist.push_back(successor);
        }
      }
    }
    return std::nullopt;
  }

 private:
  /// Whether the entry value of `family` is a caller's value the interpreter does not pass to a
  /// callee (Callee contract only). Not foreign: the argument registers, the stack pointer (whose
  /// value the check follows as a stack address), the zero register, a lifter temporary (var_N,
  /// defined by the statement before it), and the flags (a compare sets them without naming them
  /// as a destination, and the lifters already make a function Partial when it reads flags it did
  /// not set).
  [[nodiscard]] bool foreign_family(const std::string& family) const {
    return contract_ == FrameContract::Callee && abi_.arguments.count(family) == 0 &&
           family != abi_.stack_pointer && family != "xzr" && family != "flags" &&
           family.rfind("var_", 0) != 0;
  }

  [[nodiscard]] ByteMask foreign_of(const FrameValue& value) const {
    return foreign_bytes(value,
                         [this](const std::string& family) { return foreign_family(family); });
  }

  /// The foreign bytes a register operand reads, within its width; 0 for any other operand.
  [[nodiscard]] ByteMask read_mask(const FrameState& state, const IrOperand& operand,
                                   std::uint8_t width) const {
    if (operand.kind != IrOperandKind::Register || operand.reg.empty()) {
      return 0;
    }
    const std::uint8_t used = operand.width != 0 ? operand.width : width;
    return static_cast<ByteMask>(foreign_of(operand_value(state, operand)) & low_bytes(used));
  }

  [[nodiscard]] FrameState join(const FrameState& a, const FrameState& b) const {
    FrameState out;
    std::set<std::string> families;
    for (const auto& [family, value] : a.registers) {
      families.insert(family);
    }
    for (const auto& [family, value] : b.registers) {
      families.insert(family);
    }
    for (const std::string& family : families) {
      const FrameValue va = value_of(a, family);
      const FrameValue vb = value_of(b, family);
      set_value(out, family, join_values(va, vb, foreign_of(va), foreign_of(vb)));
    }
    bool dropped_foreign = false;
    for (const auto& [offset, slot] : a.slots) {
      const auto other = b.slots.find(offset);
      if (other != b.slots.end() && other->second == slot) {
        out.slots.emplace(offset, slot);
      } else if (foreign_of(slot.value) != 0) {
        dropped_foreign = true;
      }
    }
    for (const auto& [offset, slot] : b.slots) {
      if (out.slots.count(offset) == 0 && foreign_of(slot.value) != 0) {
        dropped_foreign = true;
      }
    }
    out.foreign_memory = a.foreign_memory || b.foreign_memory || dropped_foreign;
    return out;
  }

  [[nodiscard]] static std::optional<std::string> foreign_use(ByteMask mask, const char* what) {
    if (mask == 0) {
      return std::nullopt;
    }
    return std::string(what) +
           " depends on the entry value of a register that is no argument: it is the caller's "
           "value, which a call does not pass";
  }

  /// The registers a memory operand's address is computed from must not be foreign.
  [[nodiscard]] std::optional<std::string> read_address(const FrameState& state,
                                                        const IrOperand& operand) const {
    if (operand.kind != IrOperandKind::Memory) {
      return std::nullopt;
    }
    ByteMask mask = 0;
    for (const std::string* name : {&operand.reg, &operand.index}) {
      if (!name->empty()) {
        mask = static_cast<ByteMask>(mask | foreign_of(value_of(state, register_family(*name))));
      }
    }
    return foreign_use(mask, "an address");
  }

  /// A call's target and arguments are observed by the callee.
  [[nodiscard]] std::optional<std::string> read_call(const IrStatement& statement,
                                                     const FrameState& state) const {
    if (auto failed = read_address(state, statement.a)) {
      return failed;
    }
    ByteMask mask = read_mask(state, statement.a, 8);
    for (const IrOperand& argument : statement.call_arguments) {
      mask = static_cast<ByteMask>(mask | read_mask(state, argument, 8));
      if (auto failed = read_address(state, argument)) {
        return failed;
      }
    }
    return foreign_use(mask, "a call's target or argument");
  }

  [[nodiscard]] std::optional<std::string> check_return(const FrameState& state,
                                                        bool own_return) const {
    if (!abi_.link_register.empty()) {
      const FrameValue link = value_of(state, abi_.link_register);
      if (!(link == FrameValue::entry(abi_.link_register))) {
        return "a return does not see the entry " + abi_.link_register +
               ", so it may not return to the caller";
      }
    }
    if (contract_ != FrameContract::Callee) {
      return std::nullopt;
    }
    if (!(value_of(state, abi_.stack_pointer) == FrameValue::stack(0))) {
      return "the stack pointer at a return is not its entry value";
    }
    for (const std::string& family : abi_.callee_saved) {
      if (!(value_of(state, family) == FrameValue::entry(family))) {
        return "callee-saved register " + family + " does not hold its entry value at a return";
      }
    }
    // The caller takes all of the result register (a tail call's result is its callee's).
    if (own_return) {
      if (auto failed = foreign_use(foreign_of(value_of(state, abi_.result)), "the result")) {
        return failed;
      }
    }
    return std::nullopt;
  }

  /// Erases the slots that overlap [first, first + width); a foreign slot that goes leaves its
  /// bytes in memory the slots no longer describe.
  void erase_overlapping(FrameState& state, std::int64_t first, std::uint8_t width) const {
    const std::int64_t end = first + width;
    for (auto it = state.slots.begin(); it != state.slots.end();) {
      const std::int64_t slot_end = it->first + it->second.width;
      if (it->first < end && first < slot_end) {
        state.foreign_memory = state.foreign_memory || foreign_of(it->second.value) != 0;
        it = state.slots.erase(it);
      } else {
        ++it;
      }
    }
  }

  /// Whether some stack memory may hold foreign bytes: a slot does, or memory no slot describes.
  [[nodiscard]] bool stack_may_hold_foreign(const FrameState& state) const {
    if (state.foreign_memory) {
      return true;
    }
    for (const auto& [offset, slot] : state.slots) {
      if (foreign_of(slot.value) != 0) {
        return true;
      }
    }
    return false;
  }

  /// The foreign bytes a load of [first, first + width) on the stack may read.
  [[nodiscard]] ByteMask stack_load_mask(const FrameState& state, std::int64_t first,
                                         std::uint8_t width) const {
    if (state.foreign_memory) {
      return low_bytes(width);
    }
    const std::int64_t end = first + width;
    for (const auto& [offset, slot] : state.slots) {
      if (offset < end && first < offset + slot.width && foreign_of(slot.value) != 0) {
        return low_bytes(width);
      }
    }
    return 0;
  }

  /// A write of memory: a Store (address `a`, value `b`), or any other statement whose
  /// destination is memory (x86 `add [m], r`), whose value is not followed.
  std::optional<std::string> store(FrameState& state, const IrStatement& statement) const {
    const bool plain = statement.op == IrOp::Store;
    const IrOperand& target = plain ? statement.a : statement.dest;
    if (auto failed = read_address(state, target)) {
      return failed;
    }
    const FrameAddress address = address_of(state, target);
    const std::uint8_t width = statement.width == 0 ? 8 : statement.width;
    // The bytes stored that may be foreign. A read-modify-write mixes the old memory in as well.
    ByteMask value_mask = plain ? read_mask(state, statement.b, width)
                                : static_cast<ByteMask>(read_mask(state, statement.a, width) |
                                                        read_mask(state, statement.b, width) |
                                                        read_mask(state, statement.c, width));
    if (!plain && address.kind == FrameAddress::Kind::Known) {
      value_mask =
          static_cast<ByteMask>(value_mask | stack_load_mask(state, address.offset, width));
    } else if (!plain && address.kind == FrameAddress::Kind::StackAny &&
               stack_may_hold_foreign(state)) {
      value_mask = low_bytes(width);
    }
    if (!plain && value_mask != 0) {
      value_mask = low_bytes(width);
    }
    if (address.kind == FrameAddress::Kind::NotStack) {
      // Memory outside the stack is the callee's output: no foreign byte may reach it. The check's
      // premise: such a store does not write this function's register save slots (only a dangling
      // or overflowing pointer could).
      return foreign_use(value_mask, "a value stored to memory");
    }
    if (address.kind == FrameAddress::Kind::StackAny) {
      for (const auto& [offset, slot] : state.slots) {
        state.foreign_memory = state.foreign_memory || foreign_of(slot.value) != 0;
      }
      state.slots.clear();
      state.foreign_memory = state.foreign_memory || value_mask != 0;
      if (contract_ == FrameContract::Callee && abi_.link_register.empty()) {
        return "a store at an unknown stack offset may write the return address";
      }
      return std::nullopt;
    }
    const std::int64_t first = address.offset;
    if (contract_ == FrameContract::Callee && abi_.link_register.empty() && first < 8 &&
        first + width > 0) {
      return "a store writes the return address";
    }
    erase_overlapping(state, first, width);
    Slot slot;
    slot.width = width;
    if (plain && width == 8 && statement.b.kind == IrOperandKind::Register) {
      slot.value = operand_value(state, statement.b);  // a save: the value is followed
    } else {
      slot.value = FrameValue::unknown(false, value_mask);
    }
    state.slots[first] = slot;
    return std::nullopt;
  }

  /// The foreign bytes of a register statement's result, before it is written to its destination.
  [[nodiscard]] ByteMask result_mask(const IrStatement& statement, const FrameState& state,
                                     std::uint8_t width) const {
    if (reads_nothing_of_its_register(statement)) {
      return 0;
    }
    const ByteMask a = read_mask(state, statement.a, width);
    const ByteMask b = read_mask(state, statement.b, width);
    const ByteMask c = read_mask(state, statement.c, width);
    switch (statement.op) {
      case IrOp::Assign:
      case IrOp::ZeroExtend:
        return static_cast<ByteMask>(a & low_bytes(width));
      case IrOp::SignExtend: {
        const std::uint8_t from = statement.a.width != 0 ? statement.a.width : width;
        const bool top = ((a >> (from == 0 ? 0 : from - 1)) & 1U) != 0;
        return static_cast<ByteMask>((a | (top ? 0xFFU : 0U)) & low_bytes(width));
      }
      case IrOp::And:
        if (statement.b.kind == IrOperandKind::Constant) {
          return static_cast<ByteMask>(a & nonzero_bytes(statement.b.constant) & low_bytes(width));
        }
        if (statement.a.kind == IrOperandKind::Constant) {
          return static_cast<ByteMask>(b & nonzero_bytes(statement.a.constant) & low_bytes(width));
        }
        return static_cast<ByteMask>((a | b) & low_bytes(width));
      case IrOp::Or:
      case IrOp::Xor:
        return static_cast<ByteMask>((a | b) & low_bytes(width));
      case IrOp::Add:
      case IrOp::Sub:
      case IrOp::Mul:
      case IrOp::Shl:
      case IrOp::AddCarry:
      case IrOp::SubBorrow:
      case IrOp::Lea:
        return spread_up(static_cast<ByteMask>(a | b | c), width);
      default:
        // Anything else (a shift right, a division, a bit count, floating point): any foreign byte
        // may reach any byte of the result.
        return (a | b | c) != 0 ? low_bytes(width) : ByteMask{0};
    }
  }

  std::optional<std::string> transfer(const IrStatement& statement, FrameState& state) const {
    if (statement.op == IrOp::Store || statement.dest.kind == IrOperandKind::Memory) {
      return store(state, statement);
    }
    if (statement.op == IrOp::Call) {
      if (auto failed = read_call(statement, state)) {
        return failed;
      }
      // A call keeps the callee-saved registers and the stack pointer (the callee's own summary or
      // the C library's ABI says so; an unresolved call leaves its caller Partial anyway) and
      // changes the caller-saved ones; on AArch64 `bl` writes x30.
      for (const std::string& family : abi_.caller_saved) {
        set_value(state, family, FrameValue::unknown(false));
      }
      if (!abi_.link_register.empty()) {
        set_value(state, abi_.link_register, FrameValue::unknown(false));
      }
      return std::nullopt;
    }
    // An access's address is observed (it may fault, and it decides what is read). A lea only
    // computes its address: the result's foreign bytes are followed instead.
    for (const IrOperand* operand : {&statement.a, &statement.b, &statement.c}) {
      if (statement.op != IrOp::Lea) {
        if (auto failed = read_address(state, *operand)) {
          return failed;
        }
      }
    }
    const std::uint8_t width = statement.width == 0 ? 8 : statement.width;
    if (statement.dest.kind != IrOperandKind::Register || statement.dest.reg.empty()) {
      // No register is written: a compare, a test, a branch, a switch on its selector. What it
      // reads decides control flow or the flags, which the callee's result follows.
      ByteMask mask = static_cast<ByteMask>(read_mask(state, statement.a, width) |
                                            read_mask(state, statement.b, width) |
                                            read_mask(state, statement.c, width));
      if (statement.op == IrOp::Switch) {
        mask = static_cast<ByteMask>(mask | read_mask(state, statement.dest, width));
      }
      if (reads_nothing_of_its_register(statement)) {
        mask = 0;
      }
      return foreign_use(mask, "a comparison or a branch");
    }
    if (statement.op == IrOp::DivUnsigned || statement.op == IrOp::DivSigned ||
        statement.op == IrOp::RemUnsigned || statement.op == IrOp::RemSigned) {
      // A division faults on a zero divisor or an overflow: what it reads is observed.
      if (auto failed = foreign_use(static_cast<ByteMask>(read_mask(state, statement.a, width) |
                                                          read_mask(state, statement.b, width) |
                                                          read_mask(state, statement.c, width)),
                                    "a division")) {
        return failed;
      }
    }
    const std::string dest = register_family(statement.dest.reg);
    const FrameValue old = value_of(state, dest);
    const ByteMask old_foreign = foreign_of(old);
    const FrameValue a = operand_value(state, statement.a);
    const FrameValue b = operand_value(state, statement.b);
    const FrameValue c = operand_value(state, statement.c);
    // Whether the result may be a stack address: it is computed from one (a register that holds
    // one, or the address a lea takes). A value loaded from the stack is not one unless the slot
    // held one, which the load case below reads.
    const bool reads_stack =
        a.stackish() || b.stackish() || c.stackish() ||
        (statement.op == IrOp::Lea && statement.a.kind == IrOperandKind::Memory &&
         address_of(state, statement.a).kind != FrameAddress::Kind::NotStack);
    // A write that keeps part of the old value (an 8- or 16-bit write merged into the register).
    const bool partial_write = statement.merged_width != 0 || !keeps_whole_register(statement.dest);
    ByteMask computed = result_mask(statement, state, width);
    if (statement.op == IrOp::Lea && statement.a.kind == IrOperandKind::Memory) {
      ByteMask address = 0;
      for (const std::string* name : {&statement.a.reg, &statement.a.index}) {
        if (!name->empty()) {
          address =
              static_cast<ByteMask>(address | foreign_of(value_of(state, register_family(*name))));
        }
      }
      computed = static_cast<ByteMask>(computed | spread_up(address, width));
    }
    FrameValue result = FrameValue::unknown(reads_stack || (partial_write && old.stackish()));
    bool followed = false;  // the result is a value the check follows (an entry value or a slot's)
    if (!partial_write && full_width(statement.dest)) {
      if (statement.op == IrOp::Assign && statement.a.kind == IrOperandKind::Register &&
          full_width(statement.a)) {
        result = a;
        followed = true;
      } else if ((statement.op == IrOp::Add || statement.op == IrOp::Sub) &&
                 a.kind == FrameValue::Kind::Stack && statement.b.kind == IrOperandKind::Constant) {
        const auto amount = static_cast<std::int64_t>(statement.b.constant);
        result =
            FrameValue::stack(statement.op == IrOp::Add ? a.offset + amount : a.offset - amount);
      } else if (statement.op == IrOp::Lea && statement.a.kind == IrOperandKind::Memory) {
        const FrameAddress address = address_of(state, statement.a);
        if (address.kind == FrameAddress::Kind::Known) {
          result = FrameValue::stack(address.offset);
        }
      }
    }
    if ((statement.op == IrOp::Load || statement.op == IrOp::Assign) &&
        statement.a.kind == IrOperandKind::Memory) {
      // A load: the AArch64 lifter writes it as Load, the x86-64 lifter as an Assign from a
      // memory operand.
      const FrameAddress address = address_of(state, statement.a);
      computed = 0;
      if (address.kind == FrameAddress::Kind::Known) {
        const auto slot = state.slots.find(address.offset);
        if (!partial_write && full_width(statement.dest) && slot != state.slots.end() &&
            slot->second.width == width && width == 8) {
          result = slot->second.value;  // a restore: the saved value is followed
          followed = true;
        } else {
          computed = stack_load_mask(state, address.offset, width);
        }
      } else if (address.kind == FrameAddress::Kind::StackAny) {
        computed = stack_may_hold_foreign(state) ? low_bytes(width) : ByteMask{0};
      }
    }
    if (!followed) {
      // The bytes the write leaves: a merge keeps the old value's bytes above the write, a 4-byte
      // write zero-extends, an 8-byte write replaces all of them.
      const std::uint8_t written = statement.dest.width == 0 ? 8 : statement.dest.width;
      ByteMask mask = 0;
      if (partial_write) {
        mask = static_cast<ByteMask>((old_foreign & ~low_bytes(written)) |
                                     (computed & low_bytes(written)));
      } else {
        mask = static_cast<ByteMask>(computed & low_bytes(written));
      }
      result.foreign = mask;
    }
    if (statement.op == IrOp::CondAssign) {
      // The old value stays when the condition is false.
      result = join_values(old, result, old_foreign, foreign_of(result));
    }
    set_value(state, dest, result);
    return std::nullopt;
  }

  const IrFunction& function_;
  FrameAbi abi_;
  FrameContract contract_;
};

}  // namespace

std::set<std::string> sysv_caller_saved_families() {
  std::set<std::string> out = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"};
  for (int n = 0; n < 16; ++n) {
    out.insert("xmm" + std::to_string(n));
  }
  return out;
}

std::set<std::string> aapcs64_caller_saved_families() {
  std::set<std::string> out;
  for (int n = 0; n <= 18; ++n) {
    out.insert("x" + std::to_string(n));
  }
  out.insert("x30");
  for (int n = 0; n <= 7; ++n) {
    out.insert("v" + std::to_string(n));
  }
  for (int n = 16; n <= 31; ++n) {
    out.insert("v" + std::to_string(n));
  }
  return out;
}

std::optional<std::string> check_frame(const IrFunction& function, Architecture architecture,
                                       FrameContract contract) {
  if (architecture != Architecture::X86_64 && architecture != Architecture::AArch64) {
    return "the frame check models x86-64 and AArch64 only";
  }
  return FrameCheck(function, architecture, contract).run();
}

}  // namespace donkey::internal
