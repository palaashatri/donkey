#include "donkey/ir/lift.h"

#include "donkey/ir/abi.h"
#include "donkey/ir/libc_models.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "donkey/analysis/cfg.h"
#include "lift_internal.h"
#include "registers.h"

namespace donkey {
namespace {

/// The x86-64 register families a call may change (System V's caller-saved set, which holds every
/// Win64 caller-saved register too).
const std::set<std::string>& caller_saved_families() {
  static const std::set<std::string> families = [] {
    std::set<std::string> out = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"};
    for (int n = 0; n < 16; ++n) {
      out.insert("xmm" + std::to_string(n));
    }
    return out;
  }();
  return families;
}

}  // namespace

struct CallSummaryCache::Impl {
  /// What a call to a resolved callee needs and what it changes (G21-T2).
  struct Summary {
    std::vector<IrParameter> parameters;  // the callee's System V integer arguments, in order
    std::uint8_t return_width = 0;        // the integer result's width; 0 for none
    std::vector<std::string> writes;      // every register family the callee's code may write
    std::size_t height = 1;               // 1 + the tallest callee below it; 1 for a leaf
  };
  /// The verdict of a summary for the budget it is asked with. Positive: a summary of height at
  /// most the budget exists (the one stored). Negative: none exists at any budget. Cut: none of
  /// height at most `cut_at` exists (one may exist above it).
  enum class Verdict : std::uint8_t { Positive, Negative, Cut };
  struct Entry {
    Verdict kind = Verdict::Negative;
    Summary summary;           // Positive only
    std::uint64_t cut_at = 0;  // Cut only: the largest budget it was cut at
  };
  /// A function being lifted, with the budget it is lifted at (its callees are asked with one
  /// less). `saw_*` record how its calls answered.
  struct Frame {
    std::uint64_t address = 0;
    std::uint64_t budget = 0;
    bool saw_negative = false;
    bool saw_cut = false;
  };
  std::unordered_map<std::uint64_t, Entry> entries;
  // The functions being lifted, outermost first. A call back to one of them is a cycle.
  std::vector<Frame> path;
};

class CallSummaryAccess {
 public:
  static CallSummaryCache::Impl& impl(CallSummaryCache& cache) { return *cache.impl_; }
};

CallSummaryCache::CallSummaryCache() : impl_(std::make_unique<CallSummaryCache::Impl>()) {}

CallSummaryCache::~CallSummaryCache() = default;

namespace {

/// `0x1149`: an address as the notes print it.
std::string hex_address(std::uint64_t value) {
  char buffer[24];
  std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
  return std::string(buffer);
}

// Whether a callee's code may read an argument passed on the stack (the seventh and later integer
// arguments, at entry rsp + 8 and up). The check runs a dataflow over the callee's IR (the lift
// without passes): every register is tracked as an offset from the entry rsp when it holds a stack
// address, and an access, a lea or a stack address passed to a call at offset 8 or more is taken as
// an incoming argument. Whatever cannot be followed (a stack address of unknown offset, or a stack
// address stored into a register the tracking does not model) is taken as an incoming argument too,
// so the caller is never resolved on a guess. Returns true when the callee may read one.
bool reads_incoming_stack_argument(const IrFunction& function) {
  // A register family's value: absent (not a stack address), a known offset from the entry rsp, or
  // nullopt (a stack address of unknown offset).
  using StackValues = std::map<std::string, std::optional<std::int64_t>>;
  const std::size_t count = function.blocks.size();
  if (count == 0) {
    return false;
  }
  std::vector<std::optional<StackValues>> entry(count);
  entry[0] = StackValues{{"rsp", 0}};
  bool refused = false;

  auto join = [](const StackValues& a, const StackValues& b) {
    StackValues out;
    for (const auto& [family, value] : a) {
      const auto other = b.find(family);
      if (other == b.end()) {
        out[family] = std::nullopt;
      } else {
        out[family] = value == other->second ? value : std::nullopt;
      }
    }
    for (const auto& [family, value] : b) {
      if (a.find(family) == a.end()) {
        out[family] = std::nullopt;
      }
    }
    return out;
  };
  auto same = [](const StackValues& a, const StackValues& b) { return a == b; };

  // `access` is false for a lea, which only computes the address; an access covers the operand's
  // bytes, so it reaches an argument when any of them is at entry rsp + 8 or above.
  auto check_memory = [&](const IrOperand& operand, const StackValues& values, bool access) {
    if (operand.kind != IrOperandKind::Memory) {
      return;
    }
    const std::string base =
        operand.reg.empty() ? std::string() : internal::register_family(operand.reg);
    const std::string index =
        operand.index.empty() ? std::string() : internal::register_family(operand.index);
    if (!index.empty() && values.count(index) != 0) {
      refused = true;  // an indexed stack address
    }
    if (base.empty()) {
      return;
    }
    const auto found = values.find(base);
    if (found == values.end()) {
      return;
    }
    if (!found->second.has_value()) {
      refused = true;
      return;
    }
    if (!index.empty()) {
      // A stack base with an index: nothing bounds the index, so the access can reach the incoming
      // stack arguments whatever the displacement is.
      refused = true;
      return;
    }
    const auto displacement = static_cast<std::int64_t>(operand.constant);
    const std::int64_t first = *found->second + displacement;
    const std::int64_t size = access ? (operand.width == 0 ? 8 : operand.width) : 1;
    if (first + size > 8) {
      refused = true;  // an incoming stack argument (entry rsp + 8 and up)
    }
  };

  auto transfer = [&](const IrStatement& statement, StackValues& values) {
    const bool lea = statement.op == IrOp::Lea;
    check_memory(statement.dest, values, true);
    check_memory(statement.a, values, !lea);
    check_memory(statement.b, values, true);
    check_memory(statement.c, values, true);
    auto tracked = [&](const IrOperand& operand) {
      return operand.kind == IrOperandKind::Register &&
             values.count(internal::register_family(operand.reg)) != 0;
    };
    if (statement.op == IrOp::Call) {
      for (const IrOperand& argument : statement.call_arguments) {
        if (tracked(argument)) {
          refused = true;  // a stack address escapes into the callee
        }
      }
    }
    // The statements the tracking models: a move, an add or subtract of a constant, a lea, a load
    // and a call. Any other statement that reads a stack address (including a store of one, which
    // would let a later load read it back) is not followed: it is refused.
    const bool modelled = statement.op == IrOp::Assign || statement.op == IrOp::Lea ||
                          statement.op == IrOp::Load || statement.op == IrOp::Call ||
                          ((statement.op == IrOp::Add || statement.op == IrOp::Sub) &&
                           statement.b.kind == IrOperandKind::Constant);
    if (!modelled) {
      for (const IrOperand* operand : {&statement.a, &statement.b, &statement.c}) {
        if (tracked(*operand)) {
          refused = true;
        }
      }
    }
    if (statement.dest.kind != IrOperandKind::Register || statement.dest.reg.empty()) {
      return;
    }
    const std::string dest = internal::register_family(statement.dest.reg);
    // A write that can keep the destination's old value, in part or on some path (a conditional
    // move, an 8- or 16-bit write, a merge into the register), leaves a stack address the register
    // held in it: the tracking does not follow that, so it is refused.
    const bool keeps_old_value = statement.op == IrOp::CondAssign || statement.merged_width != 0 ||
                                 (statement.dest.width != 0 && statement.dest.width < 4);
    if (keeps_old_value && values.count(dest) != 0) {
      refused = true;
      return;
    }
    // The value the statement gives the destination: outer optional: is it a stack address; inner:
    // its offset from the entry rsp, when known.
    using StackAddress = std::optional<std::optional<std::int64_t>>;
    StackAddress result;
    auto source_value = [&](const IrOperand& operand) -> StackAddress {
      if (operand.kind != IrOperandKind::Register) {
        return std::nullopt;
      }
      const auto found = values.find(internal::register_family(operand.reg));
      if (found == values.end()) {
        return std::nullopt;
      }
      return found->second;
    };
    if (statement.op == IrOp::Assign) {
      result = source_value(statement.a);
    } else if ((statement.op == IrOp::Add || statement.op == IrOp::Sub) &&
               statement.b.kind == IrOperandKind::Constant) {
      const auto source = source_value(statement.a);
      if (source.has_value()) {
        if (!source->has_value()) {
          result = std::optional<std::int64_t>{};
        } else {
          const auto amount = static_cast<std::int64_t>(statement.b.constant);
          result = statement.op == IrOp::Add ? **source + amount : **source - amount;
        }
      }
    } else if (statement.op == IrOp::Lea && statement.a.kind == IrOperandKind::Memory) {
      // The address of a memory operand. With an index register the offset is not known: refuse
      // when the index or the base is a stack address; otherwise the base and displacement give it.
      const bool index_tracked = !statement.a.index.empty() &&
                                 values.count(internal::register_family(statement.a.index)) != 0;
      const auto base = statement.a.reg.empty()
                            ? values.end()
                            : values.find(internal::register_family(statement.a.reg));
      const bool base_tracked = base != values.end();
      if (index_tracked || (base_tracked && !statement.a.index.empty())) {
        refused = true;
      } else if (base_tracked) {
        if (!base->second.has_value()) {
          result = std::optional<std::int64_t>{};
        } else {
          const auto displacement = static_cast<std::int64_t>(statement.a.constant);
          result = *base->second + displacement;
        }
      }
    }
    if (result.has_value()) {
      values[dest] = *result;
    } else {
      values.erase(dest);
    }
  };

  std::vector<std::size_t> worklist{0};
  while (!worklist.empty() && !refused) {
    const std::size_t block = worklist.back();
    worklist.pop_back();
    if (!entry[block].has_value()) {
      continue;
    }
    StackValues values = *entry[block];
    for (const IrStatement& statement : function.blocks[block].statements) {
      transfer(statement, values);
      if (refused) {
        return true;
      }
    }
    const IrStatement& terminator = function.blocks[block].statements.back();
    std::vector<std::size_t> successors;
    if (terminator.op == IrOp::Branch) {
      successors.push_back(terminator.a.block);
    } else if (terminator.op == IrOp::CondBranch) {
      successors.push_back(terminator.b.block);
      successors.push_back(block + 1);
    } else if (terminator.op == IrOp::Switch) {
      return true;  // not followed through a jump table
    }
    for (const std::size_t successor : successors) {
      if (successor >= count) {
        return true;
      }
      if (!entry[successor].has_value()) {
        entry[successor] = values;
        worklist.push_back(successor);
      } else {
        StackValues merged = join(*entry[successor], values);
        if (!same(merged, *entry[successor])) {
          entry[successor] = std::move(merged);
          worklist.push_back(successor);
        }
      }
    }
  }
  return refused;
}

using namespace donkey;

std::uint8_t register_width(const std::string& name) {
  static const std::unordered_map<std::string, std::uint8_t> kWidths = {
      {"rax", 8},  {"rbx", 8},  {"rcx", 8},  {"rdx", 8},  {"rsi", 8},  {"rdi", 8},  {"rbp", 8},
      {"rsp", 8},  {"r8", 8},   {"r9", 8},   {"r10", 8},  {"r11", 8},  {"r12", 8},  {"r13", 8},
      {"r14", 8},  {"r15", 8},  {"eax", 4},  {"ebx", 4},  {"ecx", 4},  {"edx", 4},  {"esi", 4},
      {"edi", 4},  {"ebp", 4},  {"esp", 4},  {"r8d", 4},  {"r9d", 4},  {"r10d", 4}, {"r11d", 4},
      {"r12d", 4}, {"r13d", 4}, {"r14d", 4}, {"r15d", 4}, {"ax", 2},   {"bx", 2},   {"cx", 2},
      {"dx", 2},   {"si", 2},   {"di", 2},   {"bp", 2},   {"sp", 2},   {"al", 1},   {"bl", 1},
      {"cl", 1},   {"dl", 1},   {"ah", 1},   {"bh", 1},   {"ch", 1},   {"dh", 1},   {"sil", 1},
      {"dil", 1},  {"bpl", 1},  {"spl", 1},  {"r8b", 1},  {"r9b", 1},  {"r10b", 1}, {"r11b", 1},
      {"r12b", 1}, {"r13b", 1}, {"r14b", 1}, {"r15b", 1}, {"r8w", 2},  {"r9w", 2},  {"r10w", 2},
      {"r11w", 2}, {"r12w", 2}, {"r13w", 2}, {"r14w", 2}, {"r15w", 2}, {"x0", 8},   {"x1", 8},
      {"x2", 8},   {"x3", 8},   {"x4", 8},   {"x5", 8},   {"x6", 8},   {"x7", 8},   {"x8", 8},
      {"x9", 8},   {"x10", 8},  {"x11", 8},  {"x12", 8},  {"x13", 8},  {"x14", 8},  {"x15", 8},
      {"x16", 8},  {"x17", 8},  {"x18", 8},  {"x19", 8},  {"x20", 8},  {"x21", 8},  {"x22", 8},
      {"x23", 8},  {"x24", 8},  {"x25", 8},  {"x26", 8},  {"x27", 8},  {"x28", 8},  {"x29", 8},
      {"x30", 8},  {"w0", 4},   {"w1", 4},   {"w2", 4},   {"w3", 4},   {"w4", 4},   {"w5", 4},
      {"w6", 4},   {"w7", 4},   {"w8", 4},   {"w9", 4},   {"w10", 4},  {"w11", 4},  {"w12", 4},
      {"w13", 4},  {"w14", 4},  {"w15", 4},  {"w16", 4},  {"w17", 4},  {"w18", 4},  {"w19", 4},
      {"w20", 4},  {"w21", 4},  {"w22", 4},  {"w23", 4},  {"w24", 4},  {"w25", 4},  {"w26", 4},
      {"w27", 4},  {"w28", 4},  {"w29", 4},  {"w30", 4},  {"sp", 8},   {"wsp", 4},  {"fp", 8},
      {"lr", 8},   {"pc", 8},   {"xzr", 8},  {"wzr", 4},
  };
  const auto found = kWidths.find(name);
  if (found != kWidths.end()) {
    return found->second;
  }
  // An XMM register is modelled by its low 8 bytes (the scalar lane).
  return name.rfind("xmm", 0) == 0 ? 8 : 0;
}

std::uint8_t operand_width(const Operand& operand) {
  if (operand.size != 0) {
    return operand.size;
  }
  if (operand.kind == OperandKind::Register) {
    return register_width(operand.reg);
  }
  return 0;
}

/// Note for an instruction with an fs- or gs-relative memory operand (x86 thread-local storage and
/// the stack-protector canary).
const std::string kSegmentRelativeNote =
    "fs- or gs-relative memory (thread-local storage) is not modelled";

/// True when an operand of the instruction is a memory access with an fs or gs segment override.
bool has_segment_memory_operand(const Instruction& instruction) {
  for (const Operand& operand : instruction.structured_operands) {
    if (operand.kind == OperandKind::Memory && !operand.memory.segment.empty()) {
      return true;
    }
  }
  return false;
}

IrOperand memory_operand(const Operand& operand, const Instruction& instruction) {
  IrOperand result;
  result.kind = IrOperandKind::Memory;
  result.width = operand_width(operand);
  result.reg = operand.memory.base;
  result.index = operand.memory.index;
  result.scale = operand.memory.scale == 0 ? 1 : operand.memory.scale;
  if (result.reg == "rip") {
    result.reg.clear();
    const std::uint64_t resolved = instruction.address + instruction.length +
                                   static_cast<std::uint64_t>(operand.memory.displacement);
    result.constant = resolved;
  } else {
    result.constant = static_cast<std::uint64_t>(operand.memory.displacement);
  }
  return result;
}

IrOperand to_ir_operand(const Operand& operand, const Instruction& instruction,
                        std::uint8_t default_width) {
  switch (operand.kind) {
    case OperandKind::Register:
      return IrOperand::register_ref(operand.reg, register_width(operand.reg));
    case OperandKind::Immediate:
      return IrOperand::constant_value(
          static_cast<std::uint64_t>(operand.immediate),
          operand_width(operand) == 0 ? default_width : operand_width(operand));
    case OperandKind::Memory:
      return memory_operand(operand, instruction);
    case OperandKind::Unknown:
      break;
  }
  return IrOperand::none();
}

IrCondition branch_condition(const std::string& mnemonic) {
  if (mnemonic == "jz" || mnemonic == "je") {
    return IrCondition::Zero;
  }
  if (mnemonic == "jnz" || mnemonic == "jne") {
    return IrCondition::NonZero;
  }
  if (mnemonic == "jb" || mnemonic == "jc" || mnemonic == "jnae") {
    return IrCondition::UnsignedLess;
  }
  if (mnemonic == "jae" || mnemonic == "jnb" || mnemonic == "jnc") {
    return IrCondition::UnsignedGreaterEqual;
  }
  if (mnemonic == "ja" || mnemonic == "jnbe") {
    return IrCondition::UnsignedGreater;
  }
  if (mnemonic == "jbe" || mnemonic == "jna") {
    return IrCondition::UnsignedLessEqual;
  }
  if (mnemonic == "jl" || mnemonic == "jnge") {
    return IrCondition::SignedLess;
  }
  if (mnemonic == "jge" || mnemonic == "jnl") {
    return IrCondition::SignedGreaterEqual;
  }
  if (mnemonic == "jg" || mnemonic == "jnle") {
    return IrCondition::SignedGreater;
  }
  if (mnemonic == "jle" || mnemonic == "jng") {
    return IrCondition::SignedLessEqual;
  }
  if (mnemonic == "jp" || mnemonic == "jpe") {
    return IrCondition::Parity;  // unordered after an FP comparison
  }
  if (mnemonic == "jnp" || mnemonic == "jpo") {
    return IrCondition::NoParity;
  }
  if (mnemonic == "js") {
    return IrCondition::Negative;
  }
  if (mnemonic == "jns") {
    return IrCondition::Positive;
  }
  if (mnemonic == "jo") {
    return IrCondition::Overflow;
  }
  if (mnemonic == "jno") {
    return IrCondition::NoOverflow;
  }
  return IrCondition::None;
}

/// Condition of a cmovcc / setcc mnemonic, through the jcc table.
IrCondition suffix_condition(const std::string& mnemonic, std::size_t prefix) {
  if (mnemonic.size() <= prefix) {
    return IrCondition::None;
  }
  return branch_condition("j" + mnemonic.substr(prefix));
}

bool is_cmov(const std::string& mnemonic) {
  return mnemonic.rfind("cmov", 0) == 0 && suffix_condition(mnemonic, 4) != IrCondition::None;
}

bool is_setcc(const std::string& mnemonic) {
  return mnemonic.rfind("set", 0) == 0 && suffix_condition(mnemonic, 3) != IrCondition::None;
}

/// The name of the high 64-bit lane of an XMM register. The IR keeps the two lanes of
/// an XMM register as two registers, so an instruction that changes the high lane names it.
std::string high_lane(const std::string& xmm) {
  return xmm + "_hi";
}

/// Scalar single and double SSE instructions that the lifter models, and the packed
/// logical operations that combine both lanes of two registers.
bool is_scalar_sse(const std::string& mnemonic) {
  static const char* const kNames[] = {
      "addss",    "addsd",    "subss",     "subsd",     "mulss",    "mulsd",    "divss",
      "divsd",    "sqrtss",   "sqrtsd",    "movss",     "movsd",    "movaps",   "movapd",
      "cvtsi2ss", "cvtsi2sd", "cvttss2si", "cvttsd2si", "cvtss2sd", "cvtsd2ss", "ucomiss",
      "ucomisd",  "comiss",   "comisd",    "xorps",     "xorpd",    "pxor",     "andps",
      "andpd",    "andnps",   "andnpd",    "orps",      "orpd",     "cmpltsd",
  };
  return std::find(std::begin(kNames), std::end(kNames), mnemonic) != std::end(kNames);
}

/// The comparisons that set the flags from an FP comparison.
bool is_sse_compare(const std::string& mnemonic) {
  return mnemonic == "ucomiss" || mnemonic == "ucomisd" || mnemonic == "comiss" ||
         mnemonic == "comisd";
}

/// Instructions that leave the flags exactly as they were.
bool preserves_flags(const std::string& mnemonic) {
  return mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "movzx" || mnemonic == "movsx" ||
         mnemonic == "movsxd" || mnemonic == "lea" || mnemonic == "push" || mnemonic == "pop" ||
         mnemonic == "nop" || mnemonic == "endbr64" || mnemonic == "endbr32" ||
         mnemonic == "cdqe" || mnemonic == "cdq" || mnemonic == "cqo" || mnemonic == "cwde" ||
         mnemonic == "cbw" || mnemonic == "cwd" || mnemonic == "not" || is_cmov(mnemonic) ||
         is_setcc(mnemonic) ||
         (is_scalar_sse(mnemonic) && !is_sse_compare(mnemonic) && mnemonic != "cmpltsd");
}

/// xchg of two registers: a swap that leaves the flags alone. The memory forms
/// need a load and a store, so they are not register exchanges.
bool is_register_exchange(const Instruction& instruction) {
  const std::vector<Operand>& operands = instruction.structured_operands;
  return instruction.mnemonic == "xchg" && operands.size() == 2 &&
         operands[0].kind == OperandKind::Register && operands[1].kind == OperandKind::Register;
}

/// Conditions that read only ZF and SF, which every flag-setting arithmetic
/// instruction derives from its result alone.
bool zero_sign_condition(IrCondition condition) {
  return condition == IrCondition::Zero || condition == IrCondition::NonZero ||
         condition == IrCondition::Equal || condition == IrCondition::NotEqual ||
         condition == IrCondition::Negative || condition == IrCondition::Positive;
}

/// Conditions that read only CF (jb, jae, setb, cmovae, ...), and adc/sbb. A
/// Compare's unsigned conditions are exactly the carry: `a <u b` is CF after
/// `cmp a, b`, and the lifter writes jb / setb as UnsignedLess.
bool carry_condition(IrCondition condition) {
  return condition == IrCondition::Carry || condition == IrCondition::NoCarry ||
         condition == IrCondition::UnsignedLess || condition == IrCondition::UnsignedGreaterEqual;
}

bool is_bitwise_or_arithmetic(const std::string& mnemonic) {
  return mnemonic == "add" || mnemonic == "sub" || mnemonic == "and" || mnemonic == "or" ||
         mnemonic == "xor" || mnemonic == "shl" || mnemonic == "sal" || mnemonic == "shr" ||
         mnemonic == "sar" || mnemonic == "imul";
}

IrOp arithmetic_op(const std::string& mnemonic) {
  if (mnemonic == "add" || mnemonic == "inc") {
    return IrOp::Add;
  }
  if (mnemonic == "sub" || mnemonic == "dec") {
    return IrOp::Sub;
  }
  if (mnemonic == "and") {
    return IrOp::And;
  }
  if (mnemonic == "or") {
    return IrOp::Or;
  }
  if (mnemonic == "xor") {
    return IrOp::Xor;
  }
  if (mnemonic == "shl" || mnemonic == "sal") {
    return IrOp::Shl;
  }
  if (mnemonic == "shr") {
    return IrOp::Shr;
  }
  if (mnemonic == "sar") {
    return IrOp::Sar;
  }
  if (mnemonic == "imul") {
    return IrOp::Mul;
  }
  return IrOp::Nop;
}

/// The budget of a top-level call (G21-T2): a direct call resolves when the callee's summary has
/// height at most this. It is the evaluator's call depth: kMaxCallDepth in eval.cpp is 8, and it
/// runs a callee at depth 1 to 8. The budget falls by one at each level, so the summaries being
/// computed are never more than kMaxCallHeight + 1 levels deep.
constexpr std::uint64_t kMaxCallHeight = 8;

using KnownCallee = CallSummaryCache::Impl::Summary;
using Verdict = CallSummaryCache::Impl::Verdict;

/// Pushes a function being lifted, with its budget, for the length of the lift.
class PathFrame {
 public:
  PathFrame(CallSummaryCache::Impl& cache, std::uint64_t address, std::uint64_t budget)
      : cache_(cache) {
    CallSummaryCache::Impl::Frame frame;
    frame.address = address;
    frame.budget = budget;
    cache_.path.push_back(frame);
  }
  ~PathFrame() { cache_.path.pop_back(); }
  PathFrame(const PathFrame&) = delete;
  PathFrame& operator=(const PathFrame&) = delete;

 private:
  CallSummaryCache::Impl& cache_;
};

Result<IrFunction> lift_body(const BinaryImage& image, const AnalysisResult& analysis,
                             const Function& function, const LiftOptions& options);

/// Lifts `callee` at `budget` and classifies it (G21-T2). A Negative callee makes it Negative for
/// every budget. Otherwise a Cut callee makes it Cut at this budget. Only when all its calls
/// resolved does its own lift decide: Positive, with height one more than its tallest callee, or
/// Negative. The caller caches the result.
CallSummaryCache::Impl::Entry compute_summary(CallSummaryCache::Impl& cache,
                                              const BinaryImage& image,
                                              const AnalysisResult& analysis,
                                              const Function& callee, std::uint64_t budget,
                                              const LiftOptions& options) {
  CallSummaryCache::Impl::Entry negative;
  CallSummaryCache::Impl::Entry cut;
  cut.kind = Verdict::Cut;
  cut.cut_at = budget;
  PathFrame frame(cache, callee.address, budget);
  const std::size_t self = cache.path.size() - 1;
  LiftOptions nested = options;
  // The signature must not depend on how the caller is lifted: always with passes.
  nested.run_passes = true;
  auto lifted = lift_body(image, analysis, callee, nested);
  if (cache.path[self].saw_negative) {
    return negative;
  }
  if (cache.path[self].saw_cut) {
    return cut;
  }
  if (!lifted || lifted.value().partial || lifted.value().return_floating_point) {
    return negative;
  }
  static const std::array<std::string, 6> kSysV = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
  for (std::size_t i = 0; i < lifted.value().parameters.size(); ++i) {
    if (i >= kSysV.size() || lifted.value().parameters[i].abi_register != kSysV[i]) {
      return negative;
    }
  }
  // The passes remove a register write that nothing reads (dead-register removal), but the
  // compiled callee still makes it, so the write set comes from the callee's lift without passes.
  LiftOptions unoptimised = nested;
  unoptimised.run_passes = false;
  auto raw = lift_body(image, analysis, callee, unoptimised);
  if (cache.path[self].saw_negative) {
    return negative;
  }
  if (cache.path[self].saw_cut) {
    return cut;
  }
  if (!raw || raw.value().partial) {
    return negative;
  }
  // A callee that reads a stack-passed argument has more parameters than the registers show.
  if (reads_incoming_stack_argument(raw.value())) {
    return negative;
  }
  CallSummaryCache::Impl::Entry result;
  result.kind = Verdict::Positive;
  KnownCallee& summary = result.summary;
  summary.parameters = lifted.value().parameters;
  summary.return_width = lifted.value().return_width;
  std::size_t tallest = 0;
  for (const IrBlock& block : raw.value().blocks) {
    for (const IrStatement& statement : block.statements) {
      if (statement.dest.kind == IrOperandKind::Register && !statement.dest.reg.empty()) {
        summary.writes.push_back(internal::register_family(statement.dest.reg));
      }
      if (statement.op == IrOp::Call && !statement.call_model.empty()) {
        // A modelled C library call (G21-T7) may change every caller-saved register.
        summary.writes.insert(summary.writes.end(), caller_saved_families().begin(),
                              caller_saved_families().end());
        continue;
      }
      if (statement.op != IrOp::Call || !statement.signature_inferred) {
        continue;
      }
      // A resolved call of the callee: what its own callee writes changes here too, and its height
      // counts. A resolved callee is Positive in the table, with a height within its budget.
      summary.writes.insert(summary.writes.end(), statement.call_writes.begin(),
                            statement.call_writes.end());
      if (statement.a.kind != IrOperandKind::Constant) {
        return negative;
      }
      const auto below = cache.entries.find(statement.a.constant);
      if (below == cache.entries.end() || below->second.kind != Verdict::Positive) {
        return negative;
      }
      tallest = std::max(tallest, below->second.summary.height);
    }
  }
  std::sort(summary.writes.begin(), summary.writes.end());
  summary.writes.erase(std::unique(summary.writes.begin(), summary.writes.end()),
                       summary.writes.end());
  summary.height = 1 + tallest;
  return result;
}

/// The answer of a summary query: Positive with its summary, Negative, or Cut.
struct Answer {
  Verdict verdict = Verdict::Negative;
  const KnownCallee* summary = nullptr;
};

/// What a stored entry answers for `budget`. A Cut entry is not decided here (see answer_for).
Answer answer_from(const CallSummaryCache::Impl::Entry& entry, std::uint64_t budget) {
  Answer answer;
  if (entry.kind == Verdict::Positive) {
    if (entry.summary.height <= budget) {
      answer.verdict = Verdict::Positive;
      answer.summary = &entry.summary;
    } else {
      answer.verdict = Verdict::Cut;  // exists, but taller than this budget
    }
  } else {
    answer.verdict = entry.kind;
  }
  return answer;
}

/// The answer for the function at `target` asked with `budget` (G21-T2). A cycle (the function is
/// being lifted) is Negative. A Cut entry answers any budget up to the one it was cut at, and is
/// computed again above it: a Cut is never final.
Answer answer_for(const BinaryImage& image, const AnalysisResult& analysis, std::uint64_t target,
                  std::uint64_t budget, const LiftOptions& options) {
  CallSummaryCache::Impl& cache = CallSummaryAccess::impl(*options.call_summaries);
  Answer none;
  none.verdict = Verdict::Cut;
  if (budget == 0) {
    return none;  // no summary has height 0
  }
  if (const auto known = cache.entries.find(target); known != cache.entries.end()) {
    if (known->second.kind != Verdict::Cut || budget <= known->second.cut_at) {
      return answer_from(known->second, budget);
    }
  }
  for (const CallSummaryCache::Impl::Frame& frame : cache.path) {
    if (frame.address == target) {
      Answer cycle;
      cycle.verdict = Verdict::Negative;  // a function on a cycle is never resolved
      return cycle;
    }
  }
  const Function* callee = nullptr;
  for (const Function& candidate : analysis.functions) {
    if (candidate.address == target) {
      callee = &candidate;
      break;
    }
  }
  if (callee == nullptr) {
    cache.entries[target] = CallSummaryCache::Impl::Entry{};
    return answer_from(cache.entries[target], budget);
  }
  CallSummaryCache::Impl::Entry computed =
      compute_summary(cache, image, analysis, *callee, budget, options);
  CallSummaryCache::Impl::Entry& stored = cache.entries[target];
  stored = std::move(computed);
  return answer_from(stored, budget);
}

struct Lifter {
  const BinaryImage& image;
  const AnalysisResult& analysis;
  const Function& function;
  const LiftOptions& options;

  std::vector<const BasicBlock*> blocks;
  std::unordered_map<std::uint64_t, std::uint32_t> block_by_address;
  IrFunction out;
  std::size_t statement_count = 0;
  std::uint32_t temporary = 0;
  std::uint8_t pointer_width = 8;
  const char* stack_pointer = "rsp";
  const char* frame_pointer = "rbp";
  const char* return_register = "rax";

  Lifter(const BinaryImage& image_in, const AnalysisResult& analysis_in,
         const Function& function_in, const LiftOptions& options_in)
      : image(image_in),
        analysis(analysis_in),
        function(function_in),
        options(options_in),
        pointer_width(image_in.architecture == Architecture::X86 ? 4 : 8),
        stack_pointer(image_in.architecture == Architecture::X86 ? "esp" : "rsp"),
        frame_pointer(image_in.architecture == Architecture::X86 ? "ebp" : "rbp"),
        return_register(image_in.architecture == Architecture::X86 ? "eax" : "rax") {}

  std::uint32_t temporary_id() { return temporary++; }

  IrOperand temp_operand(std::uint32_t id, std::uint8_t width) {
    return IrOperand::register_ref("var_" + std::to_string(id), width);
  }

  bool limit_reached() const { return statement_count >= options.max_statements; }

  void push(IrBlock& block, IrStatement statement) {
    // A block needs its terminator even when the statement budget is spent, or the IR does not
    // verify. Anything else dropped at the limit makes the function Partial, so a truncated body
    // is never reported as Complete.
    const bool terminator = statement.op == IrOp::Branch || statement.op == IrOp::CondBranch ||
                            statement.op == IrOp::Switch || statement.op == IrOp::Return;
    if (limit_reached() && !terminator) {
      out.partial = true;
      return;
    }
    if (statement.width == 0) {
      statement.width = pointer_width;
    }
    // Never emit an operand the verifier would reject. An unknown register
    // width is a modelling gap, so the statement becomes an explicit opaque
    // effect instead of malformed IR.
    auto bad_width = [](const IrOperand& operand) {
      if (operand.kind == IrOperandKind::None || operand.kind == IrOperandKind::Block) {
        return false;
      }
      return operand.width != 1 && operand.width != 2 && operand.width != 4 && operand.width != 8;
    };
    if (bad_width(statement.dest) || bad_width(statement.a) || bad_width(statement.b)) {
      const std::uint64_t address = statement.source_address;
      statement = IrStatement{};
      statement.op = IrOp::Unsupported;
      statement.width = pointer_width;
      statement.source_address = address;
      statement.text = "operand width is not modelled";
      out.partial = true;
    }
    block.statements.push_back(std::move(statement));
    ++statement_count;
  }

  void note(std::string text) { out.notes.push_back(std::move(text)); }

  /// A result that depends on the MXCSR rounding mode. The caller may set a mode other than round
  /// to nearest, and this lifter does not model MXCSR, so the function is reported Partial with
  /// the assumption written down, once.
  void mark_rounding_dependent() {
    static const std::string kNote =
        "floating-point results assume the MXCSR rounding mode is round to nearest; a caller "
        "may set another mode, which is not modelled";
    if (std::find(out.notes.begin(), out.notes.end(), kNote) == out.notes.end()) {
      mark_partial(kNote);
    } else {
      out.partial = true;
    }
  }

  void mark_partial(std::string text) {
    out.notes.push_back(std::move(text));
    out.partial = true;
  }

  /// mark_partial for a reason that every call of a kind gives: the note is added once.
  void mark_partial_once(const std::string& text) {
    if (std::find(out.notes.begin(), out.notes.end(), text) == out.notes.end()) {
      out.notes.push_back(text);
    }
    out.partial = true;
  }

  void unsupported(IrBlock& block, const Instruction& instruction) {
    IrStatement statement;
    statement.op = IrOp::Unsupported;
    statement.source_address = instruction.address;
    statement.width = pointer_width;
    statement.text = instruction.mnemonic;
    if (!instruction.operands.empty()) {
      statement.text += " " + instruction.operands;
    }
    push(block, std::move(statement));
    out.partial = true;
  }

  void lift_mov(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand source = to_ir_operand(operands[1], instruction, pointer_width);
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);

    if (destination.kind == IrOperandKind::Register) {
      IrStatement statement;
      statement.op = IrOp::Assign;
      statement.dest = destination;
      statement.a = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return;
    }
    if (destination.kind == IrOperandKind::Memory) {
      IrStatement statement;
      statement.op = IrOp::Store;
      statement.a = destination;
      statement.b = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return;
    }
    unsupported(block, instruction);
  }

  void lift_extend(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    const IrOperand source = to_ir_operand(operands[1], instruction, pointer_width);
    if (destination.kind != IrOperandKind::Register || destination.width <= source.width ||
        source.width == 0) {
      // An extend must widen: the verifier requires a destination strictly wider than its
      // source. movsxd with a 32-bit destination from a 32-bit source (found by the PE fuzzer,
      // ir.malformed_extend) is not a widening, so it is not modelled rather than mis-typed.
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = instruction.mnemonic == "movzx" ? IrOp::ZeroExtend : IrOp::SignExtend;
    statement.dest = destination;
    statement.a = source;
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_lea(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[1].kind != OperandKind::Memory) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Lea;
    statement.dest = to_ir_operand(operands[0], instruction, pointer_width);
    statement.a = memory_operand(operands[1], instruction);
    statement.width = statement.dest.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  /// What the IR knows about the flags a later jcc / cmovcc / setcc / adc reads.
  /// Exact: every flag. ZeroSign: ZF and SF only. CarryOnly: CF only (the last
  /// Compare holds the operands that give CF exactly, but not ZF or SF).
  enum class FlagsState { Unknown, Exact, ZeroSign, CarryOnly };
  FlagsState flags_state = FlagsState::Unknown;

  /// True when the modelled flags give `condition` exactly.
  bool flags_readable(IrCondition condition) const {
    switch (flags_state) {
      case FlagsState::Unknown:
        return false;
      case FlagsState::Exact:
        return true;
      case FlagsState::ZeroSign:
        return zero_sign_condition(condition);
      case FlagsState::CarryOnly:
        return carry_condition(condition);
    }
    return false;
  }

  IrStatement flags_test_of(const IrOperand& value, std::uint64_t address) const {
    IrStatement test;
    test.op = IrOp::Test;
    test.a = value;
    test.b = value;
    test.width = value.width;
    test.source_address = address;
    return test;
  }

  /// `consumer` is the condition the next flag reader in this block uses (if
  /// any reads these flags before they are overwritten). Flags are modelled
  /// only where the IR can state them exactly: logic operations clear CF/OF
  /// so a test of the result is exact; a subtraction keeps its operands in a
  /// comparison; other arithmetic gives exact ZF/SF only.
  void lift_arithmetic(IrBlock& block, const Instruction& instruction,
                       std::optional<IrCondition> consumer) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    const IrOp op = arithmetic_op(mnemonic);
    const FlagsState prior_flags = flags_state;
    flags_state = FlagsState::Unknown;
    if (op == IrOp::Nop || operands.empty()) {
      unsupported(block, instruction);
      return;
    }
    if (mnemonic == "imul" && operands.size() == 1) {
      unsupported(block, instruction);  // rdx:rax = rax * src: no double-width result in the IR
      return;
    }

    IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    IrOperand left = destination;
    IrOperand source;
    if (mnemonic == "imul" && operands.size() == 3) {
      // imul dst, src, imm: dst = src * imm (the destination is not an input).
      left = to_ir_operand(operands[1], instruction, pointer_width);
      source = to_ir_operand(operands[2], instruction, pointer_width);
    } else if (operands.size() >= 2) {
      source = to_ir_operand(operands[1], instruction, pointer_width);
    } else {
      source = IrOperand::constant_value(1, destination.width);  // inc / dec
    }
    const bool shift = op == IrOp::Shl || op == IrOp::Shr || op == IrOp::Sar;
    const bool logic = op == IrOp::And || op == IrOp::Or || op == IrOp::Xor;
    const bool subtract = mnemonic == "sub";
    if (shift && source.kind == IrOperandKind::Constant) {
      // x86 masks the count to 5 bits (6 for 64-bit operands): `shl eax, 32`
      // shifts by 0. Emit the effective count.
      source.constant &= destination.width >= 8 ? 0x3FU : 0x1FU;
    }
    // A shift by an effective count of zero (a register may hold one) changes
    // neither the destination nor the flags, so its flags are not defined here.
    const bool flags_defined =
        mnemonic != "imul" &&
        (!shift || (source.kind == IrOperandKind::Constant && source.constant != 0));
    if (shift && source.kind == IrOperandKind::Constant && source.constant == 0) {
      // Known not to touch the flags: the previous flag writer's Compare/Test
      // is still the last one in the block, so whatever it modelled holds.
      flags_state = prior_flags;
    }

    if (destination.kind == IrOperandKind::Register) {
      std::optional<IrOperand> saved;
      // The flags are derived from the operands the operation read. An operand
      // that is also the destination is overwritten by the operation, so it is
      // copied first: `sub x, x` and `add x, x` need the original value.
      const bool carry_add = mnemonic == "add" && consumer && carry_condition(*consumer);
      const bool needs_operands =
          consumer && flags_defined && (subtract ? !zero_sign_condition(*consumer) : carry_add);
      auto copy_before = [&](const IrOperand& value) {
        const IrOperand copy_of = temp_operand(temporary_id(), value.width);
        IrStatement copy;
        copy.op = IrOp::Assign;
        copy.dest = copy_of;
        copy.a = value;
        copy.width = value.width;
        copy.source_address = instruction.address;
        push(block, std::move(copy));
        return copy_of;
      };
      if (needs_operands && subtract) {
        // Keep the minuend: the condition compares it with the subtrahend.
        saved = copy_before(destination);
      }
      // The Compare reads the source again after the destination is written. A
      // source that the destination is part of (a register, or a memory address
      // formed from it, as in `add rax, [rax]`) must be copied before the write.
      std::optional<IrOperand> saved_source;
      const std::string destination_family = internal::register_family(destination.reg);
      const bool source_uses_destination =
          source.kind == IrOperandKind::Register
              ? internal::register_family(source.reg) == destination_family
              : source.kind == IrOperandKind::Memory &&
                    (internal::register_family(source.reg) == destination_family ||
                     internal::register_family(source.index) == destination_family);
      if (needs_operands && source_uses_destination) {
        saved_source = copy_before(source);
      }
      IrStatement statement;
      statement.op = op;
      statement.dest = destination;
      statement.a = left;
      statement.b = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      if (needs_operands) {
        const IrOperand compared = saved_source ? *saved_source : source;
        IrStatement compare;
        compare.op = IrOp::Compare;
        compare.b = compared;
        compare.width = destination.width;
        compare.source_address = instruction.address;
        if (saved) {
          compare.a = *saved;
          compare.condition = IrCondition::Equal;
          push(block, std::move(compare));
          flags_state = FlagsState::Exact;
        } else {
          // add: the carry out is set exactly when the sum is below the addend.
          compare.a = destination;
          compare.condition = IrCondition::UnsignedLess;
          push(block, std::move(compare));
          flags_state = FlagsState::CarryOnly;
        }
      } else if (consumer && flags_defined) {
        push(block, flags_test_of(destination, instruction.address));
        flags_state = logic ? FlagsState::Exact : FlagsState::ZeroSign;
      }
      return;
    }

    if (destination.kind == IrOperandKind::Memory) {
      // Read-modify-write through a temporary: the IR has no memory-to-memory
      // forms and must not pretend the destination is a register.
      const std::uint32_t id = temporary_id();
      IrStatement load;
      load.op = IrOp::Assign;
      load.dest = temp_operand(id, destination.width);
      load.a = destination;
      load.width = destination.width;
      load.source_address = instruction.address;
      push(block, std::move(load));

      IrStatement compute;
      compute.op = op;
      compute.dest = temp_operand(id, destination.width);
      compute.a = temp_operand(id, destination.width);
      compute.b = source;
      compute.width = destination.width;
      compute.source_address = instruction.address;
      push(block, std::move(compute));

      IrStatement store;
      store.op = IrOp::Store;
      store.a = destination;
      store.b = temp_operand(id, destination.width);
      store.width = destination.width;
      store.source_address = instruction.address;
      push(block, std::move(store));
      if (consumer && flags_defined) {
        push(block, flags_test_of(temp_operand(id, destination.width), instruction.address));
        flags_state = logic ? FlagsState::Exact : FlagsState::ZeroSign;
      }
      return;
    }
    unsupported(block, instruction);
  }

  /// popcnt, tzcnt, lzcnt and bswap (register destination; popcnt, tzcnt and
  /// lzcnt take a register or memory source). popcnt, tzcnt and lzcnt write
  /// flags that are not modelled. bswap leaves the flags alone. Memory
  /// destinations and the 8- and 16-bit forms are Unsupported.
  void lift_bit_operation(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    if (mnemonic == "bt" || mnemonic == "bts" || mnemonic == "btr" || mnemonic == "btc") {
      lift_bit_test(block, instruction);
      return;
    }
    const bool swap = mnemonic == "bswap";
    if (!swap) {
      flags_state = FlagsState::Unknown;
    }
    if (operands.size() != (swap ? 1U : 2U) || operands[0].kind != OperandKind::Register ||
        (!swap && operands[1].kind != OperandKind::Register &&
         operands[1].kind != OperandKind::Memory)) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    if (destination.width != 4 && destination.width != 8) {
      unsupported(block, instruction);
      return;
    }
    IrOperand source = destination;
    if (!swap) {
      source = to_ir_operand(operands[1], instruction, pointer_width);
      if (source.kind == IrOperandKind::Memory) {
        // The memory operand is read first, into a temporary of the operation's width.
        const IrOperand value = temp_operand(temporary_id(), destination.width);
        IrStatement load;
        load.op = IrOp::Load;
        load.dest = value;
        load.a = source;
        load.width = destination.width;
        load.source_address = instruction.address;
        push(block, std::move(load));
        source = value;
      }
    }
    if (mnemonic == "bsf" || mnemonic == "bsr") {
      lift_bit_scan(block, instruction, destination, source);
      return;
    }
    IrStatement statement;
    if (mnemonic == "popcnt") {
      statement.op = IrOp::PopCount;
    } else if (mnemonic == "tzcnt") {
      statement.op = IrOp::CountTrailingZeros;
    } else if (mnemonic == "lzcnt") {
      statement.op = IrOp::CountLeadingZeros;
    } else {
      statement.op = IrOp::ByteSwap;
    }
    statement.dest = destination;
    statement.a = source;
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  /// The compare or test whose flags are still current at the end of `previous`,
  /// a block that falls through into the next one. Scanning back from its end,
  /// the first instruction that writes flags must be a two-operand cmp or test of
  /// registers and immediates. Everything after it must keep the flags and must
  /// not write a register the compare reads. Returns its index in
  /// analysis.instructions.
  std::optional<std::uint32_t> carried_flag_writer(const BasicBlock& previous) const {
    const std::uint32_t first = previous.first_instruction;
    const std::uint32_t end = previous.first_instruction + previous.instruction_count;
    if (previous.instruction_count == 0 || end > analysis.instructions.size()) {
      return std::nullopt;
    }
    std::optional<std::uint32_t> writer;
    for (std::uint32_t i = end; i-- > first;) {
      const Instruction& candidate = analysis.instructions[i];
      if (candidate.classification == InstructionClass::ConditionalJump) {
        continue;  // reads the flags and writes none; it can only end the block
      }
      if (candidate.classification != InstructionClass::Other) {
        return std::nullopt;
      }
      if (!preserves_flags(candidate.mnemonic)) {
        writer = i;
        break;
      }
    }
    if (!writer) {
      return std::nullopt;
    }
    const Instruction& compare = analysis.instructions[*writer];
    // A float compare (ucomis*, comis*) may read memory. The block after it re-reads that
    // memory, so nothing after the compare may access memory: a store could change it.
    const bool float_compare = is_sse_compare(compare.mnemonic);
    if ((compare.mnemonic != "cmp" && compare.mnemonic != "test" && !float_compare) ||
        compare.structured_operands.size() != 2) {
      return std::nullopt;
    }
    bool compare_reads_memory = false;
    std::vector<std::string> read;
    for (const Operand& operand : compare.structured_operands) {
      if (operand.kind == OperandKind::Register) {
        read.push_back(internal::register_family(operand.reg));
      } else if (operand.kind == OperandKind::Memory && float_compare) {
        compare_reads_memory = true;
        if (!operand.memory.base.empty()) {
          read.push_back(internal::register_family(operand.memory.base));
        }
        if (!operand.memory.index.empty()) {
          read.push_back(internal::register_family(operand.memory.index));
        }
      } else if (operand.kind != OperandKind::Immediate) {
        return std::nullopt;  // a memory operand could change before the next block
      }
    }
    for (std::uint32_t i = *writer + 1; i < end; ++i) {
      const Instruction& later = analysis.instructions[i];
      if (later.classification == InstructionClass::ConditionalJump && i + 1 == end) {
        continue;  // the block's terminator
      }
      if (compare_reads_memory) {
        for (const Operand& operand : later.structured_operands) {
          if (operand.kind == OperandKind::Memory) {
            return std::nullopt;  // the memory the compare read may have changed
          }
        }
      }
      // cdq, cqo, cdqe, cwde, cbw and cwd write rax or rdx without an operand.
      if (later.classification != InstructionClass::Other || !preserves_flags(later.mnemonic) ||
          later.mnemonic == "cdq" || later.mnemonic == "cqo" || later.mnemonic == "cdqe" ||
          later.mnemonic == "cwde" || later.mnemonic == "cbw" || later.mnemonic == "cwd") {
        return std::nullopt;
      }
      const auto reads = [&read](const std::string& family) {
        return std::find(read.begin(), read.end(), family) != read.end();
      };
      if ((later.mnemonic == "push" || later.mnemonic == "pop") && reads("rsp")) {
        return std::nullopt;
      }
      if (!later.structured_operands.empty() &&
          later.structured_operands[0].kind == OperandKind::Register &&
          reads(internal::register_family(later.structured_operands[0].reg))) {
        return std::nullopt;
      }
    }
    return writer;
  }

  /// True when `block` has no predecessor but `previous`, the block just before it
  /// in address order, and `previous` reaches it by falling through: either it does
  /// not end in a branch, or it ends in a conditional branch whose not-taken edge
  /// is `block`. An unresolved indirect branch in the function could reach any
  /// block, so it rules this out. Calls and jumps from elsewhere count as
  /// predecessors, which is conservative.
  bool single_fallthrough_predecessor(const BasicBlock& previous, const BasicBlock& block) const {
    if (function.estimated) {
      return false;
    }
    const Instruction& last =
        analysis.instructions[previous.first_instruction + previous.instruction_count - 1];
    std::size_t predecessors = 0;
    bool from_previous = false;
    for (const CfgEdge& edge : analysis.cfg.edges) {
      if (edge.to != block.address) {
        continue;
      }
      ++predecessors;
      if (edge.from == last.address && edge.kind == CfgEdgeKind::ConditionalFalse) {
        from_previous = true;
      }
    }
    if (last.classification == InstructionClass::Other) {
      // A plain fall-through is the edge from `last` counted above. Without one (the CFG records
      // it only between contiguous blocks), the fall-through still reaches `block`.
      if (!from_previous) {
        ++predecessors;
        from_previous = true;
      }
    } else if (last.classification != InstructionClass::ConditionalJump) {
      return false;
    }
    return from_previous && predecessors == 1;
  }

  /// bsf and bsr: the index of the lowest or highest set bit. For a nonzero source
  /// they are tzcnt and width-1 minus lzcnt. For a zero source the architecture
  /// leaves the destination undefined, and this lifter does not model that case,
  /// so the function is Partial. ZF is not modelled either, so the flags are
  /// unknown afterwards.
  void lift_bit_scan(IrBlock& block, const Instruction& instruction, const IrOperand& destination,
                     const IrOperand& source) {
    mark_partial(
        "bsf and bsr with a zero source leave the destination undefined; that case is not "
        "modelled");
    IrStatement statement;
    statement.dest = destination;
    statement.width = destination.width;
    statement.source_address = instruction.address;
    if (instruction.mnemonic == "bsf") {
      statement.op = IrOp::CountTrailingZeros;
      statement.a = source;
      push(block, std::move(statement));
      return;
    }
    const IrOperand leading = temp_operand(temporary_id(), destination.width);
    IrStatement count;
    count.op = IrOp::CountLeadingZeros;
    count.dest = leading;
    count.a = source;
    count.width = destination.width;
    count.source_address = instruction.address;
    push(block, std::move(count));
    statement.op = IrOp::Sub;
    statement.a = IrOperand::constant_value(static_cast<std::uint64_t>(destination.width) * 8U - 1U,
                                            destination.width);
    statement.b = leading;
    push(block, std::move(statement));
  }

  /// bt, bts, btr and btc with a register destination and a register or immediate
  /// bit index. CF becomes the selected bit, and the other flags are undefined.
  /// The IR states CF as `0 <u bit`, which is the CarryOnly state. bts, btr and
  /// btc then set, clear or flip that bit. A memory destination, whose bit can
  /// lie outside the operand, is Unsupported.
  void lift_bit_test(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    flags_state = FlagsState::Unknown;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        (operands[1].kind != OperandKind::Register && operands[1].kind != OperandKind::Immediate)) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand value = to_ir_operand(operands[0], instruction, pointer_width);
    if (value.width != 4 && value.width != 8) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = value.width;
    const std::uint64_t mask_bits = static_cast<std::uint64_t>(width) * 8U - 1U;
    const auto emit = [&](IrOp op, const IrOperand& dest, const IrOperand& a, const IrOperand& b,
                          IrCondition condition) {
      IrStatement statement;
      statement.op = op;
      statement.dest = dest;
      statement.a = a;
      statement.b = b;
      statement.condition = condition;
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    IrOperand index = IrOperand::constant_value(0, width);
    if (operands[1].kind == OperandKind::Immediate) {
      index = IrOperand::constant_value(
          static_cast<std::uint64_t>(operands[1].immediate) & mask_bits, width);
    } else {
      // A register index is taken modulo the operand width.
      const IrOperand selector = to_ir_operand(operands[1], instruction, pointer_width);
      if (selector.width != width) {
        unsupported(block, instruction);
        return;
      }
      const IrOperand masked = temp_operand(temporary_id(), width);
      emit(IrOp::And, masked, selector, IrOperand::constant_value(mask_bits, width),
           IrCondition::None);
      index = masked;
    }
    const IrOperand shifted = temp_operand(temporary_id(), width);
    emit(IrOp::Shr, shifted, value, index, IrCondition::None);
    const IrOperand bit = temp_operand(temporary_id(), width);
    emit(IrOp::And, bit, shifted, IrOperand::constant_value(1, width), IrCondition::None);
    // CF = bit, which is `0 <u bit`.
    emit(IrOp::Compare, IrOperand::none(), IrOperand::constant_value(0, width), bit,
         IrCondition::UnsignedLess);
    flags_state = FlagsState::CarryOnly;
    if (instruction.mnemonic == "bt") {
      return;
    }
    // bts sets the selected bit, btr clears it and btc flips it. CF was read into
    // `bit` above, so the write does not change it.
    const IrOperand mask = temp_operand(temporary_id(), width);
    emit(IrOp::Shl, mask, IrOperand::constant_value(1, width), index, IrCondition::None);
    if (instruction.mnemonic == "bts") {
      emit(IrOp::Or, value, value, mask, IrCondition::None);
    } else if (instruction.mnemonic == "btc") {
      emit(IrOp::Xor, value, value, mask, IrCondition::None);
    } else {
      // btr: AND with the complement of the mask.
      const std::uint64_t all_ones = width == 8 ? ~0ULL : 0xFFFF'FFFFULL;
      const IrOperand clear = temp_operand(temporary_id(), width);
      emit(IrOp::Xor, clear, mask, IrOperand::constant_value(all_ones, width), IrCondition::None);
      emit(IrOp::And, value, value, clear, IrCondition::None);
    }
  }

  /// movbe with a register and a memory operand: a load of the memory operand
  /// with its bytes reversed (`movbe reg, mem`), or the reverse, a store
  /// (`movbe mem, reg`). Only 32- and 64-bit forms are lifted; movbe leaves the
  /// flags alone.
  void lift_movbe(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 ||
        !((operands[0].kind == OperandKind::Register && operands[1].kind == OperandKind::Memory) ||
          (operands[0].kind == OperandKind::Memory && operands[1].kind == OperandKind::Register))) {
      unsupported(block, instruction);
      return;
    }
    const bool load = operands[0].kind == OperandKind::Register;
    const IrOperand register_operand =
        to_ir_operand(operands[load ? 0 : 1], instruction, pointer_width);
    const IrOperand memory_operand =
        to_ir_operand(operands[load ? 1 : 0], instruction, pointer_width);
    const std::uint8_t width = register_operand.width;
    if (width != 4 && width != 8) {
      unsupported(block, instruction);
      return;
    }
    if (load) {
      // reg = bswap(load(mem)).
      const IrOperand value = temp_operand(temporary_id(), width);
      IrStatement fetch;
      fetch.op = IrOp::Load;
      fetch.dest = value;
      fetch.a = memory_operand;
      fetch.width = width;
      fetch.source_address = instruction.address;
      push(block, std::move(fetch));
      IrStatement swap;
      swap.op = IrOp::ByteSwap;
      swap.dest = register_operand;
      swap.a = value;
      swap.width = width;
      swap.source_address = instruction.address;
      push(block, std::move(swap));
      return;
    }
    // store(mem, bswap(reg)).
    const IrOperand value = temp_operand(temporary_id(), width);
    IrStatement swap;
    swap.op = IrOp::ByteSwap;
    swap.dest = value;
    swap.a = register_operand;
    swap.width = width;
    swap.source_address = instruction.address;
    push(block, std::move(swap));
    IrStatement store;
    store.op = IrOp::Store;
    store.a = memory_operand;
    store.b = value;
    store.width = width;
    store.source_address = instruction.address;
    push(block, std::move(store));
  }

  /// mul / imul with one operand, and div / idiv, which use the implicit rax and
  /// rdx operands: rdx:rax = rax * source, or rax = rdx:rax / source and
  /// rdx = rdx:rax % source. The 8- and 16-bit forms use other registers and are
  /// Unsupported. The flags after these are not modelled.
  void lift_multiply_divide(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    flags_state = FlagsState::Unknown;
    if (operands.size() != 1 ||
        (operands[0].kind != OperandKind::Register && operands[0].kind != OperandKind::Memory)) {
      unsupported(block, instruction);
      return;
    }
    IrOperand source = to_ir_operand(operands[0], instruction, pointer_width);
    const std::uint8_t width = source.width;
    if (width != 4 && width != 8) {
      unsupported(block, instruction);
      return;
    }
    if (source.kind == IrOperandKind::Memory) {
      // The memory operand is read first, into a temporary of the operation's width.
      const IrOperand value = temp_operand(temporary_id(), width);
      IrStatement load;
      load.op = IrOp::Load;
      load.dest = value;
      load.a = source;
      load.width = width;
      load.source_address = instruction.address;
      push(block, std::move(load));
      source = value;
    }
    const IrOperand accumulator = IrOperand::register_ref(width == 8 ? "rax" : "eax", width);
    const IrOperand high = IrOperand::register_ref(width == 8 ? "rdx" : "edx", width);
    const auto emit = [&](IrOp op, const IrOperand& dest, const IrOperand& a, const IrOperand& b,
                          const IrOperand& c) {
      IrStatement statement;
      statement.op = op;
      statement.dest = dest;
      statement.a = a;
      statement.b = b;
      statement.c = c;
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    if (mnemonic == "mul" || mnemonic == "imul") {
      // Both halves are computed before either register is written.
      const bool is_signed = mnemonic == "imul";
      const IrOperand high_part = temp_operand(temporary_id(), width);
      const IrOperand low_part = temp_operand(temporary_id(), width);
      emit(is_signed ? IrOp::MulHighSigned : IrOp::MulHighUnsigned, high_part, accumulator, source,
           IrOperand::none());
      emit(IrOp::Mul, low_part, accumulator, source, IrOperand::none());
      emit(IrOp::Assign, high, high_part, IrOperand::none(), IrOperand::none());
      emit(IrOp::Assign, accumulator, low_part, IrOperand::none(), IrOperand::none());
      return;
    }
    const bool is_signed = mnemonic == "idiv";
    const IrOperand quotient = temp_operand(temporary_id(), width);
    const IrOperand remainder = temp_operand(temporary_id(), width);
    emit(is_signed ? IrOp::DivSigned : IrOp::DivUnsigned, quotient, high, accumulator, source);
    emit(is_signed ? IrOp::RemSigned : IrOp::RemUnsigned, remainder, high, accumulator, source);
    emit(IrOp::Assign, accumulator, quotient, IrOperand::none(), IrOperand::none());
    emit(IrOp::Assign, high, remainder, IrOperand::none(), IrOperand::none());
  }

  /// xchg reg, reg: a swap through a temporary. An exchange leaves the flags alone.
  /// Returns false when the exchange is Unsupported, which invalidates the flags.
  bool lift_exchange(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (!is_register_exchange(instruction)) {
      unsupported(block, instruction);  // with memory it needs a load and a store
      return false;
    }
    const IrOperand first = to_ir_operand(operands[0], instruction, pointer_width);
    const IrOperand second = to_ir_operand(operands[1], instruction, pointer_width);
    if (first.width != second.width) {
      unsupported(block, instruction);
      return false;
    }
    const IrOperand saved = temp_operand(temporary_id(), first.width);
    const auto assign = [&](const IrOperand& dest, const IrOperand& source) {
      IrStatement statement;
      statement.op = IrOp::Assign;
      statement.dest = dest;
      statement.a = source;
      statement.width = dest.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    assign(saved, first);
    assign(first, second);
    assign(second, saved);
    return true;
  }

  /// adc / sbb with a register destination: dest = dest +/- source +/- CF. The
  /// carry is read through the flag model, so it must be exact there: the last
  /// flag writer must have set CF (a compare, a test, or an add whose consumer
  /// reads CF). Otherwise the instruction is Unsupported, which makes the
  /// function Partial.
  void lift_add_with_carry(IrBlock& block, const Instruction& instruction,
                           std::optional<IrCondition> consumer) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const bool subtract = instruction.mnemonic == "sbb";
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        (operands[1].kind != OperandKind::Register && operands[1].kind != OperandKind::Immediate &&
         operands[1].kind != OperandKind::Memory) ||
        !flags_readable(IrCondition::Carry)) {
      flags_state = FlagsState::Unknown;
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    IrStatement statement;
    statement.op = subtract ? IrOp::SubBorrow : IrOp::AddCarry;
    statement.dest = destination;
    statement.a = destination;
    if (operands[1].kind == OperandKind::Memory) {
      // The memory operand is loaded first. A load leaves the flags alone.
      const IrOperand value = temp_operand(temporary_id(), destination.width);
      IrStatement load;
      load.op = IrOp::Load;
      load.dest = value;
      load.a = memory_operand(operands[1], instruction);
      load.width = destination.width;
      load.source_address = instruction.address;
      push(block, std::move(load));
      statement.b = value;
    } else {
      statement.b = to_ir_operand(operands[1], instruction, pointer_width);
    }
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
    flags_state = FlagsState::Unknown;  // the carry out is not modelled
    if (consumer) {
      push(block, flags_test_of(destination, instruction.address));
      flags_state = FlagsState::ZeroSign;
    }
  }

  /// neg / not.
  void lift_unary(IrBlock& block, const Instruction& instruction,
                  std::optional<IrCondition> consumer) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const bool negate = instruction.mnemonic == "neg";
    if (operands.size() != 1 || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    IrStatement statement;
    statement.op = negate ? IrOp::Sub : IrOp::Xor;
    statement.dest = destination;
    statement.a = negate ? IrOperand::constant_value(0, destination.width) : destination;
    statement.b = negate ? destination : IrOperand::constant_value(~0ULL, destination.width);
    statement.width = destination.width;
    statement.source_address = instruction.address;
    if (negate) {
      // 0 - x: operand `a` must have the destination's width.
      statement.a.width = destination.width;
    }
    push(block, std::move(statement));
    if (negate) {  // not leaves the flags alone
      flags_state = FlagsState::Unknown;
      if (consumer) {
        push(block, flags_test_of(destination, instruction.address));
        flags_state = FlagsState::ZeroSign;
      }
    }
  }

  /// cdqe / cwde / cbw (sign-extend in place) and cdq / cqo / cwd (fill the
  /// high register with the sign of the low one).
  void lift_sign_widen(IrBlock& block, const Instruction& instruction) {
    struct Form {
      const char* mnemonic;
      const char* dest;
      std::uint8_t dest_width;
      const char* source;
      std::uint8_t source_width;
      bool fill;
    };
    static const Form kForms[] = {
        {"cdqe", "rax", 8, "eax", 4, false}, {"cwde", "eax", 4, "ax", 2, false},
        {"cbw", "ax", 2, "al", 1, false},    {"cqo", "rdx", 8, "rax", 8, true},
        {"cdq", "edx", 4, "eax", 4, true},   {"cwd", "dx", 2, "ax", 2, true},
    };
    for (const Form& form : kForms) {
      if (instruction.mnemonic != form.mnemonic) {
        continue;
      }
      IrStatement statement;
      statement.dest = IrOperand::register_ref(form.dest, form.dest_width);
      statement.width = form.dest_width;
      statement.source_address = instruction.address;
      if (form.fill) {
        statement.op = IrOp::Sar;
        statement.a = IrOperand::register_ref(form.source, form.source_width);
        statement.b = IrOperand::constant_value(form.source_width * 8U - 1U, 1);
      } else {
        statement.op = IrOp::SignExtend;
        statement.a = IrOperand::register_ref(form.source, form.source_width);
      }
      push(block, std::move(statement));
      return;
    }
    unsupported(block, instruction);
  }

  /// rol / ror by an immediate: two shifts and an or through temporaries.
  void lift_rotate(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Immediate) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand value = to_ir_operand(operands[0], instruction, pointer_width);
    if (value.width == 0) {
      // No modelled width: a zero width must not reach the modulo below.
      unsupported(block, instruction);
      return;
    }
    const unsigned bits = value.width * 8U;
    const unsigned count = static_cast<unsigned>(operands[1].immediate) % bits;
    flags_state = FlagsState::Unknown;  // CF/OF change, ZF does not: not modelled
    if (count == 0) {
      return;
    }
    const bool left = instruction.mnemonic == "rol";
    const IrOperand high = temp_operand(temporary_id(), value.width);
    const IrOperand low = temp_operand(temporary_id(), value.width);
    IrStatement first;
    first.op = left ? IrOp::Shl : IrOp::Shr;
    first.dest = high;
    first.a = value;
    first.b = IrOperand::constant_value(count, 1);
    first.width = value.width;
    first.source_address = instruction.address;
    push(block, std::move(first));
    IrStatement second;
    second.op = left ? IrOp::Shr : IrOp::Shl;
    second.dest = low;
    second.a = value;
    second.b = IrOperand::constant_value(bits - count, 1);
    second.width = value.width;
    second.source_address = instruction.address;
    push(block, std::move(second));
    IrStatement combine;
    combine.op = IrOp::Or;
    combine.dest = value;
    combine.a = high;
    combine.b = low;
    combine.width = value.width;
    combine.source_address = instruction.address;
    push(block, std::move(combine));
  }

  /// cmovcc (dest = src if cond) and setcc (dest = cond ? 1 : 0).
  void lift_conditional(IrBlock& block, const Instruction& instruction, bool set) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const IrCondition condition = suffix_condition(instruction.mnemonic, set ? 3U : 4U);
    if (!flags_readable(condition)) {
      mark_partial("'" + instruction.mnemonic + "' reads flags this lifter does not model");
    }
    if ((set && operands.size() != 1) || (!set && operands.size() != 2) ||
        operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    if (set) {
      IrStatement clear;
      clear.op = IrOp::Assign;
      clear.dest = destination;
      clear.a = IrOperand::constant_value(0, destination.width);
      clear.width = destination.width;
      clear.source_address = instruction.address;
      push(block, std::move(clear));
    } else if (destination.width == 4) {
      // A 32-bit cmov zero-extends its destination even when it does not
      // move: model that before the conditional part.
      IrStatement widen;
      widen.op = IrOp::Assign;
      widen.dest = destination;
      widen.a = destination;
      widen.width = destination.width;
      widen.source_address = instruction.address;
      push(block, std::move(widen));
    }
    IrStatement statement;
    statement.op = IrOp::CondAssign;
    statement.condition = condition;
    statement.dest = destination;
    statement.a = set ? IrOperand::constant_value(1, destination.width)
                      : to_ir_operand(operands[1], instruction, pointer_width);
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  static bool is_xmm(const Operand& operand) {
    return operand.kind == OperandKind::Register && operand.reg.rfind("xmm", 0) == 0;
  }

  IrStatement statement_of(IrOp op, IrOperand dest, IrOperand a, IrOperand b, std::uint8_t width,
                           const Instruction& instruction) const {
    IrStatement statement;
    statement.op = op;
    statement.dest = std::move(dest);
    statement.a = std::move(a);
    statement.b = std::move(b);
    statement.width = width;
    statement.source_address = instruction.address;
    return statement;
  }

  /// A source operand of `width` bytes: an XMM register, or a memory operand loaded
  /// into a temporary. Returns nullopt for anything else.
  std::optional<IrOperand> sse_source(IrBlock& block, const Instruction& instruction,
                                      const Operand& operand, std::uint8_t width) {
    if (is_xmm(operand)) {
      return IrOperand::register_ref(operand.reg, width);
    }
    if (operand.kind != OperandKind::Memory) {
      return std::nullopt;
    }
    const std::uint32_t id = temporary_id();
    IrOperand address = memory_operand(operand, instruction);
    address.width = width;
    push(block, statement_of(IrOp::Load, temp_operand(id, width), address, IrOperand::none(), width,
                             instruction));
    return temp_operand(id, width);
  }

  /// Writes a 4-byte value held in temporary `value` into bits 0 to 31 of `destination`.
  /// Bits 32 to 63 keep their old value, as the scalar single forms require.
  void merge_low_single(IrBlock& block, const Instruction& instruction, std::uint32_t value,
                        const std::string& destination) {
    const std::uint32_t widened = temporary_id();
    push(block, statement_of(IrOp::ZeroExtend, temp_operand(widened, 8), temp_operand(value, 4),
                             IrOperand::none(), 8, instruction));
    const std::uint32_t kept = temporary_id();
    push(block,
         statement_of(IrOp::And, temp_operand(kept, 8), IrOperand::register_ref(destination, 8),
                      IrOperand::constant_value(0xffffffff00000000ULL, 8), 8, instruction));
    IrStatement merge =
        statement_of(IrOp::Or, IrOperand::register_ref(destination, 8), temp_operand(kept, 8),
                     temp_operand(widened, 8), 8, instruction);
    merge.merged_width = 4;
    push(block, std::move(merge));
  }

  /// Writes a result of `width` bytes into the XMM register `destination`: a double
  /// replaces the low lane, and a single goes through the merge above.
  void write_xmm_scalar(IrBlock& block, const Instruction& instruction, IrStatement statement,
                        std::uint8_t width, const std::string& destination) {
    if (width == 8) {
      statement.dest = IrOperand::register_ref(destination, 8);
      push(block, std::move(statement));
      return;
    }
    const std::uint32_t id = temporary_id();
    statement.dest = temp_operand(id, 4);
    push(block, std::move(statement));
    merge_low_single(block, instruction, id, destination);
  }

  /// Lowers one of the scalar SSE instructions in is_scalar_sse. Returns false if
  /// the operands are not a form it models; the caller then marks the instruction
  /// Unsupported.
  bool lift_scalar_sse(IrBlock& block, const Instruction& instruction) {
    const std::string& m = instruction.mnemonic;
    const std::vector<Operand>& ops = instruction.structured_operands;
    if (ops.size() != 2) {
      return false;
    }
    const bool single = m.size() >= 2 && m.compare(m.size() - 2, 2, "ss") == 0;

    // Arithmetic and square root: dest = dest OP source (sqrt: dest = sqrt(source)).
    static const char* const kBinary[] = {"addss", "addsd", "subss", "subsd",
                                          "mulss", "mulsd", "divss", "divsd"};
    const bool binary = std::find(std::begin(kBinary), std::end(kBinary), m) != std::end(kBinary);
    if (binary || m == "sqrtss" || m == "sqrtsd") {
      const std::uint8_t width = single ? 4 : 8;
      if (!is_xmm(ops[0])) {
        return false;
      }
      const auto source = sse_source(block, instruction, ops[1], width);
      if (!source) {
        return false;
      }
      IrOp op = IrOp::FSqrt;
      if (m.rfind("add", 0) == 0) op = IrOp::FAdd;
      if (m.rfind("sub", 0) == 0) op = IrOp::FSub;
      if (m.rfind("mul", 0) == 0) op = IrOp::FMul;
      if (m.rfind("div", 0) == 0) op = IrOp::FDiv;
      IrStatement statement =
          statement_of(op, IrOperand::none(), IrOperand::register_ref(ops[0].reg, width),
                       binary ? *source : IrOperand::none(), width, instruction);
      if (op == IrOp::FSqrt) {
        statement.a = *source;
      }
      statement.float_model = IrFloatModel::X86;
      mark_rounding_dependent();
      write_xmm_scalar(block, instruction, std::move(statement), width, ops[0].reg);
      return true;
    }

    // Scalar moves. The register form keeps the bits the instruction does not write.
    if (m == "movss" || m == "movsd") {
      const std::uint8_t width = single ? 4 : 8;
      if (is_xmm(ops[0]) && is_xmm(ops[1])) {
        if (width == 8) {
          push(block, statement_of(IrOp::Assign, IrOperand::register_ref(ops[0].reg, 8),
                                   IrOperand::register_ref(ops[1].reg, 8), IrOperand::none(), 8,
                                   instruction));
        } else {
          const std::uint32_t id = temporary_id();
          push(block, statement_of(IrOp::Assign, temp_operand(id, 4),
                                   IrOperand::register_ref(ops[1].reg, 4), IrOperand::none(), 4,
                                   instruction));
          merge_low_single(block, instruction, id, ops[0].reg);
        }
        return true;
      }
      if (is_xmm(ops[0]) && ops[1].kind == OperandKind::Memory) {
        // A load zeroes the rest of the register, as the architecture does: the low lane
        // gets the loaded value (a single zero-extends within the low lane) and the high
        // lane becomes zero.
        IrOperand address = memory_operand(ops[1], instruction);
        address.width = width;
        push(block, statement_of(IrOp::Load, IrOperand::register_ref(ops[0].reg, width), address,
                                 IrOperand::none(), width, instruction));
        push(block,
             statement_of(IrOp::Assign, IrOperand::register_ref(high_lane(ops[0].reg), 8),
                          IrOperand::constant_value(0, 8), IrOperand::none(), 8, instruction));
        return true;
      }
      if (ops[0].kind == OperandKind::Memory && is_xmm(ops[1])) {
        IrOperand address = memory_operand(ops[0], instruction);
        address.width = width;
        push(block, statement_of(IrOp::Store, IrOperand::none(), address,
                                 IrOperand::register_ref(ops[1].reg, width), width, instruction));
        return true;
      }
      return false;
    }
    if ((m == "movaps" || m == "movapd") && is_xmm(ops[0]) && is_xmm(ops[1])) {
      // Copies all 128 bits: the low lane and the high lane.
      push(block,
           statement_of(IrOp::Assign, IrOperand::register_ref(ops[0].reg, 8),
                        IrOperand::register_ref(ops[1].reg, 8), IrOperand::none(), 8, instruction));
      push(block, statement_of(IrOp::Assign, IrOperand::register_ref(high_lane(ops[0].reg), 8),
                               IrOperand::register_ref(high_lane(ops[1].reg), 8), IrOperand::none(),
                               8, instruction));
      return true;
    }

    // Conversions between integers and floats.
    if (m == "cvtsi2ss" || m == "cvtsi2sd") {
      mark_rounding_dependent();
      if (!is_xmm(ops[0])) {
        return false;
      }
      const std::uint8_t width = single ? 4 : 8;
      std::uint8_t integer_width = 0;
      std::optional<IrOperand> source;
      if (ops[1].kind == OperandKind::Register) {
        integer_width = register_width(ops[1].reg);
        source = IrOperand::register_ref(ops[1].reg, integer_width);
      } else if (ops[1].kind == OperandKind::Memory) {
        integer_width = ops[1].size;
        if (integer_width == 4 || integer_width == 8) {
          source = sse_source(block, instruction, ops[1], integer_width);
        }
      }
      if (!source || (integer_width != 4 && integer_width != 8)) {
        return false;
      }
      write_xmm_scalar(block, instruction,
                       statement_of(IrOp::IntToFloat, IrOperand::none(), *source, IrOperand::none(),
                                    width, instruction),
                       width, ops[0].reg);
      return true;
    }
    if (m == "cvttss2si" || m == "cvttsd2si") {
      if (ops[0].kind != OperandKind::Register) {
        return false;
      }
      const std::uint8_t integer_width = register_width(ops[0].reg);
      const std::uint8_t width = m == "cvttss2si" ? 4 : 8;
      if (integer_width != 4 && integer_width != 8) {
        return false;
      }
      const auto source = sse_source(block, instruction, ops[1], width);
      if (!source) {
        return false;
      }
      IrStatement statement =
          statement_of(IrOp::FloatToInt, IrOperand::register_ref(ops[0].reg, integer_width),
                       *source, IrOperand::none(), integer_width, instruction);
      statement.float_model = IrFloatModel::X86;
      push(block, std::move(statement));
      return true;
    }
    if (m == "cvtss2sd" || m == "cvtsd2ss") {
      if (!is_xmm(ops[0])) {
        return false;
      }
      const bool widen = m == "cvtss2sd";
      const auto source = sse_source(block, instruction, ops[1], widen ? 4 : 8);
      if (!source) {
        return false;
      }
      write_xmm_scalar(
          block, instruction,
          statement_of(widen ? IrOp::FloatExtend : IrOp::FloatTruncate, IrOperand::none(), *source,
                       IrOperand::none(), widen ? 8 : 4, instruction),
          widen ? 8 : 4, ops[0].reg);
      return true;
    }

    // Comparisons set the flags as ucomis* and comis* do.
    if (is_sse_compare(m)) {
      if (!is_xmm(ops[0])) {
        return false;
      }
      const std::uint8_t width = single ? 4 : 8;
      const auto source = sse_source(block, instruction, ops[1], width);
      if (!source) {
        return false;
      }
      IrStatement statement =
          statement_of(IrOp::FCompare, IrOperand::none(),
                       IrOperand::register_ref(ops[0].reg, width), *source, width, instruction);
      statement.float_model = IrFloatModel::X86;
      push(block, std::move(statement));
      return true;
    }

    // Zeroing idioms: xorps x, x and pxor x, x set both lanes to zero.
    if ((m == "xorps" || m == "xorpd" || m == "pxor") && is_xmm(ops[0]) && is_xmm(ops[1]) &&
        ops[0].reg == ops[1].reg) {
      push(block, statement_of(IrOp::Assign, IrOperand::register_ref(ops[0].reg, 8),
                               IrOperand::constant_value(0, 8), IrOperand::none(), 8, instruction));
      push(block, statement_of(IrOp::Assign, IrOperand::register_ref(high_lane(ops[0].reg), 8),
                               IrOperand::constant_value(0, 8), IrOperand::none(), 8, instruction));
      return true;
    }

    // cmpltsd x, y: the low lane of x becomes all ones when x < y and zero otherwise, and an
    // unordered comparison is false. The flags of ucomisd y, x say y > x, which is false when the
    // operands are unordered, so the mask is the "above" condition over them. The high lane is
    // kept. cmpltsd does not change the flags, but the flags of the compare above replace them in
    // the IR, so they are not kept (see preserves_flags).
    if (m == "cmpltsd" && is_xmm(ops[0]) && is_xmm(ops[1])) {
      IrStatement compare =
          statement_of(IrOp::FCompare, IrOperand::none(), IrOperand::register_ref(ops[1].reg, 8),
                       IrOperand::register_ref(ops[0].reg, 8), 8, instruction);
      compare.float_model = IrFloatModel::X86;
      push(block, std::move(compare));
      const std::uint32_t mask = temporary_id();
      push(block, statement_of(IrOp::Assign, temp_operand(mask, 8), IrOperand::constant_value(0, 8),
                               IrOperand::none(), 8, instruction));
      IrStatement select;
      select.op = IrOp::CondAssign;
      select.condition = IrCondition::UnsignedGreater;
      select.dest = temp_operand(mask, 8);
      select.a = IrOperand::constant_value(~0ULL, 8);
      select.width = 8;
      select.source_address = instruction.address;
      push(block, std::move(select));
      push(block, statement_of(IrOp::Assign, IrOperand::register_ref(ops[0].reg, 8),
                               temp_operand(mask, 8), IrOperand::none(), 8, instruction));
      return true;
    }

    // Packed logical operations on two registers. Each lane is combined with the same lane of
    // the source, so both lanes are modelled. andn is ~dest & source.
    const bool logical = m == "andps" || m == "andpd" || m == "andnps" || m == "andnpd" ||
                         m == "orps" || m == "orpd" || m == "xorps" || m == "xorpd" || m == "pxor";
    if (logical && is_xmm(ops[0]) && is_xmm(ops[1])) {
      const bool negate = m == "andnps" || m == "andnpd";
      const IrOp op = m[0] == 'a' ? IrOp::And : (m[0] == 'o' ? IrOp::Or : IrOp::Xor);
      for (const bool high : {false, true}) {
        const std::string destination = high ? high_lane(ops[0].reg) : ops[0].reg;
        const std::string source = high ? high_lane(ops[1].reg) : ops[1].reg;
        IrOperand left = IrOperand::register_ref(destination, 8);
        if (negate) {
          const std::uint32_t id = temporary_id();
          push(block, statement_of(IrOp::Xor, temp_operand(id, 8), left,
                                   IrOperand::constant_value(~0ULL, 8), 8, instruction));
          left = temp_operand(id, 8);
        }
        push(block, statement_of(op, IrOperand::register_ref(destination, 8), left,
                                 IrOperand::register_ref(source, 8), 8, instruction));
      }
      return true;
    }
    return false;
  }

  void lift_compare(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Compare;
    statement.a = to_ir_operand(operands[0], instruction, pointer_width);
    statement.b = to_ir_operand(operands[1], instruction, pointer_width);
    statement.condition = IrCondition::Equal;
    statement.width = statement.a.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_test(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Test;
    statement.a = to_ir_operand(operands[0], instruction, pointer_width);
    statement.b = to_ir_operand(operands[1], instruction, pointer_width);
    statement.width = statement.a.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_push(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 1) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand source = to_ir_operand(operands[0], instruction, pointer_width);
    if (source.kind == IrOperandKind::None) {
      // An operand this lifter cannot model would produce malformed IR.
      unsupported(block, instruction);
      return;
    }
    IrStatement decrement;
    decrement.op = IrOp::Sub;
    decrement.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    decrement.a = IrOperand::register_ref(stack_pointer, pointer_width);
    decrement.b = IrOperand::constant_value(pointer_width, pointer_width);
    decrement.width = pointer_width;
    decrement.source_address = instruction.address;
    push(block, std::move(decrement));

    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = stack_pointer;
    slot.width = pointer_width;
    IrStatement store;
    store.op = IrOp::Store;
    store.a = slot;
    store.b = source;
    store.width = pointer_width;
    store.source_address = instruction.address;
    push(block, std::move(store));
  }

  void lift_pop(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 1) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    if (destination.kind != IrOperandKind::Register) {
      // pop with a memory destination would need a load/store pair; model it
      // as unsupported rather than emitting a Load with no register result.
      unsupported(block, instruction);
      return;
    }
    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = stack_pointer;
    slot.width = pointer_width;
    IrStatement load;
    load.op = IrOp::Load;
    load.dest = destination;
    load.a = slot;
    load.width = pointer_width;
    load.source_address = instruction.address;
    push(block, std::move(load));

    IrStatement increment;
    increment.op = IrOp::Add;
    increment.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.a = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.b = IrOperand::constant_value(pointer_width, pointer_width);
    increment.width = pointer_width;
    increment.source_address = instruction.address;
    push(block, std::move(increment));
  }

  void lift_leave(IrBlock& block, const Instruction& instruction) {
    IrStatement restore_stack;
    restore_stack.op = IrOp::Assign;
    restore_stack.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    restore_stack.a = IrOperand::register_ref(frame_pointer, pointer_width);
    restore_stack.width = pointer_width;
    restore_stack.source_address = instruction.address;
    push(block, std::move(restore_stack));

    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = stack_pointer;
    slot.width = pointer_width;
    IrStatement load;
    load.op = IrOp::Load;
    load.dest = IrOperand::register_ref(frame_pointer, pointer_width);
    load.a = slot;
    load.width = pointer_width;
    load.source_address = instruction.address;
    push(block, std::move(load));

    IrStatement increment;
    increment.op = IrOp::Add;
    increment.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.a = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.b = IrOperand::constant_value(pointer_width, pointer_width);
    increment.width = pointer_width;
    increment.source_address = instruction.address;
    push(block, std::move(increment));
  }

  /// The summary of the callee of a direct call to a function of this image (G21-T2), when the
  /// call resolves: the callee is Positive at the budget the calling function's lift is asked with
  /// one less. The call's answer is recorded on the calling function's frame.
  std::optional<KnownCallee> known_callee(const Instruction& instruction) const {
    if (image.architecture != Architecture::X86_64 || !options.resolve_calls ||
        !options.call_summaries || !instruction.direct_target.has_value()) {
      return std::nullopt;
    }
    CallSummaryCache::Impl& cache = CallSummaryAccess::impl(*options.call_summaries);
    if (cache.path.empty()) {
      return std::nullopt;
    }
    const std::size_t caller = cache.path.size() - 1;
    const std::uint64_t budget = cache.path[caller].budget - 1;
    const Answer answer =
        answer_for(image, analysis, instruction.direct_target.value(), budget, options);
    // The query may have reallocated the path, so the caller's frame is found by index again.
    if (answer.verdict == Verdict::Negative) {
      cache.path[caller].saw_negative = true;
    } else if (answer.verdict == Verdict::Cut) {
      cache.path[caller].saw_cut = true;
    }
    if (answer.verdict != Verdict::Positive) {
      return std::nullopt;
    }
    return *answer.summary;
  }

  /// Gives a call statement the callee's signature: the arguments are the caller's registers at the
  /// call, in the callee's ABI order, and the result is the whole of rax. Reads after the call are
  /// checked by check_call_clobbers, not assumed here.
  static void resolve_call_statement(IrStatement& statement, const KnownCallee& callee) {
    for (const IrParameter& parameter : callee.parameters) {
      statement.call_arguments.push_back(IrOperand::register_ref(
          parameter.abi_register, parameter.width == 0 ? 8 : parameter.width));
    }
    if (callee.return_width > 0) {
      // After the call, the caller's rax is the callee's rax: all 64 bits, whatever width the
      // callee's return value has. The inferred width (from the callee's last write in block
      // order) can be narrower than what a path leaves in rax (`mov eax, 0x100; mov al, 1` leaves
      // 0x101 with a width of 1), so a write of that width would keep stale bits of the caller's
      // rax above it.
      statement.dest = IrOperand::register_ref("rax", 8);
    }
    statement.signature_inferred = true;
    statement.call_writes = callee.writes;
  }

  /// The library prototype of a direct call's target (G22-T4): x86-64 System V only (ELF and
  /// Mach-O; a Windows x64 call passes its arguments in other registers).
  const CallPrototype* library_prototype(const Instruction& instruction) const {
    if (image.architecture != Architecture::X86_64 || image.format == BinaryFormat::Pe ||
        !instruction.direct_target.has_value() || options.call_prototypes.empty()) {
      return nullptr;
    }
    const auto found = options.call_prototypes.find(instruction.direct_target.value());
    if (found == options.call_prototypes.end() ||
        found->second.parameter_widths.size() > kSystemVArguments.size()) {
      return nullptr;
    }
    for (const std::uint8_t width : found->second.parameter_widths) {
      if (width == 0 || width > 8) {
        return nullptr;
      }
    }
    return found->second.return_width > 8 ? nullptr : &found->second;
  }

  static constexpr std::array<const char*, 6> kSystemVArguments = {"rdi", "rsi", "rdx",
                                                                   "rcx", "r8",  "r9"};

  /// Gives a call the arguments and result of a library prototype: the System V argument
  /// registers in order, each as wide as its parameter, and rax for a result. An argument register
  /// past the prototype's parameters that this block writes and does not read before the call is
  /// reported as a possible mismatch: the write may be dead code, so it is not taken as an
  /// argument, and the prototype is applied as written.
  void apply_library_prototype(const IrBlock& block, IrStatement& statement,
                               const CallPrototype& prototype) {
    for (std::size_t index = 0; index < prototype.parameter_widths.size(); ++index) {
      statement.call_arguments.push_back(
          IrOperand::register_ref(kSystemVArguments[index], prototype.parameter_widths[index]));
    }
    if (prototype.return_width > 0) {
      statement.dest = IrOperand::register_ref("rax", 8);
    }
    statement.signature_source = prototype.source;
    std::set<std::string> extra;
    for (std::size_t index = prototype.parameter_widths.size(); index < kSystemVArguments.size();
         ++index) {
      extra.insert(kSystemVArguments[index]);
    }
    if (prototype.variadic) {
      return;  // a variadic callee may read any of them
    }
    std::set<std::string> read_later;
    std::set<std::string> written_later;
    for (std::size_t at = block.statements.size(); at-- > 0;) {
      const IrStatement& earlier = block.statements[at];
      if (earlier.op == IrOp::Call) {
        break;  // a value set before an earlier call is that call's business
      }
      if (earlier.dest.kind == IrOperandKind::Register && !earlier.dest.reg.empty()) {
        const std::string family = internal::register_family(earlier.dest.reg);
        if (extra.contains(family) && !read_later.contains(family) &&
            !written_later.contains(family)) {
          note("possible argument mismatch: " + family + " is written at " +
               hex_address(earlier.source_address) + " and not read before the call at " +
               hex_address(statement.source_address) + ", whose prototype has " +
               std::to_string(prototype.parameter_widths.size()) + " parameter(s)");
        }
        written_later.insert(family);
      }
      const auto add_read = [&](const IrOperand& operand) {
        if (operand.kind == IrOperandKind::Register && !operand.reg.empty()) {
          read_later.insert(internal::register_family(operand.reg));
        } else if (operand.kind == IrOperandKind::Memory) {
          if (!operand.reg.empty()) read_later.insert(internal::register_family(operand.reg));
          if (!operand.index.empty()) read_later.insert(internal::register_family(operand.index));
        }
      };
      if (earlier.dest.kind == IrOperandKind::Memory) {
        add_read(earlier.dest);
      }
      add_read(earlier.a);
      add_read(earlier.b);
      add_read(earlier.c);
    }
  }

  /// The model of the C function a call target runs (G21-T7): the target is an import stub or a
  /// GOT or IAT slot (`call *slot`) of an import the analysis shows binds to the C library, and
  /// the function has a model. x86-64 only: the System V or Win64 argument registers.
  [[nodiscard]] const LibcModel* modelled_call(const IrOperand& target) const {
    if (image.architecture != Architecture::X86_64) {
      return nullptr;
    }
    const bool direct = target.kind == IrOperandKind::Constant && target.constant != 0;
    const bool slot = target.kind == IrOperandKind::Memory && target.reg.empty() &&
                      target.index.empty() && target.width == pointer_width;
    if (!direct && !slot) {
      return nullptr;
    }
    const auto bound = analysis.c_library_imports.find(target.constant);
    return bound == analysis.c_library_imports.end() ? nullptr
                                                     : find_libc_model(bound->second.name);
  }

  /// Gives a call statement the C prototype of `model`: each argument in its register of the
  /// image's calling convention (an int in the register's low 32 bits), the result in all of rax.
  void resolve_model_call(IrStatement& statement, const LibcModel& model) const {
    static constexpr std::array<const char*, 3> kSysV64{"rdi", "rsi", "rdx"};
    static constexpr std::array<const char*, 3> kSysV32{"edi", "esi", "edx"};
    static constexpr std::array<const char*, 3> kWin64{"rcx", "rdx", "r8"};
    static constexpr std::array<const char*, 3> kWin32{"ecx", "edx", "r8d"};
    const bool win64 = image.format == BinaryFormat::Pe;
    for (std::size_t i = 0; i < model.arguments.size() && i < kSysV64.size(); ++i) {
      const bool narrow = model.arguments[i] == LibcArgument::Int;
      const char* name =
          win64 ? (narrow ? kWin32[i] : kWin64[i]) : (narrow ? kSysV32[i] : kSysV64[i]);
      statement.call_arguments.push_back(IrOperand::register_ref(name, narrow ? 4 : 8));
    }
    statement.dest = IrOperand::register_ref("rax", 8);
    statement.call_model = std::string(model.name);
  }

  void lift_call(IrBlock& block, const Instruction& instruction) {
    IrStatement statement;
    statement.op = IrOp::Call;
    statement.width = pointer_width;
    statement.source_address = instruction.address;
    if (instruction.direct_target.has_value()) {
      statement.a = IrOperand::constant_value(instruction.direct_target.value(), pointer_width);
    } else if (!instruction.structured_operands.empty()) {
      statement.a =
          to_ir_operand(instruction.structured_operands.front(), instruction, pointer_width);
    } else {
      statement.a = IrOperand::constant_value(0, pointer_width);
    }
    if (const LibcModel* model = modelled_call(statement.a)) {
      resolve_model_call(statement, *model);
      push(block, std::move(statement));
      return;
    }
    if (const auto callee = known_callee(instruction)) {
      resolve_call_statement(statement, *callee);
      push(block, std::move(statement));
      return;
    }
    if (const CallPrototype* prototype = library_prototype(instruction)) {
      apply_library_prototype(block, statement, *prototype);
      push(block, std::move(statement));
      // The callee is an import, with no body to run: the oracle cannot execute the call, so the
      // caller is not Complete (G22-T4). The arguments and the result are the prototype's.
      mark_partial_once(
          "a call to an imported function is not executed, so its caller is not verified");
      if (prototype->variadic) {
        mark_partial_once("a variadic call shows its fixed arguments only");
      }
      return;
    }
    push(block, std::move(statement));
    // The callee's effects on registers and memory are not modelled, so the
    // function cannot be Complete. The call itself stays in the IR.
    mark_partial("outgoing call arguments and return values follow no modelled ABI");
  }
};

/// What a returned value is, as the last definition before a return says.
struct ReturnDefinition {
  bool found = false;    // some path defined the return value
  bool unknown = false;  // a path reaches a call, an unmodelled write or the entry
  bool float_value = false;
  std::uint8_t width = 0;
};

ReturnDefinition join(const ReturnDefinition& a, const ReturnDefinition& b) {
  if (!a.found) {
    return b;
  }
  if (!b.found) {
    return a;
  }
  ReturnDefinition out = a;
  if (a.unknown || b.unknown || a.float_value != b.float_value) {
    out.unknown = true;
  } else if (a.width != b.width) {
    // A 4-byte integer write zero-extends into the whole register on x86-64 and AArch64, so it
    // defines the return value as an 8-byte write does: `mov eax, 0` on one path and `mov rax,
    // rdx` on the other return the full register. A narrower write keeps the other bytes, and a
    // floating-point width is part of the value's type, so those widths must match.
    if (a.float_value || a.width < 4 || b.width < 4) {
      out.unknown = true;
    } else {
      out.width = a.width > b.width ? a.width : b.width;
    }
  }
  return out;
}

/// The registers a function returns values in: the integer register and the
/// floating-point register, as register families (rax and xmm0, or x0 and v0).
struct ReturnRegisters {
  std::string integer_family;
  std::string float_family;
  bool aarch64 = false;
};

/// The name the IR uses for the floating-point return register at `width` bytes.
std::string float_return_name(const ReturnRegisters& regs, std::uint8_t width) {
  if (!regs.aarch64) {
    return "xmm0";
  }
  return width == 4 ? "s0" : "d0";
}

ReturnDefinition unknown_definition() {
  ReturnDefinition out;
  out.found = true;
  out.unknown = true;
  return out;
}

/// Successor blocks of block `index`, from its terminator and fall-through.
std::vector<std::size_t> successors_of(const IrFunction& function, std::size_t index) {
  std::vector<std::size_t> out;
  const IrBlock& block = function.blocks[index];
  bool falls_through = true;
  if (!block.statements.empty()) {
    const IrStatement& last = block.statements.back();
    if (last.op == IrOp::Branch) {
      out.push_back(last.a.block);
      falls_through = false;
    } else if (last.op == IrOp::CondBranch) {
      out.push_back(last.b.block);
    } else if (last.op == IrOp::Switch) {
      out.push_back(last.a.block);
      for (const IrSwitchCase& switch_case : last.switch_cases) {
        out.push_back(switch_case.target_block);
      }
      falls_through = false;
    } else if (last.op == IrOp::Return) {
      falls_through = false;
    }
  }
  if (falls_through && index + 1 < function.blocks.size()) {
    out.push_back(index + 1);
  }
  return out;
}

/// The last definition of rax (any width) or xmm0 among statements [0, end) of
/// `block`. A call or an unmodelled statement may define either, so it is unknown.
std::optional<ReturnDefinition> definition_in_block(const IrBlock& block, std::size_t end,
                                                    const ReturnRegisters& regs) {
  for (std::size_t s = end; s-- > 0;) {
    const IrStatement& statement = block.statements[s];
    // A resolved call (G21) that returns a value defines the integer return register: its result.
    // Any other call, and an unsupported statement, may define either register: unknown.
    if (statement.op == IrOp::Call &&
        (statement.signature_inferred || !statement.signature_source.empty() ||
         !statement.call_model.empty()) &&
        statement.dest.kind == IrOperandKind::Register &&
        internal::register_family(statement.dest.reg) == regs.integer_family) {
      ReturnDefinition out;
      out.found = true;
      out.width = statement.dest.width;
      return out;
    }
    if (statement.op == IrOp::Call || statement.op == IrOp::Unsupported) {
      return unknown_definition();
    }
    if (statement.dest.kind != IrOperandKind::Register || statement.dest.reg.empty()) {
      continue;
    }
    const std::string family = internal::register_family(statement.dest.reg);
    const bool integer = family == regs.integer_family;
    if (!integer && family != regs.float_family) {
      continue;
    }
    ReturnDefinition out;
    out.found = true;
    out.float_value = !integer;
    out.width = statement.dest.width != 0 ? statement.dest.width : statement.width;
    return out;
  }
  return std::nullopt;
}

/// The definition that reaches the start of block `index`, over every path back
/// through its predecessors. A path that reaches the function entry without a
/// definition carries an incoming value, which is unknown here. `visited` stops a
/// loop: a block searched already adds nothing, because the search that began there
/// covers its paths.
ReturnDefinition reaching_block_start(const IrFunction& function, std::size_t index,
                                      std::vector<bool>& visited, const ReturnRegisters& regs) {
  if (visited[index]) {
    return {};
  }
  visited[index] = true;
  ReturnDefinition joined;
  if (index == 0) {
    joined = join(joined, unknown_definition());  // the entry itself
  }
  bool has_predecessor = false;
  for (std::size_t p = 0; p < function.blocks.size(); ++p) {
    const auto successors = successors_of(function, p);
    if (std::find(successors.begin(), successors.end(), index) == successors.end()) {
      continue;
    }
    has_predecessor = true;
    const IrBlock& pred = function.blocks[p];
    if (const auto defined = definition_in_block(pred, pred.statements.size(), regs)) {
      joined = join(joined, *defined);
    } else {
      joined = join(joined, reaching_block_start(function, p, visited, regs));
    }
  }
  if (!has_predecessor && index != 0) {
    joined = join(joined, unknown_definition());  // unreachable from the entry
  }
  return joined;
}

/// Which return registers are written along some path to a return. A write is not killed
/// by a later one, so a write to rax and a write to xmm0 on one path make the return
/// channel ambiguous, whichever was written last. Walks back from statement `end` of block
/// `start` over every predecessor, once per block.
struct ReturnClasses {
  bool integer = false;
  bool floating = false;
};

ReturnClasses classes_reaching_return(const IrFunction& function, std::size_t start,
                                      std::size_t end, const ReturnRegisters& regs) {
  ReturnClasses out;
  std::vector<bool> visited(function.blocks.size(), false);
  std::vector<std::pair<std::size_t, std::size_t>> pending{{start, end}};
  while (!pending.empty()) {
    const auto [index, limit] = pending.back();
    pending.pop_back();
    const IrBlock& block = function.blocks[index];
    for (std::size_t s = 0; s < limit && s < block.statements.size(); ++s) {
      const IrStatement& statement = block.statements[s];
      if (statement.dest.kind != IrOperandKind::Register || statement.dest.reg.empty()) {
        continue;
      }
      const std::string family = internal::register_family(statement.dest.reg);
      if (family == regs.integer_family) {
        out.integer = true;
      } else if (family == regs.float_family) {
        out.floating = true;
      }
    }
    for (std::size_t p = 0; p < function.blocks.size(); ++p) {
      if (visited[p]) {
        continue;
      }
      const auto successors = successors_of(function, p);
      if (std::find(successors.begin(), successors.end(), index) == successors.end()) {
        continue;
      }
      visited[p] = true;
      pending.emplace_back(p, function.blocks[p].statements.size());
    }
  }
  return out;
}

/// Returns that carry a floating-point value leave it in xmm0, not rax. The lifter
/// emits rax for every return, so each return is resolved from the definitions that
/// reach it. When they disagree, or a path has no definition, the return stays rax
/// and the function is marked Partial.
void resolve_return_registers(IrFunction& function, const ReturnRegisters& regs) {
  for (std::size_t b = 0; b < function.blocks.size(); ++b) {
    IrBlock& block = function.blocks[b];
    for (std::size_t s = 0; s < block.statements.size(); ++s) {
      IrStatement& statement = block.statements[s];
      if (statement.op != IrOp::Return || statement.a.kind != IrOperandKind::Register ||
          internal::register_family(statement.a.reg) != regs.integer_family) {
        continue;
      }
      const ReturnClasses classes = classes_reaching_return(function, b, s, regs);
      if (classes.integer && classes.floating) {
        function.partial = true;
        function.notes.push_back("both " + regs.integer_family + " and " + regs.float_family +
                                 " are written on a path to this return; which one carries the "
                                 "return value is not determined, so " +
                                 regs.integer_family + " is assumed");
        continue;
      }
      ReturnDefinition found;
      if (const auto defined = definition_in_block(block, s, regs)) {
        found = *defined;
      } else {
        std::vector<bool> visited(function.blocks.size(), false);
        found = reaching_block_start(function, b, visited, regs);
      }
      if (!found.found || found.unknown) {
        function.partial = true;
        // Name the architecture's integer return register (rax, or x0 on AArch64).
        function.notes.push_back(
            "the returned register is not determined by the definitions that reach the return; " +
            regs.integer_family + " is assumed");
      } else if (found.float_value) {
        statement.a = IrOperand::register_ref(float_return_name(regs, found.width), found.width);
      }
    }
  }
}

}  // namespace

/// Integer and floating-point parameters are placed by their own registers, so the order
/// the source gives them is not recoverable from the registers they arrive in. The
/// evaluator places parameters in the order it has, so a function with both kinds is
/// Partial rather than Complete with an order that may be wrong.
void mark_mixed_parameters(IrFunction& function) {
  bool integer = false;
  bool floating = false;
  for (const IrParameter& parameter : function.parameters) {
    (parameter.floating_point ? floating : integer) = true;
  }
  if (integer && floating) {
    function.partial = true;
    function.notes.push_back(
        "integer and floating-point parameters are both present; their order in the source is "
        "not recoverable from the registers, so the signature is Partial");
  }
}

namespace {

/// Keeps only the blocks reachable from the function's entry by the modelled control flow, puts
/// the entry first, and states what was left out (G-audit Goal 4).
///
/// Two things made some functions fail the verifier with ir.unreachable_block. The CFG assigns a
/// function every block it reaches by a direct jump that stays inside it, and the lifter emits
/// them in address order. First, a jump that leaves the function is lifted as a tail call (a call
/// and a return, with no edge), so the code it reaches is not connected to the entry; those blocks
/// are removed here and the function is Partial, with their address ranges in a note. Second, the
/// verifier starts at block 0, but the entry is not always the lowest block: a block below it can
/// be reached from the entry (a PLT stub the CFG counts as part of the function). Then the entry
/// is placed behind a trampoline, a block at address 0 whose only statement branches to the entry.
/// The trampoline changes no state, so it does not make the function Partial.
///
/// Removing unreachable blocks keeps the fall-through of a conditional branch intact: a reachable
/// block's fall-through block is reachable, so it is never removed, and the two stay adjacent.
Result<bool> keep_blocks_reachable_from_entry(IrFunction& function, const AnalysisResult& analysis,
                                              FunctionId function_id, std::uint8_t pointer_width) {
  const std::size_t count = function.blocks.size();
  std::size_t entry = count;
  for (std::size_t i = 0; i < count; ++i) {
    if (function.blocks[i].address == function.address) {
      entry = i;
      break;
    }
  }
  if (entry == count) {
    return false;  // nothing to do: the verifier reports a missing entry
  }
  std::vector<bool> reachable(count, false);
  std::vector<std::size_t> work = {entry};
  reachable[entry] = true;
  const auto visit = [&](std::size_t target) {
    if (target < count && !reachable[target]) {
      reachable[target] = true;
      work.push_back(target);
    }
  };
  while (!work.empty()) {
    const std::size_t index = work.back();
    work.pop_back();
    const auto& statements = function.blocks[index].statements;
    if (statements.empty()) {
      continue;
    }
    const IrStatement& terminator = statements.back();
    switch (terminator.op) {
      case IrOp::Branch:
        if (terminator.a.kind == IrOperandKind::Block) {
          visit(terminator.a.block);
        }
        break;
      case IrOp::CondBranch:
        if (terminator.b.kind == IrOperandKind::Block) {
          visit(terminator.b.block);
        }
        visit(index + 1);  // the fall-through is the next block
        break;
      case IrOp::Switch:
        if (terminator.a.kind == IrOperandKind::Block) {
          visit(terminator.a.block);
        }
        for (const IrSwitchCase& sc : terminator.switch_cases) {
          visit(sc.target_block);
        }
        break;
      default:
        break;
    }
  }

  std::size_t removed = 0;
  for (std::size_t i = 0; i < count; ++i) {
    removed += reachable[i] ? 0 : 1;
  }
  // The printer and the evaluator start at block 0, so an entry that is not block 0 needs the
  // trampoline; a function whose entry is block 0 and has nothing unreachable is unchanged.
  if (removed == 0 && entry == 0) {
    return false;
  }

  // Ranges of the blocks left out, from the CFG's block ends.
  const auto hex_text = [](std::uint64_t value) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "%llx", static_cast<unsigned long long>(value));
    return std::string(buffer);
  };
  std::map<std::uint64_t, std::uint64_t> ends;
  for (const BasicBlock& block : analysis.cfg.blocks) {
    if (block.function == function_id) {
      ends[block.address] = block.end_address;
    }
  }
  std::vector<std::string> left_out;
  constexpr std::size_t kNamedRanges = 8;
  for (std::size_t i = 0; i < count && removed > 0; ++i) {
    if (reachable[i]) {
      continue;
    }
    const std::uint64_t start = function.blocks[i].address;
    const auto end = ends.find(start);
    if (left_out.size() < kNamedRanges) {
      left_out.push_back(end != ends.end() && end->second > start
                             ? "0x" + hex_text(start) + "..0x" + hex_text(end->second)
                             : "0x" + hex_text(start));
    }
  }

  // New indices: the trampoline (when there is one) is block 0, and the reachable blocks follow
  // in their original order.
  const std::uint32_t offset = entry == 0 ? 0 : 1;
  std::vector<std::uint32_t> new_index(count, 0);
  std::uint32_t next = offset;
  for (std::size_t i = 0; i < count; ++i) {
    if (reachable[i]) {
      new_index[i] = next++;
    }
  }
  std::vector<IrBlock> kept;
  if (offset == 1) {
    IrBlock trampoline;
    trampoline.address = 0;  // no code lives at 0, so its label is unique
    IrStatement branch;
    branch.op = IrOp::Branch;
    branch.a = IrOperand::block_ref(new_index[entry]);
    branch.width = pointer_width;
    branch.source_address = function.address;
    trampoline.statements.push_back(std::move(branch));
    kept.push_back(std::move(trampoline));
  }
  for (std::size_t i = 0; i < count; ++i) {
    if (!reachable[i]) {
      continue;
    }
    IrBlock block = std::move(function.blocks[i]);
    for (IrStatement& statement : block.statements) {
      // An out-of-range reference is left as it is; the verifier reports it.
      for (IrOperand* operand : {&statement.a, &statement.b, &statement.c}) {
        if (operand->kind == IrOperandKind::Block && operand->block < count) {
          operand->block = new_index[operand->block];
        }
      }
      for (IrSwitchCase& sc : statement.switch_cases) {
        if (sc.target_block < count) {
          sc.target_block = new_index[sc.target_block];
        }
      }
    }
    kept.push_back(std::move(block));
  }
  function.blocks = std::move(kept);
  if (removed > 0) {
    function.partial = true;
    std::string list;
    for (const std::string& range : left_out) {
      list += (list.empty() ? "" : ", ") + range;
    }
    if (removed > left_out.size()) {
      list += ", and " + std::to_string(removed - left_out.size()) + " more";
    }
    function.notes.push_back(
        std::to_string(removed) +
        " block(s) are not reached by modelled control flow from the entry and are not shown "
        "(a jump out of the function is a tail call, so the code it reaches is not included): " +
        list);
  }
  return true;
}

}  // namespace

namespace {

/// The register families a statement reads: its register operands, the base and index of its
/// memory operands, and its call arguments.
void collect_reads(const IrStatement& statement, std::vector<std::string>& out) {
  const auto add = [&](const IrOperand& operand) {
    if (operand.kind == IrOperandKind::Register && !operand.reg.empty()) {
      out.push_back(internal::register_family(operand.reg));
    } else if (operand.kind == IrOperandKind::Memory) {
      if (!operand.reg.empty()) out.push_back(internal::register_family(operand.reg));
      if (!operand.index.empty()) out.push_back(internal::register_family(operand.index));
    }
  };
  if (statement.dest.kind == IrOperandKind::Memory) {
    add(statement.dest);  // a store's address is read; a register destination is only written
  }
  add(statement.a);
  add(statement.b);
  add(statement.c);
  for (const IrOperand& argument : statement.call_arguments) {
    add(argument);
  }
}

/// Checks that no caller-saved register is read after a call without a definition since that call
/// (G21-T1). A call clobbers them; the one register a call defines is its result. The check is a
/// forward dataflow over the blocks (a register is clobbered on a path if some path reaches the
/// read clobbered). A read of a clobbered register makes the function partial, with a note naming
/// the register. A function without calls is unchanged.
void check_call_clobbers_impl(IrFunction& function) {
  const std::size_t count = function.blocks.size();
  bool has_call = false;
  for (const IrBlock& block : function.blocks) {
    for (const IrStatement& statement : block.statements) {
      has_call = has_call || statement.op == IrOp::Call;
    }
  }
  if (!has_call || count == 0) {
    return;
  }
  using State = std::set<std::string>;
  // Successor blocks of each block, as the verifier's graph has them.
  std::vector<std::vector<std::size_t>> successors(count);
  for (std::size_t b = 0; b < count; ++b) {
    const auto& statements = function.blocks[b].statements;
    if (statements.empty()) {
      continue;
    }
    const IrStatement& terminator = statements.back();
    // A target outside the function is not a successor here (the verifier rejects it; this check
    // must not index past `in` either way).
    const auto add = [&](std::size_t target) {
      if (target < count) {
        successors[b].push_back(target);
      }
    };
    if (terminator.op == IrOp::Branch && terminator.a.kind == IrOperandKind::Block) {
      add(terminator.a.block);
    } else if (terminator.op == IrOp::CondBranch) {
      if (terminator.b.kind == IrOperandKind::Block) add(terminator.b.block);
      add(b + 1);
    } else if (terminator.op == IrOp::Switch) {
      if (terminator.a.kind == IrOperandKind::Block) add(terminator.a.block);
      for (const IrSwitchCase& sc : terminator.switch_cases) add(sc.target_block);
    }
  }
  // Simulates one block from `state`; with `report`, the first read of a clobbered register is
  // returned.
  const auto simulate = [&](const IrBlock& block, State& state,
                            std::optional<std::string>* report) {
    for (const IrStatement& statement : block.statements) {
      std::vector<std::string> reads;
      collect_reads(statement, reads);
      if (report != nullptr && !report->has_value()) {
        for (const std::string& family : reads) {
          if (state.count(family) != 0) {
            *report = family;
            break;
          }
        }
      }
      if (statement.op == IrOp::Call) {
        // A call clobbers the caller-saved families. A resolved call (its callee's IR is known and
        // complete) clobbers only the caller-saved families that callee writes; an unknown call
        // clobbers all of them. Then the call defines its result.
        const std::set<std::string>& kCallerSaved = caller_saved_families();
        if (statement.signature_inferred) {
          for (const std::string& family : statement.call_writes) {
            if (kCallerSaved.count(family) != 0) {
              state.insert(family);
            }
          }
        } else {
          state.insert(kCallerSaved.begin(), kCallerSaved.end());
        }
        if (statement.dest.kind == IrOperandKind::Register) {
          state.erase(internal::register_family(statement.dest.reg));
        }
      } else if (statement.dest.kind == IrOperandKind::Register && !statement.dest.reg.empty() &&
                 statement.op != IrOp::CondAssign &&
                 (statement.dest.width == 0 || statement.dest.width >= 4)) {
        // Only a write of the whole register defines it: a conditional assignment keeps the old
        // value when its condition is false, and an 8- or 16-bit write keeps the rest of the
        // register, so a clobber stays on those paths.
        state.erase(internal::register_family(statement.dest.reg));
      }
    }
  };
  std::vector<State> in(count);
  bool changed = true;
  while (changed) {
    changed = false;
    for (std::size_t b = 0; b < count; ++b) {
      State out = in[b];
      simulate(function.blocks[b], out, nullptr);
      for (const std::size_t successor : successors[b]) {
        const std::size_t before = in[successor].size();
        in[successor].insert(out.begin(), out.end());
        changed = changed || in[successor].size() != before;
      }
    }
  }
  for (std::size_t b = 0; b < count; ++b) {
    State state = in[b];
    std::optional<std::string> report;
    simulate(function.blocks[b], state, &report);
    if (report.has_value()) {
      function.partial = true;
      function.notes.push_back("register " + *report +
                               " is read after a call that does not define it; the value is not "
                               "the caller's, so the function is not Complete");
      return;
    }
  }
}

}  // namespace

namespace internal {

bool end_block_at_no_return_call(const AnalysisResult& analysis, IrBlock& block,
                                 std::uint8_t pointer_width) {
  if (block.statements.empty() || analysis.no_return.empty()) {
    return false;
  }
  IrStatement& call = block.statements.back();
  if (call.op != IrOp::Call) {
    return false;
  }
  const bool direct = call.a.kind == IrOperandKind::Constant && call.a.constant != 0;
  const bool slot =
      call.a.kind == IrOperandKind::Memory && call.a.reg.empty() && call.a.index.empty();
  if ((!direct && !slot) || !analysis.no_return.contains(call.a.constant)) {
    return false;
  }
  call.no_return = true;
  IrStatement end;
  end.op = IrOp::Return;
  end.unreachable = true;
  end.width = pointer_width;
  end.source_address = call.source_address;
  block.statements.push_back(std::move(end));
  return true;
}

void check_call_clobbers(IrFunction& function) {
  check_call_clobbers_impl(function);
}

Result<bool> keep_reachable_blocks(IrFunction& function, const AnalysisResult& analysis,
                                   FunctionId function_id, std::uint8_t pointer_width) {
  return keep_blocks_reachable_from_entry(function, analysis, function_id, pointer_width);
}

}  // namespace internal

namespace {

Result<IrFunction> lift_body(const BinaryImage& image, const AnalysisResult& analysis,
                             const Function& function, const LiftOptions& options) {
  if (image.architecture == Architecture::AArch64) {
    auto lifted = internal::lift_aarch64(image, analysis, function, options);
    if (lifted) {
      if (auto kept = keep_blocks_reachable_from_entry(lifted.value(), analysis, function.id, 8);
          !kept) {
        return make_error<IrFunction>(kept.diagnostic().status, kept.diagnostic().code,
                                      kept.diagnostic().message, function.address);
      }
      resolve_return_registers(lifted.value(), ReturnRegisters{"x0", "v0", true});
      internal::canonicalise_registers(lifted.value(), image.architecture);
      if (options.run_passes) {
        run_ir_passes(lifted.value(), PassOptions{image.architecture, image.format, {}});
        mark_mixed_parameters(lifted.value());
      }
    }
    return lifted;
  }
  if (image.architecture != Architecture::X86_64 && image.architecture != Architecture::X86) {
    return make_error<IrFunction>(
        Status::Unsupported, "lift.unsupported_architecture",
        "the lifter models x86, x86-64 and AArch64 only; no pseudocode is produced for other "
        "architectures",
        function.address);
  }

  Lifter lifter(image, analysis, function, options);

  for (const BasicBlock& block : analysis.cfg.blocks) {
    if (block.function == function.id) {
      lifter.blocks.push_back(&block);
    }
  }
  std::sort(lifter.blocks.begin(), lifter.blocks.end(),
            [](const BasicBlock* a, const BasicBlock* b) { return a->address < b->address; });

  if (lifter.blocks.size() > options.max_blocks) {
    return make_error<IrFunction>(Status::ResourceLimit, "lift.block_limit",
                                  "function exceeds the configured block limit", function.address);
  }
  if (lifter.blocks.empty()) {
    return make_error<IrFunction>(Status::Unsupported, "lift.no_blocks",
                                  "function has no decoded basic blocks", function.address);
  }

  for (std::size_t index = 0; index < lifter.blocks.size(); ++index) {
    lifter.block_by_address.emplace(lifter.blocks[index]->address,
                                    static_cast<std::uint32_t>(index));
  }

  lifter.out.address = function.address;
  lifter.out.name = function.name.empty() ? "sub" : function.name;
  lifter.out.partial = function.estimated;
  lifter.out.notes.push_back(
      image.architecture == Architecture::X86
          ? "x86-32 subset; register aliases are not canonicalised, cdecl stack arguments are "
            "not recovered and locals are not recovered"
          : "x86-64 subset; locals are not recovered");

  // Conditional branches whose target is outside this function (a conditional tail call): each
  // branches to an exit block, appended after the function's own blocks, that calls the target and
  // returns its result. They are patched once every block is lifted.
  struct ConditionalTailCall {
    std::size_t block = 0;
    std::size_t statement = 0;
    const Instruction* instruction = nullptr;
  };
  std::vector<ConditionalTailCall> conditional_tail_calls;

  for (const BasicBlock* block : lifter.blocks) {
    IrBlock out_block;
    out_block.address = block->address;
    // Flags carry from the previous block into this one when this block has no
    // other predecessor: the compare that set them is repeated here, from the
    // same operands, before anything else in the block.
    const Lifter::FlagsState entering = lifter.flags_state;
    lifter.flags_state = Lifter::FlagsState::Unknown;
    const std::uint32_t block_index = lifter.block_by_address.at(block->address);
    if (block_index > 0 && entering != Lifter::FlagsState::Unknown &&
        lifter.out.blocks.size() == block_index) {
      const BasicBlock& previous = *lifter.blocks[block_index - 1];
      if (previous.end_address == block->address) {
        const auto writer = lifter.carried_flag_writer(previous);
        if (writer && lifter.single_fallthrough_predecessor(previous, *block)) {
          const Instruction& compare = analysis.instructions[*writer];
          if (compare.mnemonic == "cmp") {
            lifter.lift_compare(out_block, compare);
          } else if (is_sse_compare(compare.mnemonic)) {
            if (!lifter.lift_scalar_sse(out_block, compare)) {
              lifter.unsupported(out_block, compare);
            }
          } else {
            lifter.lift_test(out_block, compare);
          }
          lifter.flags_state = entering;
        }
      }
    }

    // The condition the next flag reader in this block uses, if one reads the
    // flags written by instruction `i` before anything else writes them.
    auto next_consumer = [&](std::uint32_t i) -> std::optional<IrCondition> {
      for (std::uint32_t j = i + 1; j < block->instruction_count; ++j) {
        const std::size_t at = static_cast<std::size_t>(block->first_instruction) + j;
        if (at >= analysis.instructions.size()) {
          break;
        }
        const Instruction& next = analysis.instructions[at];
        if (next.mnemonic == "adc" || next.mnemonic == "sbb") {
          return IrCondition::Carry;  // reads CF only
        }
        if (is_register_exchange(next)) {
          continue;  // swaps two registers; the flags pass through
        }
        if (next.classification == InstructionClass::ConditionalJump) {
          return branch_condition(next.mnemonic);
        }
        if (is_cmov(next.mnemonic)) {
          return suffix_condition(next.mnemonic, 4);
        }
        if (is_setcc(next.mnemonic)) {
          return suffix_condition(next.mnemonic, 3);
        }
        if (!preserves_flags(next.mnemonic) || next.classification != InstructionClass::Other) {
          break;  // overwritten, or control leaves the block
        }
      }
      return std::nullopt;
    };

    for (std::uint32_t i = 0; i < block->instruction_count; ++i) {
      const std::size_t index = static_cast<std::size_t>(block->first_instruction) + i;
      if (index >= analysis.instructions.size()) {
        lifter.out.partial = true;
        break;
      }
      const Instruction& instruction = analysis.instructions[index];
      const std::string& mnemonic = instruction.mnemonic;

      // An fs- or gs-relative operand addresses the thread block, not the address its displacement
      // names. lea ignores the segment, so it keeps its meaning and is lifted as before.
      if (mnemonic != "lea" && has_segment_memory_operand(instruction)) {
        lifter.unsupported(out_block, instruction);
        lifter.mark_partial(kSegmentRelativeNote);
        lifter.flags_state = Lifter::FlagsState::Unknown;
        continue;
      }

      if (instruction.classification == InstructionClass::ConditionalJump) {
        IrCondition condition = branch_condition(mnemonic);
        IrStatement statement;
        statement.op = IrOp::CondBranch;
        statement.source_address = instruction.address;
        statement.width = lifter.pointer_width;
        statement.condition = condition;
        statement.a = IrOperand::register_ref("flags", lifter.pointer_width);
        if (!lifter.flags_readable(condition)) {
          lifter.mark_partial("conditional branch depends on flags this lifter does not model");
        }
        if (condition == IrCondition::None) {
          lifter.mark_partial("unsupported condition code '" + mnemonic + "'");
          condition = IrCondition::NonZero;
          statement.condition = condition;
        }
        const auto target = instruction.direct_target.has_value()
                                ? lifter.block_by_address.find(instruction.direct_target.value())
                                : lifter.block_by_address.end();
        if (target == lifter.block_by_address.end() && instruction.direct_target.has_value()) {
          // The target is another function's code: a conditional tail call. The branch goes to an
          // exit block that calls it; the block is made after the loop.
          statement.b = IrOperand::block_ref(0);
          lifter.push(out_block, std::move(statement));
          conditional_tail_calls.push_back(ConditionalTailCall{
              lifter.out.blocks.size(), out_block.statements.size() - 1, &instruction});
          continue;
        }
        if (target == lifter.block_by_address.end()) {
          lifter.mark_partial("conditional branch target is outside this function");
          statement.b = IrOperand::block_ref(0);
        } else {
          statement.b = IrOperand::block_ref(target->second);
        }
        lifter.push(out_block, std::move(statement));
        continue;
      }

      if (instruction.classification == InstructionClass::Jump) {
        IrStatement statement;
        statement.op = IrOp::Branch;
        statement.source_address = instruction.address;
        statement.width = lifter.pointer_width;
        const auto target = instruction.direct_target.has_value()
                                ? lifter.block_by_address.find(instruction.direct_target.value())
                                : lifter.block_by_address.end();
        const JumpTable* table = nullptr;
        if (!instruction.direct_target.has_value()) {
          for (const JumpTable& candidate : analysis.cfg.jump_tables) {
            if (candidate.jump_address == instruction.address) {
              table = &candidate;
            }
          }
        }
        if (table != nullptr) {
          // A jump table the analysis recovered from the bounds check and the
          // table bytes: a switch over the compared operand.
          const auto check =
              std::find_if(analysis.instructions.begin(), analysis.instructions.end(),
                           [&](const Instruction& candidate_instruction) {
                             return candidate_instruction.address == table->check_address;
                           });
          bool cases_in_function = check != analysis.instructions.end();
          IrStatement sw;
          sw.op = IrOp::Switch;
          sw.source_address = instruction.address;
          sw.width = lifter.pointer_width;
          if (cases_in_function) {
            sw.dest = to_ir_operand(table->selector, *check, lifter.pointer_width);
          }
          for (std::size_t value = 0; value < table->targets.size() && cases_in_function; ++value) {
            const auto block_it = lifter.block_by_address.find(table->targets[value]);
            if (block_it == lifter.block_by_address.end()) {
              cases_in_function = false;
              break;
            }
            sw.switch_cases.push_back(IrSwitchCase{value, block_it->second});
          }
          const auto fallback = lifter.block_by_address.find(table->default_target);
          if (cases_in_function && sw.dest.kind != IrOperandKind::None) {
            if (fallback != lifter.block_by_address.end()) {
              sw.a = IrOperand::block_ref(fallback->second);
            } else {
              // Out-of-range selectors were sent elsewhere by the bounds check
              // before this jump, so the default is unreachable here.
              sw.a = IrOperand::block_ref(sw.switch_cases.front().target_block);
            }
            lifter.push(out_block, std::move(sw));
            continue;
          }
          lifter.mark_partial("jump table cases lie outside this function");
        }
        if (target == lifter.block_by_address.end()) {
          // Tail call or an unmodelled target: stop here instead of inventing
          // a block. Calling the target is the honest reading.
          IrStatement call;
          call.op = IrOp::Call;
          call.source_address = instruction.address;
          call.width = lifter.pointer_width;
          if (instruction.direct_target.has_value()) {
            call.a =
                IrOperand::constant_value(instruction.direct_target.value(), lifter.pointer_width);
          } else if (!instruction.structured_operands.empty()) {
            // An indirect jump (jmp rax, jmp [rip+x]) is called through its own operand, as an
            // indirect call is.
            call.a = to_ir_operand(instruction.structured_operands.front(), instruction,
                                   lifter.pointer_width);
          } else {
            call.a = IrOperand::constant_value(0, lifter.pointer_width);
          }
          // A tail call to a modelled C library import (G21-T7). Not in an import stub: its own
          // jump through its slot is the import itself, not a call of it.
          const LibcModel* model =
              lifter.function.import_name.empty() ? lifter.modelled_call(call.a) : nullptr;
          if (model != nullptr) {
            lifter.resolve_model_call(call, *model);
            lifter.push(out_block, std::move(call));
            lifter.out.notes.push_back(
                "a jump to a C library function is lifted as a call of its model, followed by a "
                "return");
          } else if (const auto callee = lifter.known_callee(instruction)) {
            // A tail call to a function of the image with a known signature: the callee runs with
            // the caller's argument registers, and its result is what this function returns.
            Lifter::resolve_call_statement(call, *callee);
            lifter.push(out_block, std::move(call));
            lifter.out.notes.push_back(
                "a jump to a known function is lifted as a call with its inferred arguments and "
                "result, followed by a return");
          } else {
            lifter.push(out_block, std::move(call));
            lifter.mark_partial("jump leaves the function; treated as a tail call");
          }
          // A tail call to a function that does not return (G24-T3): nothing comes back to return.
          if (internal::end_block_at_no_return_call(analysis, out_block, lifter.pointer_width)) {
            continue;
          }
          IrStatement tail;
          tail.op = IrOp::Return;
          tail.source_address = instruction.address;
          tail.width = lifter.pointer_width;
          tail.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
          lifter.push(out_block, std::move(tail));
        } else {
          statement.a = IrOperand::block_ref(target->second);
          lifter.push(out_block, std::move(statement));
        }
        continue;
      }

      if (instruction.classification == InstructionClass::Return) {
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.source_address = instruction.address;
        statement.width = lifter.pointer_width;
        statement.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
        lifter.push(out_block, std::move(statement));
        continue;
      }

      if (instruction.classification == InstructionClass::Interrupt) {
        lifter.unsupported(out_block, instruction);
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.source_address = instruction.address;
        statement.width = lifter.pointer_width;
        lifter.push(out_block, std::move(statement));
        continue;
      }

      const auto flags_before = lifter.flags_state;
      const std::size_t statements_before = out_block.statements.size();
      bool keeps_flags = preserves_flags(mnemonic);
      if (is_scalar_sse(mnemonic)) {
        if (!lifter.lift_scalar_sse(out_block, instruction)) {
          lifter.unsupported(out_block, instruction);
        }
        if (is_sse_compare(mnemonic)) {
          lifter.flags_state = Lifter::FlagsState::Exact;
          keeps_flags = true;  // the comparison sets the flags it reads
        }
      } else if (mnemonic == "mov" || mnemonic == "movabs") {
        lifter.lift_mov(out_block, instruction);
      } else if (mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd") {
        lifter.lift_extend(out_block, instruction);
      } else if (mnemonic == "lea") {
        lifter.lift_lea(out_block, instruction);
      } else if (mnemonic == "cmp") {
        lifter.lift_compare(out_block, instruction);
        lifter.flags_state = Lifter::FlagsState::Exact;
        keeps_flags = true;  // state set above
      } else if (mnemonic == "test") {
        lifter.lift_test(out_block, instruction);
        lifter.flags_state = Lifter::FlagsState::Exact;
        keeps_flags = true;
      } else if (mnemonic == "popcnt" || mnemonic == "tzcnt" || mnemonic == "lzcnt" ||
                 mnemonic == "bsf" || mnemonic == "bsr" || mnemonic == "bswap" ||
                 mnemonic == "bt" || mnemonic == "bts" || mnemonic == "btr" || mnemonic == "btc") {
        lifter.lift_bit_operation(out_block, instruction);
        // bswap leaves the flags alone; the bit tests set CF, so their state is kept.
        keeps_flags = mnemonic == "bswap" || mnemonic == "bt" || mnemonic == "bts" ||
                      mnemonic == "btr" || mnemonic == "btc";
      } else if (mnemonic == "movbe") {
        lifter.lift_movbe(out_block, instruction);
        keeps_flags = true;  // movbe leaves the flags alone
      } else if (mnemonic == "mul" || mnemonic == "div" || mnemonic == "idiv" ||
                 (mnemonic == "imul" && instruction.structured_operands.size() == 1)) {
        lifter.lift_multiply_divide(out_block, instruction);
      } else if (is_bitwise_or_arithmetic(mnemonic) || mnemonic == "inc" || mnemonic == "dec") {
        lifter.lift_arithmetic(out_block, instruction, next_consumer(i));
        keeps_flags = true;  // lift_arithmetic set the state
      } else if (mnemonic == "xchg") {
        // A register exchange does not write the flags; an unsupported one may
        // have, so the flag state is dropped.
        keeps_flags = lifter.lift_exchange(out_block, instruction);
      } else if (mnemonic == "adc" || mnemonic == "sbb") {
        lifter.lift_add_with_carry(out_block, instruction, next_consumer(i));
        keeps_flags = true;  // lift_add_with_carry set the state
      } else if (mnemonic == "neg" || mnemonic == "not") {
        lifter.lift_unary(out_block, instruction, next_consumer(i));
        keeps_flags = true;  // lift_unary set the state
      } else if (mnemonic == "rol" || mnemonic == "ror") {
        lifter.lift_rotate(out_block, instruction);
        keeps_flags = true;
      } else if (is_cmov(mnemonic)) {
        lifter.lift_conditional(out_block, instruction, false);
      } else if (is_setcc(mnemonic)) {
        lifter.lift_conditional(out_block, instruction, true);
      } else if (mnemonic == "push") {
        lifter.lift_push(out_block, instruction);
      } else if (mnemonic == "pop") {
        lifter.lift_pop(out_block, instruction);
      } else if (mnemonic == "leave") {
        lifter.lift_leave(out_block, instruction);
      } else if (instruction.classification == InstructionClass::Call) {
        lifter.lift_call(out_block, instruction);
      } else if (mnemonic == "nop" || mnemonic == "endbr64" || mnemonic == "endbr32") {
        // No semantic effect in the IR.
      } else if (mnemonic == "cdqe" || mnemonic == "cqo" || mnemonic == "cdq" ||
                 mnemonic == "cwd" || mnemonic == "cwde" || mnemonic == "cbw") {
        lifter.lift_sign_widen(out_block, instruction);
      } else {
        lifter.unsupported(out_block, instruction);
        keeps_flags = false;
      }
      // An instruction that emitted Unsupported may have written the flags, whatever its mnemonic
      // says, so their state is unknown after it. A later carry is then not read across it.
      bool emitted_unsupported = false;
      for (std::size_t s = statements_before; s < out_block.statements.size(); ++s) {
        emitted_unsupported =
            emitted_unsupported || out_block.statements[s].op == IrOp::Unsupported;
      }
      if (!keeps_flags || emitted_unsupported) {
        lifter.flags_state = Lifter::FlagsState::Unknown;
      } else if (preserves_flags(mnemonic)) {
        lifter.flags_state = flags_before;
      }
      if (lifter.limit_reached()) {
        lifter.mark_partial("statement limit reached");
        break;
      }
    }

    if (!out_block.statements.empty() &&
        internal::end_block_at_no_return_call(analysis, out_block, lifter.pointer_width)) {
      // The block ends at a call that does not return (G24-T3): no fall-through, no return.
    } else if (out_block.statements.empty() ||
               (out_block.statements.back().op != IrOp::Branch &&
                out_block.statements.back().op != IrOp::CondBranch &&
                out_block.statements.back().op != IrOp::Switch &&
                out_block.statements.back().op != IrOp::Return)) {
      const auto next = lifter.block_by_address.find(block->end_address);
      if (next != lifter.block_by_address.end()) {
        IrStatement statement;
        statement.op = IrOp::Branch;
        statement.a = IrOperand::block_ref(next->second);
        statement.width = lifter.pointer_width;
        statement.source_address = block->end_address;
        lifter.push(out_block, std::move(statement));
      } else {
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.width = lifter.pointer_width;
        statement.source_address = block->end_address;
        statement.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
        lifter.push(out_block, std::move(statement));
        lifter.out.partial = true;
      }
    }

    lifter.out.blocks.push_back(std::move(out_block));
    if (lifter.limit_reached()) {
      lifter.out.partial = true;
      break;
    }
  }

  if (lifter.out.blocks.empty()) {
    return make_error<IrFunction>(Status::Unsupported, "lift.empty",
                                  "nothing was lifted for this function", function.address);
  }

  // A conditional branch falls through to the next block. When the branch is in
  // the last block there is no fallthrough block, so add an explicit exit block
  // for the unknown path instead of emitting IR that cannot be rendered.
  if (lifter.out.blocks.back().statements.back().op == IrOp::CondBranch) {
    IrBlock exit_block;
    exit_block.address = lifter.blocks.back()->end_address;
    IrStatement statement;
    statement.op = IrOp::Return;
    statement.width = lifter.pointer_width;
    statement.source_address = exit_block.address;
    statement.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
    exit_block.statements.push_back(std::move(statement));
    lifter.out.blocks.push_back(std::move(exit_block));
    lifter.out.partial = true;
    lifter.note("conditional fallthrough leaves the function; exit path is unmodelled");
  }
  // The exit blocks of conditional tail calls, one per target: a call of the target, with its
  // inferred signature when it is a known function of the image, and a return of its result.
  std::map<std::uint64_t, std::uint32_t> tail_exit_by_target;
  for (const ConditionalTailCall& pending : conditional_tail_calls) {
    if (pending.block >= lifter.out.blocks.size() ||
        pending.statement >= lifter.out.blocks[pending.block].statements.size()) {
      continue;  // the block was not kept (the statement limit stopped the lift)
    }
    const Instruction& instruction = *pending.instruction;
    const std::uint64_t target = instruction.direct_target.value();
    auto exit = tail_exit_by_target.find(target);
    if (exit == tail_exit_by_target.end()) {
      IrBlock exit_block;
      exit_block.address = target;
      IrStatement call;
      call.op = IrOp::Call;
      call.source_address = instruction.address;
      call.width = lifter.pointer_width;
      call.a = IrOperand::constant_value(target, lifter.pointer_width);
      if (const LibcModel* model = lifter.modelled_call(call.a); model != nullptr) {
        lifter.resolve_model_call(call, *model);
        const std::string note =
            "a conditional jump to a C library function is lifted as a branch to a call of its "
            "model, followed by a return";
        if (std::find(lifter.out.notes.begin(), lifter.out.notes.end(), note) ==
            lifter.out.notes.end()) {
          lifter.note(note);
        }
      } else if (const auto callee = lifter.known_callee(instruction)) {
        Lifter::resolve_call_statement(call, *callee);
        const std::string note =
            "a conditional jump to a known function is lifted as a branch to a call with its "
            "inferred arguments and result, followed by a return";
        if (std::find(lifter.out.notes.begin(), lifter.out.notes.end(), note) ==
            lifter.out.notes.end()) {
          lifter.note(note);
        }
      } else {
        const std::string note = "conditional jump leaves the function; treated as a tail call";
        lifter.out.partial = true;
        if (std::find(lifter.out.notes.begin(), lifter.out.notes.end(), note) ==
            lifter.out.notes.end()) {
          lifter.note(note);
        }
      }
      exit_block.statements.push_back(std::move(call));
      // A conditional tail call to a function that does not return (G24-T3): nothing comes back.
      if (!internal::end_block_at_no_return_call(analysis, exit_block, lifter.pointer_width)) {
        IrStatement tail;
        tail.op = IrOp::Return;
        tail.source_address = instruction.address;
        tail.width = lifter.pointer_width;
        tail.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
        exit_block.statements.push_back(std::move(tail));
      }
      exit =
          tail_exit_by_target.emplace(target, static_cast<std::uint32_t>(lifter.out.blocks.size()))
              .first;
      lifter.out.blocks.push_back(std::move(exit_block));
    }
    lifter.out.blocks[pending.block].statements[pending.statement].b =
        IrOperand::block_ref(exit->second);
  }
  const ReturnRegisters return_registers = image.architecture == Architecture::AArch64
                                               ? ReturnRegisters{"x0", "v0", true}
                                               : ReturnRegisters{"rax", "xmm0", false};
  if (auto kept =
          keep_blocks_reachable_from_entry(lifter.out, analysis, function.id, lifter.pointer_width);
      !kept) {
    return make_error<IrFunction>(kept.diagnostic().status, kept.diagnostic().code,
                                  kept.diagnostic().message, function.address);
  }
  resolve_return_registers(lifter.out, return_registers);
  internal::canonicalise_registers(lifter.out, image.architecture);
  if (options.run_passes) {
    run_ir_passes(lifter.out, PassOptions{image.architecture, image.format, {}});
    mark_mixed_parameters(lifter.out);
    // After the passes: copy propagation changes which registers a statement reads, so the check
    // is only sound on the final IR. Tests that lift without passes see the lifter's output as is.
    if (image.architecture == Architecture::X86_64) {
      internal::check_call_clobbers(lifter.out);
    }
  }
  return lifter.out;
}

}  // namespace

namespace {

/// Fills `call_names` (G24-T4): the name of each direct call target that has one, and the import
/// of each GOT slot an indirect call reads (`call *slot(%rip)`, a `-fno-plt` call).
void name_call_targets(const AnalysisResult& analysis, const Function& lifted_function,
                       IrFunction& function) {
  std::set<std::uint64_t> direct_targets;
  for (const IrBlock& block : function.blocks) {
    for (const IrStatement& statement : block.statements) {
      if (statement.op != IrOp::Call) {
        continue;
      }
      const IrOperand& target = statement.a;
      if (target.kind == IrOperandKind::Constant && target.constant != 0) {
        direct_targets.insert(target.constant);
      } else if (target.kind == IrOperandKind::Memory && target.reg.empty() &&
                 target.index.empty() && lifted_function.import_name.empty()) {
        // An import stub's own jump through its slot keeps its slot form: printed by name, it
        // would read as a call of the stub to itself.
        if (const auto slot = analysis.import_slots.find(target.constant);
            slot != analysis.import_slots.end() && is_c_identifier(slot->second)) {
          function.call_names.emplace(target.constant, slot->second);
        }
      }
    }
  }
  if (direct_targets.empty()) {
    return;
  }
  // One pass over the functions, which are not assumed to be in address order.
  for (const Function& callee : analysis.functions) {
    if (direct_targets.contains(callee.address)) {
      if (std::string name = function_call_name(callee); !name.empty()) {
        function.call_names.emplace(callee.address, std::move(name));
      }
    }
  }
}

}  // namespace

Result<IrFunction> lift_function(const BinaryImage& image, const AnalysisResult& analysis,
                                 const Function& function, const LiftOptions& options) {
  LiftOptions shared = options;
  if (shared.call_summaries == nullptr) {
    shared.call_summaries = std::make_shared<CallSummaryCache>();
  }
  // The lifted function is on the path, asked with the budget its callees get: a call back into it
  // is a cycle, and its direct callees may be as tall as kMaxCallHeight.
  PathFrame frame(CallSummaryAccess::impl(*shared.call_summaries), function.address,
                  kMaxCallHeight + 1);
  auto lifted = lift_body(image, analysis, function, shared);
  if (lifted) {
    // Owner decision 3 (G24-T3): Complete needs at least one returning path. A function whose
    // every path ends in a call that does not return has nothing the oracle could compare.
    bool returns = false;
    bool ends_unreachable = false;
    for (const IrBlock& block : lifted.value().blocks) {
      for (const IrStatement& statement : block.statements) {
        if (statement.op == IrOp::Return) {
          (statement.unreachable ? ends_unreachable : returns) = true;
        }
      }
    }
    if (ends_unreachable && !returns) {
      lifted.value().partial = true;
      lifted.value().notes.push_back(
          "no path returns: every path ends in a call that does not return, so nothing is "
          "compared");
    }
    name_call_targets(analysis, function, lifted.value());
    // An import stub prints under its import's own name (`abort`, not `abort@plt`), so the
    // pseudocode stays C; the note says what the function is.
    if (!function.import_name.empty() && is_c_identifier(function.import_name)) {
      lifted.value().name = function.import_name;
      lifted.value().notes.push_back("import stub: jumps to the imported function " +
                                     function.import_name + " through its GOT slot");
    } else if (!function.stub_target.empty() && is_c_identifier(function.stub_target)) {
      // A stub of a function the image defines itself (`own_fn@plt`) prints under that name too,
      // as its callers print it; it is not an import, so it gets no import note.
      lifted.value().name = function.stub_target;
      lifted.value().notes.push_back("PLT stub: jumps to " + function.stub_target +
                                     " through its GOT slot");
    }
  }
  return lifted;
}

}  // namespace donkey
