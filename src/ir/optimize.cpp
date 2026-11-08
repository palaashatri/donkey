#include "optimize.h"

#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "registers.h"

namespace donkey::internal {
namespace {

bool is_temporary(const std::string& name) {
  return name.rfind("var_", 0) == 0;
}

/// Whether a statement of this kind writes its destination (CondAssign reads its old
/// value too, so it is not a plain write; see writes_plainly).
bool writes_destination(IrOp op) {
  switch (op) {
    case IrOp::Store:
    case IrOp::Switch:
    case IrOp::Compare:
    case IrOp::Test:
    case IrOp::CondCompare:
    case IrOp::CondCompareAdd:
    case IrOp::FCompare:
    case IrOp::Branch:
    case IrOp::CondBranch:
    case IrOp::Return:
    case IrOp::Call:
    case IrOp::Unsupported:
    case IrOp::Nop:
      return false;
    default:
      return true;
  }
}

/// A write that replaces the whole destination: not a conditional write.
bool writes_plainly(const IrStatement& statement) {
  return writes_destination(statement.op) && statement.op != IrOp::CondAssign;
}

/// Statements with no effect besides their destination, which cannot fault and do not
/// set flags. Only these are removed when nothing reads their destination.
bool is_pure(IrOp op) {
  switch (op) {
    case IrOp::Assign:
    case IrOp::Add:
    case IrOp::Sub:
    case IrOp::Mul:
    case IrOp::And:
    case IrOp::Or:
    case IrOp::Xor:
    case IrOp::Shl:
    case IrOp::Shr:
    case IrOp::Sar:
    case IrOp::ZeroExtend:
    case IrOp::SignExtend:
    case IrOp::Lea:
    case IrOp::CountTrailingZeros:
    case IrOp::CountLeadingZeros:
    case IrOp::PopCount:
    case IrOp::ByteSwap:
    case IrOp::FAdd:
    case IrOp::FSub:
    case IrOp::FMul:
    case IrOp::FDiv:
    case IrOp::FSqrt:
    case IrOp::FNeg:
    case IrOp::FAbs:
    case IrOp::IntToFloat:
    case IrOp::UIntToFloat:
    case IrOp::FloatExtend:
    case IrOp::FloatTruncate:
    case IrOp::FMulAdd:
    case IrOp::FMulSub:
      return true;
    default:
      return false;
  }
}

/// The family a register operand writes or reads: rax for eax, and so on. Temporaries
/// keep their own name.
std::string family(const std::string& name) {
  return is_temporary(name) ? name : register_family(name);
}

/// Calls every register and memory-base name the operand reads, and the selector and
/// the memory address of a store.
template <typename Visit>
void for_each_read_name(const IrStatement& statement, Visit&& visit) {
  for (const IrOperand* operand : {&statement.a, &statement.b, &statement.c}) {
    if (operand->kind == IrOperandKind::Register && !operand->reg.empty()) {
      visit(family(operand->reg));
    } else if (operand->kind == IrOperandKind::Memory) {
      if (!operand->reg.empty()) visit(family(operand->reg));
      if (!operand->index.empty()) visit(family(operand->index));
    }
  }
  if (statement.dest.kind == IrOperandKind::Memory) {
    if (!statement.dest.reg.empty()) visit(family(statement.dest.reg));
    if (!statement.dest.index.empty()) visit(family(statement.dest.index));
  }
  if (statement.op == IrOp::Switch && statement.dest.kind == IrOperandKind::Register) {
    visit(family(statement.dest.reg));
  }
  if (statement.op == IrOp::CondAssign && statement.dest.kind == IrOperandKind::Register) {
    visit(family(statement.dest.reg));  // the value kept when the condition fails
  }
}

struct Copy {
  bool is_constant = false;
  std::string source;  // the register copied, when not a constant
  std::uint64_t constant = 0;
};

/// The facts of one block: a register that holds a copy of another or a constant.
using Copies = std::unordered_map<std::string, Copy>;

void forget(Copies& copies, const std::string& written) {
  copies.erase(written);
  for (auto it = copies.begin(); it != copies.end();) {
    if (!it->second.is_constant && it->second.source == written) {
      it = copies.erase(it);
    } else {
      ++it;
    }
  }
}

void substitute(IrOperand& operand, const Copies& copies, bool allow_constant) {
  if (operand.kind != IrOperandKind::Register || operand.reg.empty() || operand.width == 0) {
    return;
  }
  const auto found = copies.find(family(operand.reg));
  if (found == copies.end()) {
    return;
  }
  if (found->second.is_constant) {
    if (allow_constant) {
      operand = IrOperand::constant_value(found->second.constant, operand.width);
    }
    return;
  }
  operand.reg = found->second.source;
}

/// Replaces the register bases and indexes of a memory operand by copies of them. A
/// constant cannot take the place of a base or an index.
void substitute_address(IrOperand& operand, const Copies& copies) {
  if (operand.kind != IrOperandKind::Memory) {
    return;
  }
  if (!operand.reg.empty()) {
    const auto found = copies.find(family(operand.reg));
    if (found != copies.end() && !found->second.is_constant) {
      operand.reg = found->second.source;
    }
  }
  if (!operand.index.empty()) {
    const auto found = copies.find(family(operand.index));
    if (found != copies.end() && !found->second.is_constant) {
      operand.index = found->second.source;
    }
  }
}

}  // namespace

void propagate_copies(IrFunction& function) {
  for (IrBlock& block : function.blocks) {
    Copies copies;
    for (IrStatement& statement : block.statements) {
      substitute(statement.a, copies, true);
      substitute(statement.b, copies, true);
      substitute(statement.c, copies, true);
      if (statement.op == IrOp::Switch) {
        substitute(statement.dest, copies, false);  // the selector is read
      }
      substitute_address(statement.a, copies);
      substitute_address(statement.b, copies);
      substitute_address(statement.c, copies);
      substitute_address(statement.dest, copies);

      if (statement.op == IrOp::Call || statement.op == IrOp::Unsupported) {
        copies.clear();  // the callee or the unknown statement may write any register
        continue;
      }
      if (!writes_destination(statement.op) || statement.dest.kind != IrOperandKind::Register ||
          statement.dest.reg.empty()) {
        continue;
      }
      const std::string written = family(statement.dest.reg);
      forget(copies, written);
      if (statement.op != IrOp::Assign || statement.dest.width != 8 || statement.width != 8) {
        continue;
      }
      if (statement.a.kind == IrOperandKind::Constant && statement.a.width == 8) {
        Copy fact;
        fact.is_constant = true;
        fact.constant = statement.a.constant;
        copies[written] = fact;
      } else if (statement.a.kind == IrOperandKind::Register && statement.a.width == 8 &&
                 !statement.a.reg.empty() && family(statement.a.reg) != written) {
        Copy fact;
        fact.source = family(statement.a.reg);
        copies[written] = fact;
      }
    }
  }
}

void remove_dead_temporaries(IrFunction& function) {
  bool changed = true;
  while (changed) {
    changed = false;
    std::unordered_map<std::string, std::size_t> reads;
    for (const IrBlock& block : function.blocks) {
      for (const IrStatement& statement : block.statements) {
        for_each_read_name(statement, [&reads](const std::string& name) {
          if (is_temporary(name)) ++reads[name];
        });
      }
    }
    for (IrBlock& block : function.blocks) {
      std::vector<IrStatement> kept;
      kept.reserve(block.statements.size());
      for (IrStatement& statement : block.statements) {
        const bool dead = is_pure(statement.op) && statement.dest.kind == IrOperandKind::Register &&
                          is_temporary(statement.dest.reg) && reads[statement.dest.reg] == 0;
        if (dead) {
          changed = true;
          continue;
        }
        kept.push_back(std::move(statement));
      }
      block.statements = std::move(kept);
    }
  }
}

namespace {

/// The register families live at a point: a set of names, or every register, which is
/// the case after a call or an unsupported statement (either may read any of them).
struct Live {
  bool all = false;
  std::set<std::string> names;

  bool contains(const std::string& name) const { return all || names.count(name) != 0; }
  void add(const std::string& name) { names.insert(name); }
  void remove(const std::string& name) { names.erase(name); }
  bool unite(const Live& other) {
    bool changed = false;
    if (other.all && !all) {
      all = true;
      changed = true;
    }
    for (const std::string& name : other.names) {
      changed = names.insert(name).second || changed;
    }
    return changed;
  }
  bool operator==(const Live& other) const { return all == other.all && names == other.names; }
};

/// The blocks a block can continue to, from its terminator and its fall-through.
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

/// Whether a statement writes a whole register family, so that the old value is gone.
bool kills_family(const IrStatement& statement) {
  return writes_plainly(statement) && statement.dest.kind == IrOperandKind::Register &&
         !statement.dest.reg.empty() && !is_temporary(statement.dest.reg) &&
         statement.dest.width >= 4;
}

/// The registers a return must keep: the stack pointer and the callee-saved registers,
/// whose values the caller depends on, as well as the value the return reads itself.
/// Writes to them stay, so an epilogue that restores them is not removed.
void add_return_obligations(Live& live) {
  static const char* const kNames[] = {
      // x86-64 (and x86-32 by family). rsi and rdi are callee-saved under the Windows x64 and
      // x86-32 conventions, and this pass does not know which convention applies, so their
      // writes stay too: keeping a dead write is safe, removing a restore the caller needs is not.
      "rsp",
      "rbp",
      "rbx",
      "rsi",
      "rdi",
      "r12",
      "r13",
      "r14",
      "r15",
      // AArch64: sp, the frame and link registers, and x19 to x28
      "sp",
      "x19",
      "x20",
      "x21",
      "x22",
      "x23",
      "x24",
      "x25",
      "x26",
      "x27",
      "x28",
      "x29",
      "x30",
  };
  for (const char* name : kNames) {
    live.add(name);
  }
}

/// Walks a block backward from its live-out set, and returns the live-in set. When
/// `dead` is given, it marks each pure register write whose family is not live after it.
Live walk_block(const IrBlock& block, Live live, std::vector<bool>* dead) {
  for (std::size_t i = block.statements.size(); i-- > 0;) {
    const IrStatement& statement = block.statements[i];
    if (statement.op == IrOp::Return) {
      add_return_obligations(live);
    }
    if (statement.op == IrOp::Call || statement.op == IrOp::Unsupported) {
      live.all = true;  // the callee or the unknown statement may read any register
      continue;
    }
    if (dead != nullptr && is_pure(statement.op) &&
        statement.dest.kind == IrOperandKind::Register && !statement.dest.reg.empty() &&
        !is_temporary(statement.dest.reg)) {
      const std::string name = family(statement.dest.reg);
      if (!live.contains(name)) {
        (*dead)[i] = true;
        continue;  // a dead write reads nothing that is needed
      }
    }
    if (kills_family(statement)) {
      live.remove(family(statement.dest.reg));
    }
    for_each_read_name(statement, [&live](const std::string& name) { live.add(name); });
  }
  return live;
}

/// One round of liveness and removal. Returns whether anything was removed.
bool remove_dead_register_writes_once(IrFunction& function) {
  const std::size_t count = function.blocks.size();
  std::vector<std::vector<std::size_t>> successors(count);
  for (std::size_t b = 0; b < count; ++b) {
    successors[b] = successors_of(function, b);
  }
  std::vector<Live> live_in(count);
  bool changed = true;
  while (changed) {
    changed = false;
    for (std::size_t b = count; b-- > 0;) {
      Live live_out;
      for (const std::size_t next : successors[b]) {
        live_out.unite(live_in[next]);
      }
      Live updated = walk_block(function.blocks[b], live_out, nullptr);
      if (!(updated == live_in[b])) {
        live_in[b] = updated;
        changed = true;
      }
    }
  }
  bool removed = false;
  for (std::size_t b = 0; b < count; ++b) {
    Live live_out;
    for (const std::size_t next : successors[b]) {
      live_out.unite(live_in[next]);
    }
    std::vector<bool> dead(function.blocks[b].statements.size(), false);
    walk_block(function.blocks[b], live_out, &dead);
    IrBlock& block = function.blocks[b];
    std::vector<IrStatement> kept;
    kept.reserve(block.statements.size());
    for (std::size_t i = 0; i < block.statements.size(); ++i) {
      if (dead[i]) {
        removed = true;
      } else {
        kept.push_back(std::move(block.statements[i]));
      }
    }
    block.statements = std::move(kept);
  }
  return removed;
}

}  // namespace

void remove_dead_register_writes(IrFunction& function) {
  // Removing a dead write can make the writes it read dead too, so repeat until stable.
  while (remove_dead_register_writes_once(function)) {
  }
}

}  // namespace donkey::internal
