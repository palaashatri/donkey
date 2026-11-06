// Register alias canonicalisation (G04-T1).
//
// Every register operand is rewritten to its family, so eax, ax, al and rax are one
// variable, rax. The IR contract for widths, which the interpreter and the passes
// share, is this:
//   * a read at width w gives the low w bytes of the family;
//   * a write of width 8 replaces the family;
//   * a write of width 4 zero-extends to 8 bytes (the x86-64 and AArch64 rule);
//   * a write of width 1 or 2 keeps the other bytes of the family, so it is written
//     as an explicit merge: family = (family & ~mask) | (value << shift).
// The high byte registers (ah, bh, ch, dh) live at shift 8 of their family, so they
// are read as a shift of the family and written by a merge at shift 8.
//
// Only the x86-64 and AArch64 lifters use this. The x86-32 stack and frame registers
// keep their names, because the 32-bit lifter treats esp and ebp as pointers.

#include "lift_internal.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "registers.h"

namespace donkey::internal {
namespace {

/// The statement kinds that write their destination register. Every other kind
/// reads its dest (Switch selects on it) or has none.
bool writes_dest(IrOp op) {
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

bool is_temporary(const std::string& name) {
  return name.rfind("var_", 0) == 0;
}

bool is_high_byte(const std::string& name) {
  return name == "ah" || name == "bh" || name == "ch" || name == "dh";
}

struct Canonicaliser {
  Architecture architecture;
  std::uint32_t next_temporary = 0;

  bool x86() const { return architecture == Architecture::X86_64; }

  /// The family of a register name, or an empty string for a name this pass does
  /// not rewrite (temporaries and anything the lifters do not produce).
  std::string family(const std::string& name) const {
    if (is_temporary(name) || name.empty()) {
      return {};
    }
    if (architecture == Architecture::AArch64) {
      if (name == "fp") {
        return "x29";
      }
      if (name == "lr") {
        return "x30";
      }
      return register_family(name);
    }
    // x86-64: 16-bit sp is the low word of rsp, not an independent register.
    if (name == "sp") {
      return "rsp";
    }
    return register_family(name);
  }

  IrOperand temporary(std::uint32_t id, std::uint8_t width) const {
    return IrOperand::register_ref("var_" + std::to_string(id), width);
  }

  IrStatement make(IrOp op, IrOperand dest, IrOperand a, IrOperand b, std::uint8_t width,
                   std::uint64_t address) const {
    IrStatement statement;
    statement.op = op;
    statement.dest = std::move(dest);
    statement.a = std::move(a);
    statement.b = std::move(b);
    statement.width = width;
    statement.source_address = address;
    return statement;
  }

  /// A register read of `name` at `width` bytes, as an operand. A high byte is read
  /// as a shift of its family into a temporary, which `pre` receives.
  IrOperand read_register(const std::string& name, std::uint8_t width,
                          std::vector<IrStatement>& pre, std::uint64_t address) {
    if (name.empty() || is_temporary(name)) {
      return IrOperand::register_ref(name, width);
    }
    if (x86() && is_high_byte(name)) {
      const std::string base = family(name);
      const std::uint32_t id = next_temporary++;
      pre.push_back(make(IrOp::Shr, temporary(id, 8), IrOperand::register_ref(base, 8),
                         IrOperand::constant_value(8, 1), 8, address));
      return temporary(id, width);
    }
    return IrOperand::register_ref(family(name).empty() ? name : family(name), width);
  }

  /// Rewrites the reads of an operand in place: registers and memory bases/indexes.
  void rewrite_reads(IrOperand& operand, std::vector<IrStatement>& pre, std::uint64_t address) {
    if (operand.kind == IrOperandKind::Register) {
      operand = read_register(operand.reg, operand.width, pre, address);
      return;
    }
    if (operand.kind == IrOperandKind::Memory) {
      if (!operand.reg.empty()) {
        const std::string base = family(operand.reg);
        if (!base.empty()) {
          operand.reg = base;
        }
      }
      if (!operand.index.empty()) {
        const std::string index = family(operand.index);
        if (!index.empty()) {
          operand.index = index;
        }
      }
    }
  }

  /// Writes the result of a statement to a sub-word register: the value goes into
  /// `value` (a temporary of `width` bytes), and `post` merges it into the family.
  void merge_into_family(const std::string& family_name, bool high, std::uint8_t width,
                         std::uint32_t value, std::vector<IrStatement>& post,
                         std::uint64_t address) {
    const std::uint32_t widened = next_temporary++;
    post.push_back(make(IrOp::ZeroExtend, temporary(widened, 8), temporary(value, width),
                        IrOperand::none(), 8, address));
    std::uint64_t mask = 0;
    std::uint8_t shift = 0;
    if (high) {
      shift = 8;
      mask = 0xffULL << 8;
    } else {
      mask = width == 1 ? 0xffULL : 0xffffULL;
    }
    std::uint64_t kept_mask = ~mask;
    const std::uint32_t kept = next_temporary++;
    post.push_back(make(IrOp::And, temporary(kept, 8), IrOperand::register_ref(family_name, 8),
                        IrOperand::constant_value(kept_mask, 8), 8, address));
    IrOperand shifted = temporary(widened, 8);
    if (shift != 0) {
      const std::uint32_t moved = next_temporary++;
      post.push_back(make(IrOp::Shl, temporary(moved, 8), temporary(widened, 8),
                          IrOperand::constant_value(shift, 1), 8, address));
      shifted = temporary(moved, 8);
    }
    post.push_back(make(IrOp::Or, IrOperand::register_ref(family_name, 8), temporary(kept, 8),
                        shifted, 8, address));
  }

  void canonicalise(IrBlock& block, const std::vector<IrStatement>& statements) {
    std::vector<IrStatement> out;
    out.reserve(statements.size());
    for (IrStatement statement : statements) {
      const std::uint64_t address = statement.source_address;
      std::vector<IrStatement> pre;
      std::vector<IrStatement> post;
      rewrite_reads(statement.a, pre, address);
      rewrite_reads(statement.b, pre, address);
      rewrite_reads(statement.c, pre, address);
      if (statement.op == IrOp::Switch) {
        rewrite_reads(statement.dest, pre, address);  // the selector is read
      } else if (statement.dest.kind == IrOperandKind::Memory) {
        rewrite_reads(statement.dest, pre, address);  // the address is read
      } else if (writes_dest(statement.op) && statement.dest.kind == IrOperandKind::Register &&
                 !statement.dest.reg.empty() && !is_temporary(statement.dest.reg)) {
        rewrite_write(statement, pre, post, address);
      }
      for (IrStatement& p : pre) {
        out.push_back(std::move(p));
      }
      out.push_back(std::move(statement));
      for (IrStatement& p : post) {
        out.push_back(std::move(p));
      }
    }
    block.statements = std::move(out);
  }

  /// Rewrites the destination of a value-writing statement.
  void rewrite_write(IrStatement& statement, std::vector<IrStatement>& pre,
                     std::vector<IrStatement>& post, std::uint64_t address) {
    const std::string name = statement.dest.reg;
    const std::string base = family(name);
    if (base.empty()) {
      return;
    }
    const bool high = x86() && is_high_byte(name);
    std::uint8_t width = statement.dest.width != 0 ? statement.dest.width : statement.width;
    const bool conditional = statement.op == IrOp::CondAssign;
    if (high || width == 1 || width == 2) {
      // A sub-word write is a merge. A conditional write keeps the old bytes when its
      // condition fails, so the temporary starts as the current value.
      const std::uint8_t sub = high ? 1 : width;
      const std::uint32_t value = next_temporary++;
      if (conditional) {
        IrOperand current = read_register(name, sub, pre, address);
        pre.push_back(make(IrOp::Assign, temporary(value, sub), std::move(current),
                           IrOperand::none(), sub, address));
      }
      statement.dest = temporary(value, sub);
      merge_into_family(base, high, sub, value, post, address);
      return;
    }
    if (width == 4 && conditional) {
      // cmovcc with a 32-bit destination zero-extends even when the condition fails.
      const std::uint32_t value = next_temporary++;
      pre.push_back(make(IrOp::Assign, temporary(value, 4), IrOperand::register_ref(base, 4),
                         IrOperand::none(), 4, address));
      statement.dest = temporary(value, 4);
      post.push_back(make(IrOp::Assign, IrOperand::register_ref(base, 4), temporary(value, 4),
                          IrOperand::none(), 4, address));
      return;
    }
    // A 4-byte or 8-byte write: the family is the destination, and a 4-byte write
    // zero-extends (width 4 is kept on the operand to say so).
    statement.dest = IrOperand::register_ref(base, width);
  }
};

}  // namespace

void canonicalise_registers(IrFunction& function, Architecture architecture) {
  if (architecture != Architecture::X86_64 && architecture != Architecture::AArch64) {
    return;
  }
  Canonicaliser canonical{architecture};
  // Temporaries start after the highest one the lifter used.
  for (const IrBlock& block : function.blocks) {
    for (const IrStatement& statement : block.statements) {
      for (const IrOperand* operand : {&statement.dest, &statement.a, &statement.b, &statement.c}) {
        if (operand->kind != IrOperandKind::Register || !is_temporary(operand->reg)) {
          continue;
        }
        std::uint64_t id = 0;
        bool digits = operand->reg.size() > 4;
        for (std::size_t i = 4; i < operand->reg.size() && digits; ++i) {
          digits = operand->reg[i] >= '0' && operand->reg[i] <= '9';
          id = id * 10 + static_cast<std::uint64_t>(operand->reg[i] - '0');
        }
        if (digits && id + 1 > canonical.next_temporary) {
          canonical.next_temporary = static_cast<std::uint32_t>(id + 1);
        }
      }
    }
  }
  for (IrBlock& block : function.blocks) {
    const std::vector<IrStatement> statements = std::move(block.statements);
    canonical.canonicalise(block, statements);
  }
}

}  // namespace donkey::internal
