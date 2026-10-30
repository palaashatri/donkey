#include "donkey/ir/ir.h"

#include <cstdio>
#include <optional>
#include <string>
#include <utility>

namespace donkey {
namespace {

bool valid_width(std::uint8_t width) {
  return width == 1 || width == 2 || width == 4 || width == 8;
}

bool is_terminator(IrOp op) {
  return op == IrOp::Branch || op == IrOp::CondBranch || op == IrOp::Return;
}

const char* width_type(std::uint8_t width) {
  switch (width) {
    case 1:
      return "u8";
    case 2:
      return "u16";
    case 4:
      return "u32";
    case 8:
      return "u64";
    default:
      return "u64";
  }
}

class Renderer {
 public:
  explicit Renderer(const IrFunction& function) : function_(function) {}

  std::string address_expression(const IrOperand& value) const {
    std::string out;
    bool wrote = false;
    if (!value.reg.empty() && value.reg != "rip") {
      out += value.reg;
      wrote = true;
    }
    if (!value.index.empty()) {
      if (wrote) {
        out += " + ";
      }
      out += value.index;
      if (value.scale != 1) {
        out += " * " + std::to_string(value.scale);
      }
      wrote = true;
    }
    const auto displacement = static_cast<std::int64_t>(value.constant);
    if (displacement != 0 || !wrote) {
      char buffer[32];
      if (displacement < 0) {
        std::snprintf(buffer, sizeof(buffer), "-0x%llx",
                      static_cast<unsigned long long>(-displacement));
      } else {
        std::snprintf(buffer, sizeof(buffer), "0x%llx",
                      static_cast<unsigned long long>(displacement));
      }
      if (wrote) {
        out += " + ";
      }
      out += buffer;
    }
    return out;
  }

  std::string operand(const IrOperand& value) const {
    switch (value.kind) {
      case IrOperandKind::None:
        return "?";
      case IrOperandKind::Constant: {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "0x%llx",
                      static_cast<unsigned long long>(value.constant));
        return buffer;
      }
      case IrOperandKind::Register:
        return value.reg;
      case IrOperandKind::Block: {
        char buffer[32];
        const std::uint64_t address =
            value.block < function_.blocks.size() ? function_.blocks[value.block].address : 0;
        std::snprintf(buffer, sizeof(buffer), "loc_%llx", static_cast<unsigned long long>(address));
        return buffer;
      }
      case IrOperandKind::Memory: {
        std::string out = "*(";
        out += width_type(value.width);
        out += " *)(";
        bool wrote = false;
        if (!value.reg.empty() && value.reg != "rip") {
          out += value.reg;
          wrote = true;
        }
        if (!value.index.empty()) {
          if (wrote) {
            out += " + ";
          }
          out += value.index;
          if (value.scale != 1) {
            out += " * " + std::to_string(value.scale);
          }
          wrote = true;
        }
        if (value.constant != 0 || !wrote) {
          char buffer[32];
          const auto displacement = static_cast<std::int64_t>(value.constant);
          if (displacement < 0) {
            std::snprintf(buffer, sizeof(buffer), "-0x%llx",
                          static_cast<unsigned long long>(-displacement));
          } else {
            std::snprintf(buffer, sizeof(buffer), "0x%llx",
                          static_cast<unsigned long long>(displacement));
          }
          if (wrote) {
            out += " + ";
          }
          out += buffer;
        }
        out += ")";
        return out;
      }
    }
    return "?";
  }

  std::string statement(const IrStatement& statement, const IrStatement* previous) const {
    switch (statement.op) {
      case IrOp::Nop:
        return "";
      case IrOp::Assign:
        return operand(statement.dest) + " = " + operand(statement.a) + ";";
      case IrOp::Add:
      case IrOp::Sub:
      case IrOp::Mul:
      case IrOp::And:
      case IrOp::Or:
      case IrOp::Xor:
      case IrOp::Shl:
      case IrOp::Shr:
      case IrOp::Sar: {
        const char* symbol = "?";
        switch (statement.op) {
          case IrOp::Add:
            symbol = "+";
            break;
          case IrOp::Sub:
            symbol = "-";
            break;
          case IrOp::Mul:
            symbol = "*";
            break;
          case IrOp::And:
            symbol = "&";
            break;
          case IrOp::Or:
            symbol = "|";
            break;
          case IrOp::Xor:
            symbol = "^";
            break;
          case IrOp::Shl:
            symbol = "<<";
            break;
          case IrOp::Shr:
            symbol = ">>";
            break;
          case IrOp::Sar:
            symbol = ">>";
            break;
          default:
            break;
        }
        return operand(statement.dest) + " = " + operand(statement.a) + " " + symbol + " " +
               operand(statement.b) + ";";
      }
      case IrOp::ZeroExtend:
        return operand(statement.dest) + " = (" + width_type(statement.dest.width) + ")" +
               operand(statement.a) + ";";
      case IrOp::SignExtend:
        return operand(statement.dest) + " = (s" +
               std::to_string(static_cast<unsigned>(statement.dest.width) * 8) + ")" +
               operand(statement.a) + ";";
      case IrOp::Lea:
        return operand(statement.dest) + " = (u64)(" + address_expression(statement.a) + ");";
      case IrOp::Load:
        return operand(statement.dest) + " = " + operand(statement.a) + ";";
      case IrOp::Store:
        return operand(statement.a) + " = " + operand(statement.b) + ";";
      case IrOp::Call:
        if (statement.a.kind == IrOperandKind::Constant && statement.a.constant != 0) {
          return "sub_" + hex(statement.a.constant) + "();";
        }
        return "((void (*)(void))" + operand(statement.a) + ")();";
      case IrOp::Return:
        if (statement.a.kind == IrOperandKind::None) {
          return "return;";
        }
        return "return " + operand(statement.a) + ";";
      case IrOp::Branch:
        return "goto " + operand(statement.a) + ";";
      case IrOp::CondBranch: {
        std::string condition;
        if (previous != nullptr && previous->op == IrOp::Compare) {
          const char* op = ir_condition_operator(statement.condition);
          if (statement.condition == IrCondition::Zero ||
              statement.condition == IrCondition::NonZero) {
            condition = std::string("(") + operand(previous->a) + " & " + operand(previous->b) +
                        ") " + op + " 0";
          } else {
            condition = operand(previous->a) + " " + op + " " + operand(previous->b);
          }
        } else if (previous != nullptr && previous->op == IrOp::Test) {
          condition = std::string("(") + operand(previous->a) + " & " + operand(previous->b) +
                      ") " + ir_condition_operator(statement.condition) + " 0";
        } else if (statement.condition != IrCondition::None) {
          condition = "flags " + std::string(ir_condition_operator(statement.condition));
        } else {
          condition = operand(statement.a);
        }
        return "if (" + condition + ") goto " + operand(statement.b) + ";";
      }
      case IrOp::Compare:
        return "/* flags = " + operand(statement.a) + " " +
               ir_condition_operator(statement.condition) + " " + operand(statement.b) + " */";
      case IrOp::Test:
        return "/* flags = " + operand(statement.a) + " & " + operand(statement.b) + " */";
      case IrOp::Unsupported:
        return "/* unsupported: " + statement.text + " */";
    }
    return "";
  }

  static std::string hex(std::uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%llx", static_cast<unsigned long long>(value));
    return buffer;
  }

 private:
  const IrFunction& function_;
};

}  // namespace

const char* ir_op_name(IrOp op) noexcept {
  switch (op) {
    case IrOp::Nop:
      return "nop";
    case IrOp::Assign:
      return "assign";
    case IrOp::Add:
      return "add";
    case IrOp::Sub:
      return "sub";
    case IrOp::Mul:
      return "mul";
    case IrOp::And:
      return "and";
    case IrOp::Or:
      return "or";
    case IrOp::Xor:
      return "xor";
    case IrOp::Shl:
      return "shl";
    case IrOp::Shr:
      return "shr";
    case IrOp::Sar:
      return "sar";
    case IrOp::ZeroExtend:
      return "zero_extend";
    case IrOp::SignExtend:
      return "sign_extend";
    case IrOp::Lea:
      return "lea";
    case IrOp::Load:
      return "load";
    case IrOp::Store:
      return "store";
    case IrOp::Call:
      return "call";
    case IrOp::Return:
      return "return";
    case IrOp::Branch:
      return "branch";
    case IrOp::CondBranch:
      return "cond_branch";
    case IrOp::Compare:
      return "compare";
    case IrOp::Test:
      return "test";
    case IrOp::Unsupported:
      return "unsupported";
  }
  return "unknown";
}

const char* ir_condition_name(IrCondition condition) noexcept {
  switch (condition) {
    case IrCondition::None:
      return "none";
    case IrCondition::Equal:
      return "equal";
    case IrCondition::NotEqual:
      return "not_equal";
    case IrCondition::UnsignedLess:
      return "unsigned_less";
    case IrCondition::UnsignedGreaterEqual:
      return "unsigned_greater_equal";
    case IrCondition::UnsignedGreater:
      return "unsigned_greater";
    case IrCondition::UnsignedLessEqual:
      return "unsigned_less_equal";
    case IrCondition::SignedLess:
      return "signed_less";
    case IrCondition::SignedGreaterEqual:
      return "signed_greater_equal";
    case IrCondition::SignedGreater:
      return "signed_greater";
    case IrCondition::SignedLessEqual:
      return "signed_less_equal";
    case IrCondition::Zero:
      return "zero";
    case IrCondition::NonZero:
      return "non_zero";
    case IrCondition::Negative:
      return "negative";
    case IrCondition::Positive:
      return "positive";
    case IrCondition::Overflow:
      return "overflow";
    case IrCondition::NoOverflow:
      return "no_overflow";
    case IrCondition::Carry:
      return "carry";
    case IrCondition::NoCarry:
      return "no_carry";
  }
  return "none";
}

const char* ir_condition_operator(IrCondition condition) noexcept {
  switch (condition) {
    case IrCondition::Equal:
    case IrCondition::Zero:
      return "==";
    case IrCondition::NotEqual:
    case IrCondition::NonZero:
      return "!=";
    case IrCondition::UnsignedLess:
      return "<";
    case IrCondition::UnsignedGreaterEqual:
      return ">=";
    case IrCondition::UnsignedGreater:
      return ">";
    case IrCondition::UnsignedLessEqual:
      return "<=";
    case IrCondition::SignedLess:
      return "<";
    case IrCondition::SignedGreaterEqual:
      return ">=";
    case IrCondition::SignedGreater:
      return ">";
    case IrCondition::SignedLessEqual:
      return "<=";
    case IrCondition::Negative:
      return "<";
    case IrCondition::Positive:
      return ">";
    case IrCondition::Overflow:
    case IrCondition::NoOverflow:
    case IrCondition::Carry:
    case IrCondition::NoCarry:
    case IrCondition::None:
      return "?";
  }
  return "?";
}

IrOperand IrOperand::constant_value(std::uint64_t value, std::uint8_t width) {
  IrOperand operand;
  operand.kind = IrOperandKind::Constant;
  operand.constant = value;
  operand.width = width;
  return operand;
}

IrOperand IrOperand::register_ref(std::string name, std::uint8_t width) {
  IrOperand operand;
  operand.kind = IrOperandKind::Register;
  operand.reg = std::move(name);
  operand.width = width;
  return operand;
}

IrOperand IrOperand::block_ref(std::uint32_t index) {
  IrOperand operand;
  operand.kind = IrOperandKind::Block;
  operand.block = index;
  return operand;
}

Result<bool> verify_ir(const IrFunction& function) {
  for (std::size_t block_index = 0; block_index < function.blocks.size(); ++block_index) {
    const IrBlock& block = function.blocks[block_index];
    auto fail = [&](std::string code, std::string message) {
      return make_error<bool>(Status::InternalError, std::move(code), std::move(message),
                              block.address);
    };
    if (block.statements.empty()) {
      return fail("ir.empty_block", "block has no statements");
    }
    for (const IrStatement& statement : block.statements) {
      auto check_operand = [&](const IrOperand& operand,
                               const char* role) -> std::optional<Diagnostic> {
        if (operand.kind == IrOperandKind::None) {
          return std::nullopt;
        }
        if (operand.kind == IrOperandKind::Block) {
          if (operand.block >= function.blocks.size()) {
            return Diagnostic::make(Status::InternalError, "ir.bad_block_index",
                                    std::string(role) + " block index out of range", block.address);
          }
          return std::nullopt;
        }
        if (operand.kind == IrOperandKind::Register && operand.reg.empty()) {
          return Diagnostic::make(Status::InternalError, "ir.empty_register",
                                  std::string(role) + " register name is empty", block.address);
        }
        if (!valid_width(operand.width)) {
          return Diagnostic::make(Status::InternalError, "ir.bad_width",
                                  std::string(role) + " has an invalid width", block.address);
        }
        return std::nullopt;
      };

      const IrOperand* operands[] = {&statement.dest, &statement.a, &statement.b};
      const char* roles[] = {"dest", "a", "b"};
      for (std::size_t i = 0; i < 3; ++i) {
        if (auto problem = check_operand(*operands[i], roles[i]); problem.has_value()) {
          return make_error<bool>(Status::InternalError, problem->code, problem->message,
                                  problem->offset);
        }
      }
      if (!valid_width(statement.width)) {
        return fail("ir.bad_width", "statement width is invalid");
      }

      switch (statement.op) {
        case IrOp::Nop:
          break;
        case IrOp::Assign:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind == IrOperandKind::None) {
            return fail("ir.malformed_assign", "assign needs a register destination and a source");
          }
          break;
        case IrOp::Add:
        case IrOp::Sub:
        case IrOp::Mul:
        case IrOp::And:
        case IrOp::Or:
        case IrOp::Xor:
        case IrOp::Shl:
        case IrOp::Shr:
        case IrOp::Sar:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind == IrOperandKind::None || statement.b.kind == IrOperandKind::None) {
            return fail("ir.malformed_binary",
                        "binary operation needs a register destination and two sources");
          }
          break;
        case IrOp::Lea:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind != IrOperandKind::Memory) {
            return fail("ir.malformed_lea", "lea needs a register destination and memory source");
          }
          break;
        case IrOp::ZeroExtend:
        case IrOp::SignExtend:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind == IrOperandKind::None || statement.dest.width < statement.a.width) {
            return fail("ir.malformed_extend",
                        "extend needs a register destination at least as wide as its source");
          }
          break;
        case IrOp::Load:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind != IrOperandKind::Memory) {
            return fail("ir.malformed_load", "load needs a register destination and memory source");
          }
          break;
        case IrOp::Store:
          if (statement.a.kind != IrOperandKind::Memory ||
              statement.b.kind == IrOperandKind::None) {
            return fail("ir.malformed_store", "store needs a memory destination and a value");
          }
          break;
        case IrOp::Call:
          if (statement.a.kind == IrOperandKind::None) {
            return fail("ir.malformed_call", "call needs a target");
          }
          break;
        case IrOp::Return:
          break;
        case IrOp::Branch:
          if (statement.a.kind != IrOperandKind::Block) {
            return fail("ir.malformed_branch", "branch needs a block target");
          }
          break;
        case IrOp::CondBranch:
          if (statement.a.kind == IrOperandKind::None || statement.b.kind != IrOperandKind::Block ||
              statement.condition == IrCondition::None) {
            return fail("ir.malformed_cond_branch",
                        "conditional branch needs a condition and a block target");
          }
          break;
        case IrOp::Compare:
          if (statement.a.kind == IrOperandKind::None || statement.b.kind == IrOperandKind::None ||
              statement.condition == IrCondition::None) {
            return fail("ir.malformed_compare", "compare needs two operands and a condition");
          }
          break;
        case IrOp::Test:
          if (statement.a.kind == IrOperandKind::None || statement.b.kind == IrOperandKind::None) {
            return fail("ir.malformed_test", "test needs two operands");
          }
          break;
        case IrOp::Unsupported:
          if (statement.text.empty()) {
            return fail("ir.empty_unsupported", "unsupported statement needs raw text");
          }
          break;
      }
    }

    const IrStatement& last = block.statements.back();
    if (!is_terminator(last.op)) {
      return fail("ir.missing_terminator", "block does not end in a branch or return");
    }
    // A conditional branch always falls through to the next block. In the last
    // block there is no next block, so the false path would leave the function
    // with no modelled exit and the printer could not render it honestly.
    if (last.op == IrOp::CondBranch && block_index == function.blocks.size() - 1) {
      return fail("ir.cond_branch_tail",
                  "last block ends in a conditional branch with no fallthrough block");
    }
    if (last.op == IrOp::Branch && last.a.kind == IrOperandKind::Block &&
        last.a.block >= function.blocks.size()) {
      return fail("ir.bad_block_index", "branch target is out of range");
    }
  }
  return true;
}

Result<std::string> format_pseudocode(const IrFunction& function) {
  auto verified = verify_ir(function);
  if (!verified) {
    return make_error<std::string>(verified.diagnostic().status, verified.diagnostic().code,
                                   verified.diagnostic().message, verified.diagnostic().offset);
  }

  const Renderer renderer(function);
  std::string out;
  out += "// " + (function.name.empty() ? std::string("sub_1000") : function.name);
  if (function.partial) {
    out += "  [partial]";
  }
  out += "\n";
  if (!function.notes.empty()) {
    for (const std::string& note : function.notes) {
      out += "// note: " + note + "\n";
    }
  }
  out += "u64 " + (function.name.empty() ? std::string("sub") : function.name) + "(void) {\n";
  for (std::size_t index = 0; index < function.blocks.size(); ++index) {
    const IrBlock& block = function.blocks[index];
    out += "loc_" + Renderer::hex(block.address) + ":\n";
    for (std::size_t statement_index = 0; statement_index < block.statements.size();
         ++statement_index) {
      const IrStatement& statement = block.statements[statement_index];
      const IrStatement* previous =
          statement_index == 0 ? nullptr : &block.statements[statement_index - 1];
      std::string line = renderer.statement(statement, previous);
      if (line.empty()) {
        continue;
      }
      out += "  " + line + "\n";
    }
  }
  out += "}\n";
  return out;
}

}  // namespace donkey
