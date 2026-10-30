#include "donkey/ir/ir.h"

#include <cstdio>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ir_internal.h"

namespace donkey {
namespace {

bool valid_width(std::uint8_t width) {
  return width == 1 || width == 2 || width == 4 || width == 8;
}

bool is_terminator(IrOp op) {
  return op == IrOp::Branch || op == IrOp::CondBranch || op == IrOp::Return || op == IrOp::Switch;
}

/// Exact logical complement of a condition, when one exists. Negative/Positive
/// are deliberately excluded: `!sign` is `>= 0`, not `> 0`.
const IrCondition* complement_of(IrCondition condition) {
  static const std::pair<IrCondition, IrCondition> kComplements[] = {
      {IrCondition::Equal, IrCondition::NotEqual},
      {IrCondition::UnsignedLess, IrCondition::UnsignedGreaterEqual},
      {IrCondition::UnsignedGreater, IrCondition::UnsignedLessEqual},
      {IrCondition::SignedLess, IrCondition::SignedGreaterEqual},
      {IrCondition::SignedGreater, IrCondition::SignedLessEqual},
      {IrCondition::Zero, IrCondition::NonZero},
      {IrCondition::Carry, IrCondition::NoCarry},
      {IrCondition::Overflow, IrCondition::NoOverflow},
  };
  for (const auto& [first, second] : kComplements) {
    if (condition == first) {
      return &second;
    }
    if (condition == second) {
      return &first;
    }
  }
  return nullptr;
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
        std::snprintf(buffer, sizeof(buffer), "0x%llx",
                      static_cast<unsigned long long>(-displacement));
        out += wrote ? " - " : "-";
      } else {
        std::snprintf(buffer, sizeof(buffer), "0x%llx",
                      static_cast<unsigned long long>(displacement));
        if (wrote) {
          out += " + ";
        }
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
        if (!function_.local_variables.empty()) {
          for (const auto& var : function_.local_variables) {
            if (var.base_reg == value.reg &&
                var.offset == static_cast<std::int64_t>(value.constant)) {
              if (!value.index.empty()) {
                return var.name + "[" + value.index + "]";
              }
              return var.name;
            }
          }
        }
        if (!value.reg.empty() && !value.index.empty() && value.constant == 0) {
          return value.reg + "[" + value.index + "]";
        }
        std::string out = "*(";
        out += width_type(value.width);
        out += " *)(";
        out += address_expression(value);
        out += ")";
        return out;
      }
    }
    return "?";
  }

  /// The condition of a conditional branch. A compare/test statement directly
  /// before the branch supplies the operands; otherwise only the condition
  /// kind is known. `negate` selects an exactly complementary condition when one
  /// exists (`==` becomes `!=`); otherwise the whole condition is wrapped.
  std::string condition(const IrStatement& statement, const IrStatement* previous,
                        bool negate = false) const {
    IrCondition condition_kind = statement.condition;
    bool wrap = false;
    if (negate) {
      if (const IrCondition* complement = complement_of(condition_kind); complement != nullptr) {
        condition_kind = *complement;
      } else {
        wrap = true;
      }
    }
    std::string text;
    if (previous != nullptr && previous->op == IrOp::Compare) {
      text = operand(previous->a) + " " + ir_condition_operator(condition_kind) + " " +
             operand(previous->b);
    } else if (previous != nullptr && previous->op == IrOp::Test) {
      text = "(" + operand(previous->a) + " & " + operand(previous->b) + ") " +
             ir_condition_operator(condition_kind) + " 0";
    } else if (condition_kind != IrCondition::None) {
      text = "flags " + std::string(ir_condition_operator(condition_kind));
    } else {
      text = operand(statement.a);
    }
    if (wrap) {
      text = "!(" + text + ")";
    }
    return text;
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
      case IrOp::CondBranch:
        return "if (" + condition(statement, previous) + ") goto " + operand(statement.b) + ";";
      case IrOp::Switch: {
        std::string out = "switch (" + operand(statement.dest) + ") {";
        for (const auto& sc : statement.switch_cases) {
          char buffer[32];
          std::snprintf(buffer, sizeof(buffer), "0x%llx",
                        static_cast<unsigned long long>(sc.value));
          const std::uint64_t address = sc.target_block < function_.blocks.size()
                                            ? function_.blocks[sc.target_block].address
                                            : 0;
          char blk[32];
          std::snprintf(blk, sizeof(blk), "loc_%llx", static_cast<unsigned long long>(address));
          out += " case " + std::string(buffer) + ": goto " + std::string(blk) + ";";
        }
        if (statement.a.kind == IrOperandKind::Block) {
          const std::uint64_t address = statement.a.block < function_.blocks.size()
                                            ? function_.blocks[statement.a.block].address
                                            : 0;
          char blk[32];
          std::snprintf(blk, sizeof(blk), "loc_%llx", static_cast<unsigned long long>(address));
          out += " default: goto " + std::string(blk) + ";";
        }
        out += " }";
        return out;
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

namespace detail {

std::string render_statement(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous) {
  return Renderer(function).statement(statement, previous);
}

std::string render_operand(const IrFunction& function, const IrOperand& operand) {
  return Renderer(function).operand(operand);
}

std::string render_condition(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous, bool negate) {
  return Renderer(function).condition(statement, previous, negate);
}

}  // namespace detail

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
    case IrOp::Switch:
      return "switch";
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
  for (const IrParameter& parameter : function.parameters) {
    if (parameter.name.empty()) {
      return make_error<bool>(Status::InternalError, "ir.bad_parameter",
                              "inferred parameter has an empty name", function.address);
    }
    if (!valid_width(parameter.width)) {
      return make_error<bool>(Status::InternalError, "ir.bad_parameter",
                              "inferred parameter has an invalid width", function.address);
    }
  }
  if (function.return_width != 0 && !valid_width(function.return_width)) {
    return make_error<bool>(Status::InternalError, "ir.bad_return_width",
                            "inferred return width is invalid", function.address);
  }
  for (std::size_t block_index = 0; block_index < function.blocks.size(); ++block_index) {
    const IrBlock& block = function.blocks[block_index];
    auto fail = [&](std::string code, std::string message) {
      return make_error<bool>(Status::InternalError, std::move(code), std::move(message),
                              block.address);
    };
    if (block.statements.empty()) {
      return fail("ir.empty_block", "block has no statements");
    }
    bool seen_terminator = false;
    for (const IrStatement& statement : block.statements) {
      if (seen_terminator) {
        return fail("ir.dead_statements_after_terminator",
                    "block contains statements after terminator");
      }
      if (is_terminator(statement.op)) {
        seen_terminator = true;
      }
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
          if (statement.dest.width != statement.width) {
            return fail("ir.type_width_mismatch",
                        "assign destination width must match statement width");
          }
          if (statement.a.kind == IrOperandKind::Register &&
              statement.a.width != statement.dest.width) {
            return fail("ir.type_width_mismatch",
                        "assign register source width must match destination");
          }
          if (statement.a.kind == IrOperandKind::Constant &&
              statement.a.width > statement.dest.width) {
            return fail("ir.type_width_mismatch",
                        "assign constant source width cannot exceed destination");
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
          if (statement.dest.width != statement.width ||
              statement.a.width != statement.dest.width) {
            return fail("ir.type_width_mismatch",
                        "binary operation destination and operand 'a' width must match statement "
                        "width");
          }
          if (statement.op == IrOp::Shl || statement.op == IrOp::Shr || statement.op == IrOp::Sar) {
            if (statement.b.kind == IrOperandKind::Register &&
                statement.b.width != statement.dest.width && statement.b.width != 1) {
              return fail("ir.type_width_mismatch",
                          "shift count register width must match operand or be 1 byte");
            }
            if (statement.b.kind == IrOperandKind::Constant &&
                statement.b.width > statement.dest.width) {
              return fail("ir.type_width_mismatch",
                          "shift count constant width cannot exceed destination");
            }
          } else {
            if (statement.b.kind == IrOperandKind::Register &&
                statement.b.width != statement.dest.width) {
              return fail("ir.type_width_mismatch",
                          "binary operation register operands must have matching widths");
            }
            if (statement.b.kind == IrOperandKind::Constant &&
                statement.b.width > statement.dest.width) {
              return fail("ir.type_width_mismatch",
                          "binary operation constant cannot exceed destination width");
            }
          }
          break;
        case IrOp::Lea:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind != IrOperandKind::Memory) {
            return fail("ir.malformed_lea", "lea needs a register destination and memory source");
          }
          if (statement.dest.width != statement.width) {
            return fail("ir.type_width_mismatch",
                        "lea destination width must match statement width");
          }
          break;
        case IrOp::ZeroExtend:
        case IrOp::SignExtend:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind == IrOperandKind::None ||
              statement.dest.width <= statement.a.width) {
            return fail("ir.malformed_extend",
                        "extend needs a register destination strictly wider than its source");
          }
          if (statement.dest.width != statement.width) {
            return fail("ir.type_width_mismatch",
                        "extend statement width must match destination width");
          }
          break;
        case IrOp::Load:
          if (statement.dest.kind != IrOperandKind::Register ||
              statement.a.kind != IrOperandKind::Memory) {
            return fail("ir.malformed_load", "load needs a register destination and memory source");
          }
          if (statement.dest.width < statement.width) {
            return fail("ir.type_width_mismatch",
                        "load destination width must be at least statement memory access width");
          }
          break;
        case IrOp::Store:
          if (statement.a.kind != IrOperandKind::Memory ||
              statement.b.kind == IrOperandKind::None) {
            return fail("ir.malformed_store", "store needs a memory destination and a value");
          }
          if (statement.b.width != statement.width) {
            return fail("ir.type_width_mismatch", "store value width must match statement width");
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
        case IrOp::Switch:
          if (statement.dest.kind == IrOperandKind::None) {
            return fail("ir.malformed_switch", "switch needs a selector operand");
          }
          if (statement.a.kind != IrOperandKind::Block) {
            return fail("ir.malformed_switch", "switch needs a default block target");
          }
          break;
        case IrOp::Compare:
          if (statement.a.kind == IrOperandKind::None || statement.b.kind == IrOperandKind::None ||
              statement.condition == IrCondition::None) {
            return fail("ir.malformed_compare", "compare needs two operands and a condition");
          }
          if (statement.width != statement.a.width) {
            return fail("ir.type_width_mismatch",
                        "compare statement width must match operand 'a' width");
          }
          if (statement.b.kind == IrOperandKind::Register &&
              statement.b.width != statement.a.width) {
            return fail("ir.type_width_mismatch",
                        "compare register operands must have matching widths");
          }
          if (statement.b.kind == IrOperandKind::Constant &&
              statement.b.width > statement.a.width) {
            return fail("ir.type_width_mismatch",
                        "compare constant operand width cannot exceed operand 'a'");
          }
          break;
        case IrOp::Test:
          if (statement.a.kind == IrOperandKind::None || statement.b.kind == IrOperandKind::None) {
            return fail("ir.malformed_test", "test needs two operands");
          }
          if (statement.width != statement.a.width) {
            return fail("ir.type_width_mismatch",
                        "test statement width must match operand 'a' width");
          }
          if (statement.b.kind == IrOperandKind::Register &&
              statement.b.width != statement.a.width) {
            return fail("ir.type_width_mismatch",
                        "test register operands must have matching widths");
          }
          if (statement.b.kind == IrOperandKind::Constant &&
              statement.b.width > statement.a.width) {
            return fail("ir.type_width_mismatch",
                        "test constant operand width cannot exceed operand 'a'");
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
    if (last.op == IrOp::CondBranch && last.b.kind == IrOperandKind::Block &&
        last.b.block >= function.blocks.size()) {
      return fail("ir.bad_block_index", "conditional branch target is out of range");
    }
    if (last.op == IrOp::Switch) {
      if (last.a.kind == IrOperandKind::Block && last.a.block >= function.blocks.size()) {
        return fail("ir.bad_block_index", "switch default target is out of range");
      }
      for (const auto& sc : last.switch_cases) {
        if (sc.target_block >= function.blocks.size()) {
          return fail("ir.bad_block_index", "switch case target is out of range");
        }
      }
    }
  }

  // CFG construction, reachability, dominators, and SSA def-use validation
  if (!function.blocks.empty()) {
    detail::Graph graph = detail::build_graph(function);
    if (!graph.valid) {
      return make_error<bool>(Status::InternalError, "ir.malformed_control_flow",
                              "control flow graph has invalid edges", function.address);
    }
    std::vector<bool> reachable(function.blocks.size(), false);
    std::vector<std::size_t> worklist = {0};
    reachable[0] = true;
    while (!worklist.empty()) {
      std::size_t curr = worklist.back();
      worklist.pop_back();
      for (std::size_t succ : graph.successors[curr]) {
        if (succ < reachable.size() && !reachable[succ]) {
          reachable[succ] = true;
          worklist.push_back(succ);
        }
      }
    }
    for (std::size_t i = 1; i < reachable.size(); ++i) {
      if (!reachable[i]) {
        return make_error<bool>(Status::InternalError, "ir.unreachable_block",
                                "block is unreachable from function entry",
                                function.blocks[i].address);
      }
    }

    std::vector<detail::BitSet> dominators = detail::compute_dominators(graph);

    struct VarDef {
      std::size_t block_index = 0;
      std::size_t statement_index = 0;
      std::uint64_t address = 0;
    };
    std::unordered_map<std::string, std::vector<VarDef>> var_defs;

    auto is_temp_var = [](std::string_view name) {
      return name.starts_with("var_") || name.starts_with("tmp_");
    };

    for (std::size_t b_idx = 0; b_idx < function.blocks.size(); ++b_idx) {
      const auto& blk = function.blocks[b_idx];
      for (std::size_t s_idx = 0; s_idx < blk.statements.size(); ++s_idx) {
        const auto& stmt = blk.statements[s_idx];
        if (stmt.dest.kind == IrOperandKind::Register && is_temp_var(stmt.dest.reg)) {
          var_defs[stmt.dest.reg].push_back(
              VarDef{b_idx, s_idx, stmt.source_address ? stmt.source_address : blk.address});
        }
      }
    }

    for (std::size_t b_idx = 0; b_idx < function.blocks.size(); ++b_idx) {
      const auto& blk = function.blocks[b_idx];
      for (std::size_t s_idx = 0; s_idx < blk.statements.size(); ++s_idx) {
        const auto& stmt = blk.statements[s_idx];
        auto check_use = [&](const IrOperand& op) -> std::optional<Diagnostic> {
          if (op.kind == IrOperandKind::Register && is_temp_var(op.reg)) {
            auto it = var_defs.find(op.reg);
            if (it == var_defs.end()) {
              return Diagnostic::make(Status::InternalError, "ir.undefined_variable",
                                      "temporary '" + op.reg + "' used without definition",
                                      stmt.source_address ? stmt.source_address : blk.address);
            }
            const std::vector<VarDef>& defs = it->second;
            bool defined_before_in_block = false;
            bool defined_later_in_block = false;
            for (const auto& def : defs) {
              if (def.block_index == b_idx) {
                if (def.statement_index < s_idx) {
                  defined_before_in_block = true;
                } else if (def.statement_index >= s_idx) {
                  defined_later_in_block = true;
                }
              }
            }
            if (defined_before_in_block) {
              return std::nullopt;
            }
            if (defined_later_in_block) {
              return Diagnostic::make(Status::InternalError, "ir.use_before_def",
                                      "temporary '" + op.reg + "' used before definition in block",
                                      stmt.source_address ? stmt.source_address : blk.address);
            }
            bool dominated = false;
            for (const auto& def : defs) {
              if (def.block_index != b_idx && dominators[b_idx].test(def.block_index)) {
                dominated = true;
                break;
              }
            }
            if (!dominated) {
              return Diagnostic::make(
                  Status::InternalError, "ir.invalid_dominator_use",
                  "temporary '" + op.reg + "' used in block not dominated by definition",
                  stmt.source_address ? stmt.source_address : blk.address);
            }
          }
          return std::nullopt;
        };

        if (auto diag = check_use(stmt.a); diag.has_value()) {
          return make_error<bool>(diag->status, diag->code, diag->message, diag->offset);
        }
        if (auto diag = check_use(stmt.b); diag.has_value()) {
          return make_error<bool>(diag->status, diag->code, diag->message, diag->offset);
        }
        if (stmt.op == IrOp::Switch) {
          if (auto diag = check_use(stmt.dest); diag.has_value()) {
            return make_error<bool>(diag->status, diag->code, diag->message, diag->offset);
          }
        }
      }
    }
  }

  return true;
}

Result<Pseudocode> format_pseudocode_lines(const IrFunction& function) {
  auto verified = verify_ir(function);
  if (!verified) {
    return make_error<Pseudocode>(verified.diagnostic().status, verified.diagnostic().code,
                                  verified.diagnostic().message, verified.diagnostic().offset);
  }

  const Renderer renderer(function);
  Pseudocode out;
  auto append_line = [&](const std::string& line, std::uint64_t source_address = 0) {
    out.lines.push_back(PseudocodeLine{line, source_address});
    out.full_text += line + "\n";
  };

  std::string header = "// " + (function.name.empty() ? std::string("sub_1000") : function.name);
  if (function.partial) {
    header += "  [partial]";
  }
  append_line(header);

  if (!function.notes.empty()) {
    for (const std::string& note : function.notes) {
      append_line("// note: " + note);
    }
  }

  std::string signature;
  signature += function.return_width != 0 ? width_type(function.return_width) : "void";
  signature += " ";
  signature += function.name.empty() ? std::string("sub") : function.name;
  signature += "(";
  if (function.parameters.empty()) {
    signature += "void";
  } else {
    for (std::size_t index = 0; index < function.parameters.size(); ++index) {
      if (index != 0) {
        signature += ", ";
      }
      signature += width_type(function.parameters[index].width);
      signature += " ";
      signature += function.parameters[index].name;
    }
  }
  signature += ") {";
  append_line(signature);

  for (const auto& var : function.local_variables) {
    if (!var.is_parameter) {
      append_line("  " + std::string(width_type(var.width)) + " " + var.name + ";");
    }
  }

  // Prefer structured control flow. When the graph does not match a shape the
  // structurer models, fall back to labeled blocks with explicit `goto`; the
  // fallback is still verified IR, never guessed structure.
  if (auto structured = detail::format_structured_body_lines(function); structured.has_value()) {
    for (const auto& sline : structured.value()) {
      append_line(sline.text, sline.source_address);
    }
    append_line("}");
    return out;
  }

  append_line("// note: control flow not fully structured; showing labeled blocks");
  for (std::size_t index = 0; index < function.blocks.size(); ++index) {
    const IrBlock& block = function.blocks[index];
    append_line("loc_" + Renderer::hex(block.address) + ":", block.address);
    for (std::size_t statement_index = 0; statement_index < block.statements.size();
         ++statement_index) {
      const IrStatement& statement = block.statements[statement_index];
      const IrStatement* previous =
          statement_index == 0 ? nullptr : &block.statements[statement_index - 1];
      std::string line = renderer.statement(statement, previous);
      if (line.empty()) {
        continue;
      }
      append_line("  " + line, statement.source_address);
    }
  }
  append_line("}");
  return out;
}

Result<std::string> format_pseudocode(const IrFunction& function) {
  auto res = format_pseudocode_lines(function);
  if (!res) {
    return make_error<std::string>(res.diagnostic().status, res.diagnostic().code,
                                   res.diagnostic().message, res.diagnostic().offset);
  }
  return res.value().full_text;
}

void recover_stack_variables(IrFunction& function) {
  function.local_variables.clear();

  auto is_frame_reg = [](std::string_view reg) {
    return reg == "rbp" || reg == "ebp" || reg == "bp" || reg == "x29";
  };
  auto is_stack_reg = [](std::string_view reg) {
    return reg == "rsp" || reg == "esp" || reg == "sp";
  };

  auto inspect_operand = [&](const IrOperand& op) {
    if (op.kind != IrOperandKind::Memory) {
      return;
    }
    const auto disp = static_cast<std::int64_t>(op.constant);
    std::string name;
    bool is_param = false;
    if (is_frame_reg(op.reg)) {
      if (disp > 0) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "arg_%llx", static_cast<unsigned long long>(disp));
        name = buf;
        is_param = true;
      } else if (disp < 0) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "local_%llx", static_cast<unsigned long long>(-disp));
        name = buf;
      } else {
        name = "saved_fp";
      }
    } else if (is_stack_reg(op.reg)) {
      char buf[32];
      if (disp >= 0) {
        std::snprintf(buf, sizeof(buf), "local_sp_%llx", static_cast<unsigned long long>(disp));
      } else {
        std::snprintf(buf, sizeof(buf), "local_sp_neg_%llx",
                      static_cast<unsigned long long>(-disp));
      }
      name = buf;
    } else {
      return;
    }

    for (const auto& existing : function.local_variables) {
      if (existing.base_reg == op.reg && existing.offset == disp) {
        return;
      }
    }

    IrLocalVariable var;
    var.name = std::move(name);
    var.width = op.width != 0 ? op.width : 4;
    var.offset = disp;
    var.base_reg = op.reg;
    var.is_parameter = is_param;
    function.local_variables.push_back(std::move(var));
  };

  for (const auto& block : function.blocks) {
    for (const auto& stmt : block.statements) {
      inspect_operand(stmt.dest);
      inspect_operand(stmt.a);
      inspect_operand(stmt.b);
    }
  }

  std::sort(function.local_variables.begin(), function.local_variables.end(),
            [](const IrLocalVariable& a, const IrLocalVariable& b) {
              if (a.is_parameter != b.is_parameter) {
                return a.is_parameter < b.is_parameter;
              }
              return a.offset < b.offset;
            });
}

}  // namespace donkey
