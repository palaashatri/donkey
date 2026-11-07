#include "donkey/ir/debug_names.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace donkey {
namespace {

constexpr std::size_t kMaxTypeDepth = 64;

bool is_identifier(const std::string& name) {
  if (name.empty()) {
    return false;
  }
  for (std::size_t i = 0; i < name.size(); ++i) {
    const char c = name[i];
    const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    const bool digit = c >= '0' && c <= '9';
    if (!letter && !(digit && i > 0)) {
      return false;
    }
  }
  return true;
}

/// The size and class of a scalar debug type, following typedefs and qualifiers. False
/// for a structure, union, array, function or unknown type.
bool scalar_of(const DebugInfo& info, std::uint64_t type, std::uint8_t& width, bool& floating) {
  for (std::size_t depth = 0; depth < kMaxTypeDepth && type != 0; ++depth) {
    const auto found = info.types.find(type);
    if (found == info.types.end()) {
      return false;
    }
    const DebugType& debug = found->second;
    if (debug.kind == DebugTypeKind::Typedef || debug.kind == DebugTypeKind::Const ||
        debug.kind == DebugTypeKind::Volatile || debug.kind == DebugTypeKind::Restrict) {
      type = debug.target;
      continue;
    }
    if (debug.kind != DebugTypeKind::Base && debug.kind != DebugTypeKind::Pointer &&
        debug.kind != DebugTypeKind::Enum) {
      return false;
    }
    if (debug.byte_size == 0 || debug.byte_size > 16) {
      return false;
    }
    width = static_cast<std::uint8_t>(debug.byte_size);
    floating = debug.kind == DebugTypeKind::Base &&
               (debug.name == "float" || debug.name == "double" || debug.name == "long double");
    return true;
  }
  return false;
}

}  // namespace

Result<bool> apply_debug_stack_names(IrFunction& function, const DebugFunction& debug,
                                     const DebugInfo& info) {
  // The frame slots that can be named: one scalar slot per CFA offset, with an identifier
  // name. An offset held by two slots, or by a slot that is not a scalar, names nothing.
  struct Slot {
    std::string name;
    std::uint8_t width = 0;
    bool usable = false;
  };
  std::map<std::int64_t, Slot> slots;
  std::map<std::int64_t, std::size_t> occurrences;
  for (const DebugStackSlot& slot : debug.stack_slots) {
    ++occurrences[slot.cfa_offset];
    Slot& entry = slots[slot.cfa_offset];
    std::uint8_t width = 0;
    bool floating = false;
    entry.usable = is_identifier(slot.name) && scalar_of(info, slot.type, width, floating);
    entry.name = slot.name;
    entry.width = width;
  }

  // Pass 1: the stack pointer must move only by constants, and the frame must balance. Then
  // the offset of an access from the CFA is -8 + delta + displacement, where delta is the
  // stack pointer's movement from the entry value (the entry value is CFA - 8). Anything
  // else leaves the offsets unknown, so the function is left unnamed.
  std::int64_t delta = 0;
  for (const IrBlock& block : function.blocks) {
    for (const IrStatement& statement : block.statements) {
      if (statement.dest.kind != IrOperandKind::Register || statement.dest.reg != "rsp") {
        continue;
      }
      if ((statement.op != IrOp::Add && statement.op != IrOp::Sub) ||
          statement.a.kind != IrOperandKind::Register || statement.a.reg != "rsp" ||
          statement.b.kind != IrOperandKind::Constant) {
        return false;
      }
      const auto amount = static_cast<std::int64_t>(statement.b.constant);
      delta += statement.op == IrOp::Add ? amount : -amount;
    }
  }
  if (delta != 0) {
    return false;
  }

  // Pass 2: name each rsp-based access whose CFA offset is a usable slot of its width.
  bool named = false;
  delta = 0;
  for (IrBlock& block : function.blocks) {
    for (IrStatement& statement : block.statements) {
      for (IrOperand* operand : {&statement.dest, &statement.a, &statement.b, &statement.c}) {
        if (operand->kind != IrOperandKind::Memory || operand->reg != "rsp" ||
            !operand->index.empty()) {
          continue;
        }
        const auto displacement = static_cast<std::int64_t>(operand->constant);
        const std::int64_t cfa_offset = -8 + delta + displacement;
        const auto found = slots.find(cfa_offset);
        if (found == slots.end() || !found->second.usable || occurrences[cfa_offset] != 1 ||
            found->second.width != operand->width) {
          continue;
        }
        operand->name = found->second.name;
        named = true;
      }
      if (statement.dest.kind == IrOperandKind::Register && statement.dest.reg == "rsp") {
        const auto amount = static_cast<std::int64_t>(statement.b.constant);
        delta += statement.op == IrOp::Add ? amount : -amount;
      }
    }
  }
  return named;
}

Result<bool> apply_debug_parameter_names(IrFunction& function, const DebugFunction& debug,
                                         const DebugInfo& info) {
  const auto refuse = [&function](const char* code, std::string message) {
    return make_error<bool>(Status::InvalidInput, code, std::move(message), function.address);
  };

  if (debug.parameters.size() != function.parameters.size()) {
    return refuse("ir.debug_names_arity", "the debug information has " +
                                              std::to_string(debug.parameters.size()) +
                                              " parameters and the function has " +
                                              std::to_string(function.parameters.size()));
  }

  std::vector<std::string> names;
  for (std::size_t i = 0; i < function.parameters.size(); ++i) {
    const DebugParameter& parameter = debug.parameters[i];
    const IrParameter& inferred = function.parameters[i];
    const std::string where = "parameter " + std::to_string(i);

    std::uint8_t width = 0;
    bool floating = false;
    if (!scalar_of(info, parameter.type, width, floating)) {
      return refuse("ir.debug_names_type",
                    where + " ('" + parameter.name +
                        "') is not a scalar, so it cannot be matched to a register");
    }
    if (width != inferred.width || floating != inferred.floating_point) {
      return refuse("ir.debug_names_type", where + " is " + std::to_string(width) +
                                               " bytes in the debug information, " +
                                               "but the function reads it in " +
                                               std::to_string(inferred.width) + " bytes");
    }
    if (!is_identifier(parameter.name)) {
      return refuse("ir.debug_names_name", "'" + parameter.name + "' is not a C identifier");
    }
    if (std::find(names.begin(), names.end(), parameter.name) != names.end()) {
      return refuse("ir.debug_names_name",
                    "the name '" + parameter.name + "' is used by two parameters");
    }
    names.push_back(parameter.name);
  }

  // Everything checks out. Pointer structures refer to parameters by name, so they follow.
  std::vector<std::string> inferred_names;
  for (const IrParameter& parameter : function.parameters) {
    inferred_names.push_back(parameter.name);
  }
  for (IrPointerStruct& recovered : function.pointer_structs) {
    const auto index = std::find(inferred_names.begin(), inferred_names.end(), recovered.parameter);
    if (index != inferred_names.end()) {
      recovered.parameter = names[static_cast<std::size_t>(index - inferred_names.begin())];
    }
  }
  for (std::size_t i = 0; i < function.parameters.size(); ++i) {
    function.parameters[i].name = names[i];
  }
  function.notes.push_back("parameter names come from the debug information");
  return true;
}

}  // namespace donkey
