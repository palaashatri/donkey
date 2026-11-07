#include "donkey/ir/local_names.h"

#include <cstdint>
#include <map>
#include <set>
#include <utility>

namespace donkey {
namespace {

constexpr std::size_t kMaxNameBytes = 128;
constexpr std::uint64_t kMaxArgumentIndex = 1023;
constexpr std::uint64_t kMaxFrameOffset = 1ULL << 40;

const std::set<std::string>& c_keywords() {
  static const std::set<std::string> keywords = {
      "auto",  "bool",     "break",  "case",     "char",   "const",    "continue", "default",
      "do",    "double",   "else",   "enum",     "extern", "false",    "float",    "for",
      "goto",  "if",       "inline", "int",      "long",   "register", "restrict", "return",
      "short", "signed",   "sizeof", "static",   "struct", "switch",   "true",     "typedef",
      "union", "unsigned", "void",   "volatile", "while",  "NULL"};
  return keywords;
}

bool is_c_identifier(const std::string& name) {
  if (name.empty() || name.size() > kMaxNameBytes) {
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

bool is_register_name(const std::string& text) {
  if (text.empty() || text.size() > 16) {
    return false;
  }
  for (const char c : text) {
    const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    if (!alnum) {
      return false;
    }
  }
  return true;
}

/// Plain decimal digits: no sign, no leading zero, at most 19 digits.
bool parse_digits(const std::string& text, std::uint64_t& value) {
  if (text.empty() || text.size() > 19 || (text.size() > 1 && text[0] == '0')) {
    return false;
  }
  value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10U + static_cast<std::uint64_t>(c - '0');
  }
  return true;
}

/// A parsed key: a parameter index, or a frame base register and signed offset.
struct Key {
  bool argument = false;
  std::size_t index = 0;
  std::string base;
  std::int64_t offset = 0;
};

bool parse_key(const std::string& variable, Key& key) {
  if (variable.rfind("arg:", 0) == 0) {
    std::uint64_t index = 0;
    if (!parse_digits(variable.substr(4), index) || index > kMaxArgumentIndex) {
      return false;
    }
    key.argument = true;
    key.index = static_cast<std::size_t>(index);
    return true;
  }
  if (variable.rfind("frame:", 0) == 0) {
    const std::string rest = variable.substr(6);
    const std::size_t colon = rest.find(':');
    if (colon == std::string::npos || !is_register_name(rest.substr(0, colon))) {
      return false;
    }
    std::string digits = rest.substr(colon + 1);
    const bool negative = !digits.empty() && digits[0] == '-';
    if (negative) {
      digits.erase(0, 1);
    }
    std::uint64_t magnitude = 0;
    if (!parse_digits(digits, magnitude) || magnitude > kMaxFrameOffset ||
        (negative && magnitude == 0)) {
      return false;
    }
    key.argument = false;
    key.base = rest.substr(0, colon);
    key.offset =
        negative ? -static_cast<std::int64_t>(magnitude) : static_cast<std::int64_t>(magnitude);
    return true;
  }
  return false;
}

}  // namespace

Result<LocalNameResult> apply_user_local_names(IrFunction& function,
                                               const std::vector<UserLocalName>& names) {
  // Pass 1: check every name and key before anything changes.
  struct Plan {
    Key key;
    std::string name;
    std::string variable;
  };
  std::vector<Plan> plans;
  std::set<std::string> seen_keys;
  for (const UserLocalName& entry : names) {
    if (!is_c_identifier(entry.name) || c_keywords().count(entry.name) != 0) {
      return make_error<LocalNameResult>(
          Status::InvalidInput, "ir.local_name_invalid",
          "local name '" + entry.name + "' is not a C identifier that is not a keyword");
    }
    Key key;
    if (!parse_key(entry.variable, key)) {
      return make_error<LocalNameResult>(
          Status::InvalidInput, "ir.local_key_invalid",
          "local key '" + entry.variable + "' is not arg:<index> or frame:<base>:<offset>");
    }
    if (!seen_keys.insert(entry.variable).second) {
      return make_error<LocalNameResult>(Status::InvalidInput, "ir.local_name_duplicate",
                                         "local key '" + entry.variable + "' is named twice");
    }
    plans.push_back(Plan{key, entry.name, entry.variable});
  }

  // Pass 2: find the target of each key. A key that names nothing is stale: it is skipped, and
  // the function gets a note for it when the names are applied.
  LocalNameResult result;
  std::map<std::size_t, std::string> parameter_names;
  std::map<std::size_t, std::string> local_names;
  std::map<std::pair<std::string, std::int64_t>, std::string> frame_names;
  std::vector<IrLocalVariable> created;
  std::vector<std::string> stale_variables;
  for (const Plan& plan : plans) {
    if (plan.key.argument) {
      if (plan.key.index >= function.parameters.size()) {
        stale_variables.push_back(plan.variable);
        ++result.stale;
        continue;
      }
      parameter_names[plan.key.index] = plan.name;
      ++result.applied;
      continue;
    }
    std::size_t found = function.local_variables.size();
    for (std::size_t j = 0; j < function.local_variables.size(); ++j) {
      const IrLocalVariable& local = function.local_variables[j];
      if (local.base_reg == plan.key.base && local.offset == plan.key.offset) {
        found = j;
        break;
      }
    }
    if (found != function.local_variables.size()) {
      local_names[found] = plan.name;
      frame_names[{plan.key.base, plan.key.offset}] = plan.name;
      ++result.applied;
      continue;
    }
    // recover_stack_variables does not run on the decompiler's output, so a slot that the function
    // accesses may have no local yet. It becomes one here, with the width of its accesses. A slot
    // that no access uses names nothing.
    std::uint8_t width = 0;
    for (const IrBlock& block : function.blocks) {
      for (const IrStatement& statement : block.statements) {
        for (const IrOperand* operand :
             {&statement.dest, &statement.a, &statement.b, &statement.c}) {
          if (width == 0 && operand->kind == IrOperandKind::Memory && operand->index.empty() &&
              operand->reg == plan.key.base &&
              static_cast<std::int64_t>(operand->constant) == plan.key.offset) {
            width = operand->width != 0 ? operand->width : 4;
          }
        }
      }
    }
    if (width == 0) {
      stale_variables.push_back(plan.variable);
      ++result.stale;
      continue;
    }
    IrLocalVariable local;
    local.name = plan.name;
    local.width = width;
    local.offset = plan.key.offset;
    local.base_reg = plan.key.base;
    created.push_back(std::move(local));
    frame_names[{plan.key.base, plan.key.offset}] = plan.name;
    ++result.applied;
  }
  if (result.applied == 0) {
    // Nothing is renamed, but each stale key is reported in the notes.
    for (const std::string& name : stale_variables) {
      function.notes.push_back("local key '" + name + "' names no local of this function");
    }
    return result;
  }

  // Pass 3: a new name must not equal any name that stays, or any other new name. The names that
  // stay are the unchanged parameters and locals, and the names of frame operands that are not
  // being renamed.
  std::multiset<std::string> applied_names;
  for (const auto& [index, name] : parameter_names) {
    (void)index;
    applied_names.insert(name);
  }
  for (const auto& [index, name] : local_names) {
    (void)index;
    applied_names.insert(name);
  }
  for (const IrLocalVariable& local : created) {
    applied_names.insert(local.name);
  }
  std::set<std::string> staying;
  for (std::size_t i = 0; i < function.parameters.size(); ++i) {
    if (parameter_names.count(i) == 0) {
      staying.insert(function.parameters[i].name);
    }
  }
  for (std::size_t j = 0; j < function.local_variables.size(); ++j) {
    if (local_names.count(j) == 0) {
      staying.insert(function.local_variables[j].name);
    }
  }
  for (IrBlock& block : function.blocks) {
    for (IrStatement& statement : block.statements) {
      for (IrOperand* operand : {&statement.dest, &statement.a, &statement.b, &statement.c}) {
        if (operand->kind != IrOperandKind::Memory || operand->name.empty() ||
            !operand->index.empty()) {
          continue;
        }
        const auto key = std::make_pair(operand->reg, static_cast<std::int64_t>(operand->constant));
        if (frame_names.count(key) == 0) {
          staying.insert(operand->name);
        }
      }
    }
  }
  std::set<std::string> distinct(applied_names.begin(), applied_names.end());
  for (const std::string& name : distinct) {
    if (staying.count(name) != 0 || applied_names.count(name) > 1) {
      return make_error<LocalNameResult>(
          Status::InvalidInput, "ir.local_name_collision",
          "local name '" + name + "' is already the name of another local");
    }
  }

  // Pass 4: apply. The operands of a renamed frame slot take the new name too, because a debug
  // name already on an operand would otherwise win in the printed output.
  for (const auto& [index, name] : parameter_names) {
    function.parameters[index].name = name;
  }
  for (const auto& [index, name] : local_names) {
    function.local_variables[index].name = name;
  }
  for (IrLocalVariable& local : created) {
    function.local_variables.push_back(std::move(local));
  }
  for (const std::string& name : stale_variables) {
    function.notes.push_back("local key '" + name + "' names no local of this function");
  }
  for (IrBlock& block : function.blocks) {
    for (IrStatement& statement : block.statements) {
      for (IrOperand* operand : {&statement.dest, &statement.a, &statement.b, &statement.c}) {
        if (operand->kind != IrOperandKind::Memory || operand->name.empty() ||
            !operand->index.empty()) {
          continue;
        }
        const auto key = std::make_pair(operand->reg, static_cast<std::int64_t>(operand->constant));
        const auto found = frame_names.find(key);
        if (found != frame_names.end()) {
          operand->name = found->second;
        }
      }
    }
  }
  return result;
}

}  // namespace donkey
