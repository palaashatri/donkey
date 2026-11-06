#include "donkey/ir/debug_names.h"

#include <algorithm>
#include <cstddef>
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
