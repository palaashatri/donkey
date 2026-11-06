#include "donkey/ir/prototype.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace donkey {
namespace {

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

/// The member of `layout` that starts at `offset`, or null when there is none.
const IrTypeField* member_at(const IrTypeLayout& layout, std::int64_t offset) {
  if (offset < 0) {
    return nullptr;
  }
  for (const IrTypeField& member : layout.fields) {
    if (member.offset == static_cast<std::uint64_t>(offset)) {
      return &member;
    }
  }
  return nullptr;
}

std::string hex(std::uint64_t value) {
  char buffer[24];
  std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
  return buffer;
}

}  // namespace

Result<bool> apply_prototype(IrFunction& function, const IrPrototype& prototype) {
  const auto refuse = [&function](const char* code, std::string message) {
    return make_error<bool>(Status::InvalidInput, code, std::move(message), function.address);
  };

  if (prototype.parameters.size() != function.parameters.size()) {
    return refuse("ir.prototype_arity", "the prototype has " +
                                            std::to_string(prototype.parameters.size()) +
                                            " parameters and the function has " +
                                            std::to_string(function.parameters.size()));
  }
  if (prototype.return_width != function.return_width ||
      (prototype.return_width != 0 &&
       prototype.return_floating_point != function.return_floating_point)) {
    return refuse("ir.prototype_return",
                  "the prototype's return value does not match the value the function returns");
  }

  // Pointer structures are matched by the parameter names the function has now,
  // before any renaming.
  std::vector<std::string> names;
  std::vector<std::ptrdiff_t> recovered_index(function.parameters.size(), -1);
  for (std::size_t i = 0; i < function.parameters.size(); ++i) {
    const IrParameter& inferred = function.parameters[i];
    const IrPrototypeParameter& declared = prototype.parameters[i];
    const std::string where = "parameter " + std::to_string(i) + " ('" + inferred.name + "')";

    if (declared.width != inferred.width || declared.floating_point != inferred.floating_point) {
      return refuse(
          "ir.prototype_parameter",
          where + " has a different width or class from the function's inferred parameter");
    }
    if (declared.pointee && declared.width != 8) {
      return refuse("ir.prototype_parameter",
                    where + " points to a structure, so it must be 8 bytes wide");
    }
    const std::string final_name = declared.name.empty() ? inferred.name : declared.name;
    if (!is_identifier(final_name)) {
      return refuse("ir.prototype_name", "'" + final_name + "' is not a C identifier");
    }
    if (std::find(names.begin(), names.end(), final_name) != names.end()) {
      return refuse("ir.prototype_name", "the name '" + final_name + "' is used by two parameters");
    }
    names.push_back(final_name);

    for (std::size_t p = 0; p < function.pointer_structs.size(); ++p) {
      if (function.pointer_structs[p].parameter == inferred.name) {
        recovered_index[i] = static_cast<std::ptrdiff_t>(p);
      }
    }
    if (!declared.pointee) {
      continue;  // not a pointer to a named structure: a recovered layout keeps its name
    }
    if (!inferred.pointee_struct.empty() && inferred.pointee_struct != declared.pointee->name) {
      return refuse("ir.prototype_conflict",
                    where + " already has type struct " + inferred.pointee_struct);
    }
    if (recovered_index[i] < 0) {
      continue;  // the function never accesses the structure; only the type is applied
    }
    // Every access the function makes through this parameter must be a scalar member
    // of the named structure, at the same offset and of the same width.
    for (const IrStructField& access :
         function.pointer_structs[static_cast<std::size_t>(recovered_index[i])].fields) {
      const IrTypeField* member = member_at(*declared.pointee, access.offset);
      if (member == nullptr) {
        return refuse("ir.prototype_field", where + " is read at offset " +
                                                hex(static_cast<std::uint64_t>(access.offset)) +
                                                ", which is not a member of struct " +
                                                declared.pointee->name);
      }
      if (member->width != access.width) {
        return refuse("ir.prototype_field",
                      "member '" + member->name + "' of struct " + declared.pointee->name + " is " +
                          std::to_string(member->width) + " bytes, but the function reads " +
                          std::to_string(access.width) + " bytes at that offset");
      }
    }
  }

  // Everything checks out: now change the function. Statements are not touched.
  for (std::size_t i = 0; i < function.parameters.size(); ++i) {
    IrParameter& parameter = function.parameters[i];
    const IrPrototypeParameter& declared = prototype.parameters[i];
    parameter.name = names[i];
    if (declared.pointee) {
      parameter.pointee_struct = declared.pointee->name;
    }
    if (recovered_index[i] < 0) {
      continue;
    }
    IrPointerStruct& recovered =
        function.pointer_structs[static_cast<std::size_t>(recovered_index[i])];
    recovered.parameter = parameter.name;
    if (!declared.pointee) {
      continue;
    }
    recovered.type_name = declared.pointee->name;
    recovered.applied = true;
    for (IrStructField& field : recovered.fields) {
      if (const IrTypeField* member = member_at(*declared.pointee, field.offset)) {
        field.name = member->name;
      }
    }
  }
  if (!prototype.name.empty()) {
    function.notes.push_back("parameter and return types come from the applied prototype " +
                             prototype.name);
  }
  return true;
}

}  // namespace donkey
