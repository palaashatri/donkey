#include "donkey/ir/abi.h"

#include "registers.h"

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace donkey {
namespace {

/// An XMM register (x86) or a scalar s or d register (AArch64) used as an argument.
bool is_fp_register(const std::string& name) {
  return name.rfind("xmm", 0) == 0 || internal::scalar_fp_width(name) != 0;
}

struct Alias {
  std::string name;
  std::uint8_t width = 8;
};

struct RegisterFamily {
  std::vector<Alias> aliases;
};

struct AbiModel {
  std::vector<RegisterFamily> arguments;
  std::vector<Alias> return_aliases;
  std::string convention_name = "ABI";
};

AbiModel model_for(Architecture architecture, BinaryFormat format) {
  AbiModel model;
  switch (architecture) {
    case Architecture::X86_64:
      if (format == BinaryFormat::Pe) {
        // Microsoft x64 calling convention: integer arguments in rcx, rdx, r8, r9
        // and the result in rax.
        // Each position is either an integer register or the XMM register of the same
        // position: a floating-point argument in position 1 arrives in xmm1.
        model.arguments = {
            {{{"rcx", 8}, {"ecx", 4}, {"cx", 2}, {"cl", 1}, {"xmm0", 8}}},
            {{{"rdx", 8}, {"edx", 4}, {"dx", 2}, {"dl", 1}, {"xmm1", 8}}},
            {{{"r8", 8}, {"r8d", 4}, {"r8w", 2}, {"r8b", 1}, {"xmm2", 8}}},
            {{{"r9", 8}, {"r9d", 4}, {"r9w", 2}, {"r9b", 1}, {"xmm3", 8}}},
        };
        model.return_aliases = {{"rax", 8}, {"eax", 4}, {"ax", 2}, {"al", 1}, {"xmm0", 8}};
        model.convention_name = "Microsoft x64 calling convention";
      } else {
        // System V AMD64: integer arguments in rdi, rsi, rdx, rcx, r8, r9 and the
        // result in rax. Only aliases the x86-64 lifter can emit are listed.
        // Floating-point arguments use xmm0 to xmm7 in order, independently of the
        // integer registers.
        model.arguments = {
            {{{"rdi", 8}, {"edi", 4}, {"di", 2}, {"dil", 1}}},
            {{{"rsi", 8}, {"esi", 4}, {"si", 2}, {"sil", 1}}},
            {{{"rdx", 8}, {"edx", 4}, {"dx", 2}, {"dl", 1}}},
            {{{"rcx", 8}, {"ecx", 4}, {"cx", 2}, {"cl", 1}}},
            {{{"r8", 8}, {"r8d", 4}, {"r8w", 2}, {"r8b", 1}}},
            {{{"r9", 8}, {"r9d", 4}, {"r9w", 2}, {"r9b", 1}}},
        };
        for (int index = 0; index < 8; ++index) {
          model.arguments.push_back({{{"xmm" + std::to_string(index), 8}}});
        }
        model.return_aliases = {{"rax", 8}, {"eax", 4}, {"ax", 2}, {"al", 1}, {"xmm0", 8}};
        model.convention_name = "System V AMD64 ABI";
      }
      break;
    case Architecture::AArch64:
      // AAPCS64: integer arguments in x0..x7, integer result in x0. x0 is both
      // the first argument and the return register, so `ret`'s read of x0 is
      // excluded from argument detection below.
      for (int index = 0; index < 8; ++index) {
        model.arguments.push_back(
            {{{("x" + std::to_string(index)), 8}, {("w" + std::to_string(index)), 4}}});
      }
      // Floating-point arguments use v0 to v7, read as d (8 bytes) or s (4 bytes).
      for (int index = 0; index < 8; ++index) {
        model.arguments.push_back(
            {{{"d" + std::to_string(index), 8}, {"s" + std::to_string(index), 4}}});
      }
      model.return_aliases = {{"x0", 8}, {"w0", 4}, {"d0", 8}, {"s0", 4}};
      model.convention_name = "AAPCS64 ABI";
      break;
    case Architecture::X86:
      // x86-32 cdecl passes every argument on the stack, so there are no
      // argument registers to recover. The result is in eax (formally
      // edx:eax for 64-bit values, which this model does not cover). Leaving
      // `arguments` empty means infer_signature reports no parameters, which
      // is the honest reading rather than inventing stack slots.
      model.return_aliases = {{"eax", 4}, {"ax", 2}, {"al", 1}};
      model.convention_name = "x86-32 ABI";
      break;
    default:
      break;
  }
  return model;
}

std::optional<std::size_t> family_of(const std::vector<RegisterFamily>& families,
                                     const std::string& name) {
  for (std::size_t index = 0; index < families.size(); ++index) {
    for (const Alias& alias : families[index].aliases) {
      if (alias.name == name) {
        return index;
      }
    }
  }
  return std::nullopt;
}

std::optional<std::uint8_t> width_of(const std::vector<Alias>& aliases, const std::string& name) {
  for (const Alias& alias : aliases) {
    if (alias.name == name) {
      return alias.width;
    }
  }
  return std::nullopt;
}

/// The width at which `statement` reads register `name`, or 8 when it does not say.
std::uint8_t read_width(const IrStatement& statement, const std::string& name) {
  for (const IrOperand* operand : {&statement.a, &statement.b, &statement.c}) {
    if (operand->kind == IrOperandKind::Register && operand->reg == name && operand->width != 0) {
      return operand->width;
    }
  }
  return 8;
}

/// Registers an operand reads. Block operands read nothing.
void collect_reads(const IrOperand& operand, std::vector<std::string>& out) {
  switch (operand.kind) {
    case IrOperandKind::Register:
      out.push_back(operand.reg);
      break;
    case IrOperandKind::Memory:
      if (!operand.reg.empty()) {
        out.push_back(operand.reg);
      }
      if (!operand.index.empty()) {
        out.push_back(operand.index);
      }
      break;
    case IrOperandKind::None:
    case IrOperandKind::Constant:
    case IrOperandKind::Block:
      break;
  }
}

struct Scan {
  std::vector<bool> argument_read;  // read before any write of the family
  std::vector<bool> argument_written;
  std::vector<std::uint8_t> argument_width;
  // The register each argument was first read from. A family can name several
  // (Microsoft x64 position 1 is rdx or xmm1), so the parameter keeps this one.
  std::vector<std::string> argument_register;
  bool has_value_return = false;
  bool has_bare_return = false;
  // Default to the width of the ABI's own return register (rax/x0: 8, eax: 4)
  // so a function that never writes it still reports the right size.
  std::uint8_t current_return_width = 8;
  std::uint8_t widest_return_width = 0;
};

Scan scan(const IrFunction& function, const AbiModel& model) {
  Scan result;
  if (!model.return_aliases.empty()) {
    result.current_return_width = model.return_aliases.front().width;
  }
  const std::size_t argument_count = model.arguments.size();
  result.argument_read.assign(argument_count, false);
  result.argument_written.assign(argument_count, false);
  result.argument_width.assign(argument_count, 0);
  result.argument_register.assign(argument_count, std::string());

  std::vector<std::string> reads;
  for (const IrBlock& block : function.blocks) {
    for (const IrStatement& statement : block.statements) {
      // A return reads the result register, not an incoming argument. Treating
      // it as a read would report `x0`/`rax` as a parameter of every function.
      if (statement.op == IrOp::Return) {
        if (statement.a.kind == IrOperandKind::Register) {
          result.has_value_return = true;
          // The lifter spells the return operand as the full pointer register
          // (`rax`, `x0`), so its width says nothing about the source type. The
          // last write to that family is the better signal (`mov eax, ...`
          // returns 4 bytes); fall back to the operand width only for a
          // register the ABI model does not know.
          std::uint8_t width = statement.a.width != 0 ? statement.a.width : 8;
          if (width_of(model.return_aliases, statement.a.reg).has_value()) {
            width = result.current_return_width != 0 ? result.current_return_width : width;
          }
          if (width > result.widest_return_width) {
            result.widest_return_width = width;
          }
        } else if (statement.a.kind == IrOperandKind::None) {
          result.has_bare_return = true;
        }
        continue;
      }

      reads.clear();
      collect_reads(statement.a, reads);
      collect_reads(statement.b, reads);
      collect_reads(statement.c, reads);  // the divisor of Div and Rem
      if (statement.dest.kind == IrOperandKind::Memory) {
        collect_reads(statement.dest, reads);
      }

      // Reads happen before the write in one statement, so a read of an
      // as-yet-unwritten argument register is an incoming value.
      for (const std::string& name : reads) {
        const auto family = family_of(model.arguments, name);
        if (!family.has_value()) {
          continue;
        }
        const std::size_t index = family.value();
        if (!result.argument_written[index]) {
          if (!result.argument_read[index]) {
            result.argument_register[index] = name;
          }
          result.argument_read[index] = true;
          // An XMM argument is as wide as the read that uses it: 4 for a single.
          const auto width = is_fp_register(name)
                                 ? std::optional<std::uint8_t>(read_width(statement, name))
                                 : width_of(model.arguments[index].aliases, name);
          if (width.has_value() && width.value() > result.argument_width[index]) {
            result.argument_width[index] = width.value();
          }
        }
      }

      if (statement.dest.kind == IrOperandKind::Register && !statement.dest.reg.empty()) {
        if (const auto family = family_of(model.arguments, statement.dest.reg);
            family.has_value()) {
          result.argument_written[family.value()] = true;
        }
        if (width_of(model.return_aliases, statement.dest.reg).has_value()) {
          // A merge leaves the family at full width, but the value it carries is narrower:
          // the return is as wide as that value (al, ax, or a single-precision xmm0).
          const std::uint8_t width =
              statement.merged_width != 0
                  ? statement.merged_width
                  : (statement.dest.width != 0 ? statement.dest.width : statement.width);
          if (width != 0) {
            result.current_return_width = width;
          }
        }
      }
    }
  }
  return result;
}

}  // namespace

void infer_signature(IrFunction& function, Architecture architecture, BinaryFormat format) {
  const AbiModel model = model_for(architecture, format);
  // x86-32 has no argument registers, so `arguments` is empty, but its return
  // register is still modelled. Only skip entirely when the architecture has
  // neither.
  if (model.arguments.empty() && model.return_aliases.empty()) {
    return;
  }

  const Scan result = scan(function, model);

  function.parameters.clear();
  for (std::size_t index = 0; index < model.arguments.size(); ++index) {
    // `argument_read` means "read before the first write", so a register that is
    // read and later written (like w0 in `add w0, w0, w1`) is still a parameter.
    if (!result.argument_read[index]) {
      continue;
    }
    IrParameter parameter;
    parameter.name = "a" + std::to_string(function.parameters.size());
    parameter.width = result.argument_width[index] == 0 ? 8 : result.argument_width[index];
    // Integer arguments name their family's 64-bit register; an XMM argument names the
    // XMM register it was read from.
    const std::string& read_as = result.argument_register[index];
    parameter.abi_register =
        is_fp_register(read_as) ? read_as : model.arguments[index].aliases.front().name;
    function.parameters.push_back(std::move(parameter));
  }

  function.return_width = result.has_value_return ? result.widest_return_width : 0;
  function.signature_inferred = true;

  function.notes.push_back("signature inferred from " + model.convention_name +
                           " register use, not debug info");
  if (result.has_value_return && result.has_bare_return) {
    function.notes.push_back("some return paths carry no value; return type is a guess");
  }
}

}  // namespace donkey
