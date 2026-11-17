#include "donkey/analysis/analysis.h"

#include "donkey/binary/eh_frame.h"
#include "donkey/binary/pdata.h"
#include "donkey/binary/plt.h"
#include "donkey/analysis/no_return.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "donkey/core/checked.h"

namespace donkey {
namespace {

bool printable(std::byte value) {
  const auto byte = static_cast<unsigned char>(value);
  return byte >= 0x20U && byte <= 0x7EU;
}

bool executable_contains(const BinaryImage& image, std::uint64_t address) {
  const Section* section = image.section_for_va(address);
  if (section != nullptr) {
    return section->executable;
  }
  const Segment* segment = image.segment_for_va(address);
  return segment != nullptr && segment->executable;
}

std::string synthetic_function_name(std::uint64_t address) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out = "sub_";
  bool started = false;
  for (int shift = 60; shift >= 0; shift -= 4) {
    const auto digit = static_cast<unsigned>((address >> static_cast<unsigned>(shift)) & 0xFU);
    if (digit != 0 || started || shift == 0) {
      out.push_back(kHex[digit]);
      started = true;
    }
  }
  return out;
}

/// Thunks (G24-T4): a function whose one block is an unconditional direct jump to another
/// function's start, after an optional `endbr64`. The jump is a tail call, so the function only
/// forwards to its target: it is marked `thunk` and, unless a symbol names it, named `j_` and the
/// target's name (`j_abort` for a jump to `abort@plt`). A chain of thunks takes the name of the
/// function at its end, followed for at most 8 links. A function that is one indirect jump through
/// an import's slot is an import stub instead, named by the import.
void name_thunks(AnalysisResult& result) {
  std::unordered_map<std::uint64_t, std::size_t> function_at;
  for (std::size_t index = 0; index < result.functions.size(); ++index) {
    function_at.emplace(result.functions[index].address, index);
  }
  std::unordered_map<std::uint64_t, std::size_t> instruction_at;
  instruction_at.reserve(result.instructions.size());
  for (std::size_t index = 0; index < result.instructions.size(); ++index) {
    instruction_at.emplace(result.instructions[index].address, index);
  }
  // The jump target of each one-block function that is only a jump.
  std::unordered_map<std::uint64_t, std::uint64_t> forwards;
  for (const Function& function : result.functions) {
    if (function.block_count != 1 || !function.import_name.empty() ||
        !function.stub_target.empty()) {
      continue;
    }
    auto at = instruction_at.find(function.address);
    if (at == instruction_at.end()) {
      continue;
    }
    std::size_t index = at->second;
    if (result.instructions[index].mnemonic == "endbr64" ||
        result.instructions[index].mnemonic == "endbr32") {
      ++index;
    }
    if (index >= result.instructions.size()) {
      continue;
    }
    const Instruction& jump = result.instructions[index];
    if (jump.classification != InstructionClass::Jump || !jump.direct_target.has_value() ||
        *jump.direct_target == function.address || !function_at.contains(*jump.direct_target) ||
        jump.address + jump.length != function.end_address) {
      continue;
    }
    forwards.emplace(function.address, *jump.direct_target);
  }
  for (const auto& [address, first_target] : forwards) {
    Function& thunk = result.functions[function_at.at(address)];
    thunk.thunk = true;
    thunk.thunk_target = first_target;
    if (thunk.from_symbol || thunk.name != synthetic_function_name(address)) {
      continue;
    }
    std::uint64_t target = first_target;
    for (int link = 0; link < 8; ++link) {
      const auto next = forwards.find(target);
      if (next == forwards.end() || next->second == address) {
        break;
      }
      target = next->second;
    }
    const Function& end = result.functions[function_at.at(target)];
    if (forwards.contains(target) || end.name == synthetic_function_name(target)) {
      continue;  // a cycle, or a target with no name of its own: the thunk keeps sub_<hex>
    }
    thunk.name = "j_" + (!end.import_name.empty()  ? end.import_name
                         : !end.stub_target.empty() ? end.stub_target
                                                    : end.name);
  }
}

/// Import thunks (G24-T4): a function whose first instruction (after an optional `endbr64`) is
/// an indirect jump through an import's slot (`jmp *slot(%rip)`), as MinGW emits for msvcrt
/// imports. It is an import stub, named by the import: `puts` on PE, `puts@plt` on ELF, the form
/// its PLT stubs take. Found from the decoded instructions, before the control-flow graph, so the
/// no-return marks (G24-T3) can use it.
void name_import_thunks(AnalysisResult& result, BinaryFormat format) {
  if (result.import_slots.empty()) {
    return;
  }
  std::unordered_map<std::uint64_t, std::size_t> instruction_at;
  instruction_at.reserve(result.instructions.size());
  for (std::size_t index = 0; index < result.instructions.size(); ++index) {
    instruction_at.emplace(result.instructions[index].address, index);
  }
  for (Function& function : result.functions) {
    if (!function.import_name.empty() || !function.stub_target.empty()) {
      continue;
    }
    const auto at = instruction_at.find(function.address);
    if (at == instruction_at.end()) {
      continue;
    }
    std::size_t index = at->second;
    if (result.instructions[index].mnemonic == "endbr64" ||
        result.instructions[index].mnemonic == "endbr32") {
      ++index;
    }
    if (index >= result.instructions.size()) {
      continue;
    }
    const Instruction& jump = result.instructions[index];
    if (jump.classification != InstructionClass::Jump || jump.direct_target.has_value() ||
        jump.data_references.size() != 1) {
      continue;
    }
    const auto slot = result.import_slots.find(jump.data_references.front());
    if (slot == result.import_slots.end()) {
      continue;
    }
    function.import_name = slot->second;
    function.stub_target = slot->second;
    if (!function.from_symbol && function.name == synthetic_function_name(function.address)) {
      function.name = format == BinaryFormat::Elf ? slot->second + "@plt" : slot->second;
    }
  }
}

/// Functions of the image that do not return (G24-T3, propagation): every block of the function
/// ends in a call that does not return, in `ud2` or `hlt`, or goes on to another block of the
/// function. A return, a tail call or fall-through into a function that may return, an indirect
/// jump that is not a recovered table, or a walk that stopped (a block with no known end) is a way
/// out, and the function is not marked. Only functions with a known extent are considered.
std::vector<std::uint64_t> propagate_no_return(const AnalysisResult& result,
                                               const std::set<std::uint64_t>& targets) {
  std::unordered_map<std::uint64_t, std::vector<const BasicBlock*>> blocks_of;
  for (const BasicBlock& block : result.cfg.blocks) {
    blocks_of[block.function.value()].push_back(&block);
  }
  std::unordered_map<std::uint64_t, std::vector<const CfgEdge*>> edges_from;
  for (const CfgEdge& edge : result.cfg.edges) {
    edges_from[edge.from].push_back(&edge);
  }
  std::vector<std::uint64_t> found;
  for (const Function& function : result.functions) {
    if (function.no_return || !function.has_extent || !function.import_name.empty() ||
        !function.stub_target.empty()) {
      continue;
    }
    const auto blocks = blocks_of.find(function.id.value());
    if (blocks == blocks_of.end() || blocks->second.empty()) {
      continue;
    }
    std::unordered_set<std::uint64_t> starts;
    for (const BasicBlock* block : blocks->second) {
      starts.insert(block->address);
    }
    const auto inside = [&](std::uint64_t address) { return starts.contains(address); };
    bool returns = false;
    for (const BasicBlock* block : blocks->second) {
      if (block->instruction_count == 0) {
        returns = true;
        break;
      }
      const Instruction& last =
          result.instructions[block->first_instruction + block->instruction_count - 1];
      switch (last.classification) {
        case InstructionClass::Return:
          returns = true;
          break;
        case InstructionClass::Interrupt:
          returns = last.mnemonic != "ud2" && last.mnemonic != "hlt";
          break;
        case InstructionClass::Call: {
          const bool no_return =
              last.direct_target.has_value()
                  ? targets.contains(*last.direct_target)
                  : last.data_references.size() == 1 && targets.contains(last.data_references[0]);
          returns = !no_return && !inside(block->end_address);
          break;
        }
        case InstructionClass::Jump:
        case InstructionClass::ConditionalJump: {
          // Every edge must stay inside, or go to a function that does not return. A conditional
          // jump also falls through.
          bool any = false;
          for (const CfgEdge* edge : edges_from[last.address]) {
            if (edge->kind == CfgEdgeKind::Call) {
              continue;
            }
            any = true;
            if (edge->to == 0 || (!inside(edge->to) && !targets.contains(edge->to))) {
              returns = true;
            }
          }
          if (!any) {
            returns = true;  // an unresolved or unrecorded way out
          }
          if (last.classification == InstructionClass::ConditionalJump &&
              !inside(block->end_address) && !targets.contains(block->end_address)) {
            returns = true;
          }
          break;
        }
        case InstructionClass::Unknown:
        case InstructionClass::Other:
          returns = !inside(block->end_address) && !targets.contains(block->end_address);
          break;
      }
      if (returns) {
        break;
      }
    }
    if (!returns) {
      found.push_back(function.address);
    }
  }
  return found;
}

/// Disjoint, sorted [start, end) byte ranges covering every user data range (G12-T1). Ranges
/// that overlap or touch are merged, and a range whose end would pass the top of the address
/// space is ignored.
using ByteRanges = std::vector<std::pair<std::uint64_t, std::uint64_t>>;

ByteRanges merged_user_data(const std::vector<UserDataRange>& ranges) {
  ByteRanges spans;
  for (const UserDataRange& range : ranges) {
    const std::uint64_t length = range.byte_length();
    if (length == 0 || range.address > std::numeric_limits<std::uint64_t>::max() - length) {
      continue;
    }
    spans.emplace_back(range.address, range.address + length);
  }
  std::sort(spans.begin(), spans.end());
  ByteRanges merged;
  for (const auto& [start, end] : spans) {
    if (!merged.empty() && start <= merged.back().second) {
      merged.back().second = std::max(merged.back().second, end);
    } else {
      merged.emplace_back(start, end);
    }
  }
  return merged;
}

bool in_user_data(const ByteRanges& user_data, std::uint64_t address) {
  const auto after = std::upper_bound(
      user_data.begin(), user_data.end(), address,
      [](std::uint64_t value, const std::pair<std::uint64_t, std::uint64_t>& span) {
        return value < span.first;
      });
  if (after == user_data.begin()) {
    return false;
  }
  return address < std::prev(after)->second;
}

/// One part of an executable section that the sweep decodes: `size` bytes at `address`, which
/// are at `file_offset` in the file.
struct CodePiece {
  std::uint64_t address = 0;
  std::uint64_t file_offset = 0;
  std::uint64_t size = 0;
};

/// The parts of `section` outside every user data range, in address order. An empty result
/// means the whole section is user data.
std::vector<CodePiece> code_pieces(const Section& section, const ByteRanges& user_data) {
  const std::uint64_t section_start = section.address;
  const std::uint64_t section_end =
      section.file_size > std::numeric_limits<std::uint64_t>::max() - section_start
          ? std::numeric_limits<std::uint64_t>::max()
          : section_start + section.file_size;
  std::vector<CodePiece> pieces;
  std::uint64_t cursor = section_start;
  const auto emit = [&](std::uint64_t start, std::uint64_t end) {
    if (start < end) {
      pieces.push_back(
          CodePiece{start, section.file_offset + (start - section_start), end - start});
    }
  };
  for (const auto& [start, end] : user_data) {
    if (end <= section_start || start >= section_end) {
      continue;
    }
    emit(cursor, std::max(cursor, std::min(start, section_end)));
    cursor = std::max(cursor, std::min(end, section_end));
  }
  emit(cursor, section_end);
  return pieces;
}

void fold_aarch64_data_references(std::vector<Instruction>& instructions) {
  std::unordered_map<std::string, std::uint64_t> page_regs;

  auto invalidate_reg = [&](const std::string& reg) {
    if (reg.empty()) {
      return;
    }
    page_regs.erase(reg);
    if (reg.front() == 'x') {
      page_regs.erase("w" + reg.substr(1));
    } else if (reg.front() == 'w') {
      page_regs.erase("x" + reg.substr(1));
    }
  };

  for (Instruction& instruction : instructions) {
    if (instruction.mnemonic == "adr") {
      if (instruction.structured_operands.size() >= 2 &&
          instruction.structured_operands[1].kind == OperandKind::Immediate) {
        instruction.data_references.push_back(
            static_cast<std::uint64_t>(instruction.structured_operands[1].immediate));
      }
      if (!instruction.structured_operands.empty() &&
          instruction.structured_operands[0].kind == OperandKind::Register) {
        invalidate_reg(instruction.structured_operands[0].reg);
      }
      continue;
    }

    if (instruction.mnemonic == "adrp") {
      if (instruction.structured_operands.size() >= 2 &&
          instruction.structured_operands[0].kind == OperandKind::Register &&
          instruction.structured_operands[1].kind == OperandKind::Immediate) {
        const std::string& reg = instruction.structured_operands[0].reg;
        page_regs[reg] = static_cast<std::uint64_t>(instruction.structured_operands[1].immediate);
        if (reg.front() == 'x') {
          page_regs["w" + reg.substr(1)] = page_regs[reg];
        }
      }
      continue;
    }

    if (instruction.mnemonic == "add" && instruction.structured_operands.size() >= 3 &&
        instruction.structured_operands[0].kind == OperandKind::Register &&
        instruction.structured_operands[1].kind == OperandKind::Register &&
        instruction.structured_operands[2].kind == OperandKind::Immediate) {
      const std::string& src_reg = instruction.structured_operands[1].reg;
      auto it = page_regs.find(src_reg);
      if (it != page_regs.end()) {
        const std::uint64_t resolved =
            it->second + static_cast<std::uint64_t>(instruction.structured_operands[2].immediate);
        instruction.data_references.push_back(resolved);
      }
      invalidate_reg(instruction.structured_operands[0].reg);
      continue;
    }

    if (instruction.structured_operands.size() >= 2 &&
        instruction.structured_operands[1].kind == OperandKind::Memory) {
      const auto& mem = instruction.structured_operands[1].memory;
      if (!mem.base.empty()) {
        auto it = page_regs.find(mem.base);
        if (it != page_regs.end()) {
          const std::uint64_t resolved = it->second + static_cast<std::uint64_t>(mem.displacement);
          instruction.data_references.push_back(resolved);
        }
      }
      if (instruction.mnemonic.rfind("ldr", 0) == 0 || instruction.mnemonic.rfind("ldur", 0) == 0) {
        if (instruction.structured_operands[0].kind == OperandKind::Register) {
          invalidate_reg(instruction.structured_operands[0].reg);
        }
      }
      continue;
    }

    if (instruction.classification == InstructionClass::Jump ||
        instruction.classification == InstructionClass::ConditionalJump ||
        instruction.classification == InstructionClass::Call ||
        instruction.classification == InstructionClass::Return ||
        instruction.classification == InstructionClass::Interrupt) {
      page_regs.clear();
      continue;
    }

    if (!instruction.structured_operands.empty() &&
        instruction.structured_operands[0].kind == OperandKind::Register &&
        instruction.mnemonic != "cmp" && instruction.mnemonic != "cmn" &&
        instruction.mnemonic != "tst") {
      invalidate_reg(instruction.structured_operands[0].reg);
    }
  }
}

}  // namespace

const char* xref_kind_name(XrefKind kind) noexcept {
  switch (kind) {
    case XrefKind::Unknown:
      return "unknown";
    case XrefKind::Call:
      return "call";
    case XrefKind::Jump:
      return "jump";
    case XrefKind::Data:
      return "data";
  }
  return "unknown";
}

Result<std::vector<StringLiteral>> extract_strings(const BinaryImage& image,
                                                   std::span<const std::byte> file,
                                                   const AnalysisOptions& options) {
  if (options.cancellation_token.is_cancelled()) {
    return make_error<std::vector<StringLiteral>>(Status::Cancelled, "analysis.cancelled",
                                                  "string extraction was cancelled");
  }
  if (options.min_string_length == 0) {
    return make_error<std::vector<StringLiteral>>(Status::InvalidInput,
                                                  "analysis.invalid_min_length",
                                                  "minimum string length must be at least one");
  }
  std::vector<StringLiteral> strings;

  struct Range {
    std::uint64_t file_offset;
    std::uint64_t size;
  };
  std::vector<Range> ranges;
  for (const Section& section : image.sections) {
    if (!section.has_file_data || section.executable || !section.readable ||
        section.file_size == 0) {
      continue;
    }
    if (!checked::in_range(section.file_offset, section.file_size, file.size())) {
      continue;
    }
    ranges.push_back(Range{section.file_offset, section.file_size});
  }
  if (ranges.empty()) {
    if (image.sections.empty()) {
      ranges.push_back(Range{0, static_cast<std::uint64_t>(file.size())});
    } else if (!image.sections.empty()) {
      // All sections are executable or empty: nothing sensible to scan.
      return strings;
    }
  }

  for (const Range& range : ranges) {
    if (options.cancellation_token.is_cancelled()) {
      return make_error<std::vector<StringLiteral>>(Status::Cancelled, "analysis.cancelled",
                                                    "string extraction was cancelled");
    }
    const std::uint64_t begin = range.file_offset;
    const std::uint64_t end = begin + range.size;
    std::uint64_t offset = begin;
    while (offset < end) {
      if (options.cancellation_token.is_cancelled()) {
        return make_error<std::vector<StringLiteral>>(Status::Cancelled, "analysis.cancelled",
                                                      "string extraction was cancelled");
      }
      if (strings.size() >= options.max_strings) {
        break;
      }
      const std::size_t at = static_cast<std::size_t>(offset);

      // UTF-16LE: printable byte followed by NUL.
      if (offset + 1 < end && printable(file[at]) && file[at + 1] == std::byte{0}) {
        std::uint64_t cursor = offset;
        std::string text;
        while (cursor + 1 < end && printable(file[static_cast<std::size_t>(cursor)]) &&
               file[static_cast<std::size_t>(cursor) + 1] == std::byte{0} &&
               text.size() < options.max_string_length) {
          text.push_back(static_cast<char>(file[static_cast<std::size_t>(cursor)]));
          cursor += 2;
        }
        if (text.size() >= options.min_string_length && text.size() <= options.max_string_length &&
            cursor + 1 < end && file[static_cast<std::size_t>(cursor)] == std::byte{0} &&
            file[static_cast<std::size_t>(cursor) + 1] == std::byte{0}) {
          StringLiteral literal;
          literal.file_offset = offset;
          literal.text = text;
          literal.encoding = "utf-16le";
          auto address = image.file_offset_to_va(offset);
          if (address) {
            literal.address = address.value();
            literal.mapped = true;
          }
          strings.push_back(std::move(literal));
          offset = cursor + 2;
          continue;
        }
      }

      if (printable(file[at])) {
        std::uint64_t cursor = offset;
        while (cursor < end && printable(file[static_cast<std::size_t>(cursor)])) {
          ++cursor;
        }
        const std::uint64_t length = cursor - offset;
        if (length >= options.min_string_length && length <= options.max_string_length &&
            cursor < end && file[static_cast<std::size_t>(cursor)] == std::byte{0}) {
          StringLiteral literal;
          literal.file_offset = offset;
          literal.text.assign(reinterpret_cast<const char*>(file.data() + offset),
                              static_cast<std::size_t>(length));
          literal.encoding = "ascii";
          auto address = image.file_offset_to_va(offset);
          if (address) {
            literal.address = address.value();
            literal.mapped = true;
          }
          strings.push_back(std::move(literal));
        }
        offset = cursor + 1;
        continue;
      }
      ++offset;
    }
    if (strings.size() >= options.max_strings) {
      break;
    }
  }
  return strings;
}

Result<AnalysisResult> analyze(const BinaryImage& image, std::span<const std::byte> file,
                               const AnalysisOptions& options) {
  if (options.cancellation_token.is_cancelled()) {
    return make_error<AnalysisResult>(Status::Cancelled, "analysis.cancelled",
                                      "analysis was cancelled");
  }
  AnalysisResult result;
  result.architecture = image.architecture;

  auto strings = extract_strings(image, file, options);
  if (!strings) {
    return strings.diagnostic();
  }
  result.strings = std::move(strings.value());

  if (options.cancellation_token.is_cancelled()) {
    return make_error<AnalysisResult>(Status::Cancelled, "analysis.cancelled",
                                      "analysis was cancelled");
  }

  const ByteRanges user_data = merged_user_data(options.user_data_ranges);
  std::optional<Decoder> decoder;
  auto created = Decoder::create(image.architecture, image.endian);
  if (created) {
    decoder.emplace(std::move(created.value()));
  } else {
    result.partial = true;
    result.diagnostics.push_back(created.diagnostic());
  }

  std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint8_t>> seen_xrefs;
  std::size_t decoded = 0;
  if (decoder.has_value()) {
    for (const Section& section : image.sections) {
      if (options.cancellation_token.is_cancelled()) {
        return make_error<AnalysisResult>(Status::Cancelled, "analysis.cancelled",
                                          "analysis was cancelled");
      }
      if (!section.executable || !section.has_file_data || section.file_size == 0) {
        continue;
      }
      if (decoded >= options.max_instructions) {
        break;
      }
      if (!checked::in_range(section.file_offset, section.file_size, file.size())) {
        result.partial = true;
        result.diagnostics.push_back(
            Diagnostic::make(Status::Partial, "analysis.section_out_of_bounds",
                             "executable section is not backed by the file", section.file_offset));
        continue;
      }
      // The section is decoded in the parts the user did not declare as data (G12-T1). A part
      // is decoded from its own address, so the instructions keep their true addresses.
      for (const CodePiece& piece : code_pieces(section, user_data)) {
        if (decoded >= options.max_instructions) {
          break;
        }
        auto bytes = file.subspan(static_cast<std::size_t>(piece.file_offset),
                                  static_cast<std::size_t>(piece.size));
        const std::size_t remaining = options.max_instructions - decoded;
        auto stream = decoder->decode(bytes, piece.address, remaining);
        if (!stream) {
          result.partial = true;
          result.diagnostics.push_back(stream.diagnostic());
          continue;
        }

        if (image.architecture == Architecture::AArch64) {
          fold_aarch64_data_references(stream.value().instructions);
        }

        decoded += stream.value().instructions.size();
        for (const Instruction& instruction : stream.value().instructions) {
          if (instruction.direct_target.has_value()) {
            XrefKind kind = XrefKind::Jump;
            if (instruction.classification == InstructionClass::Call) {
              kind = XrefKind::Call;
            }
            const std::tuple<std::uint64_t, std::uint64_t, std::uint8_t> key{
                instruction.address, instruction.direct_target.value(),
                static_cast<std::uint8_t>(kind)};
            if (seen_xrefs.insert(key).second) {
              result.xrefs.push_back(
                  Xref{instruction.address, instruction.direct_target.value(), kind});
            }
          }
          for (const std::uint64_t reference : instruction.data_references) {
            const std::tuple<std::uint64_t, std::uint64_t, std::uint8_t> key{
                instruction.address, reference, static_cast<std::uint8_t>(XrefKind::Data)};
            if (seen_xrefs.insert(key).second) {
              result.xrefs.push_back(Xref{instruction.address, reference, XrefKind::Data});
            }
          }
          result.instructions.push_back(instruction);
        }
        if (stream.value().invalid_bytes != 0) {
          // Data in code or encodings the decoder does not know: skipped, so
          // the code after them is still decoded, but the sweep is Partial.
          result.partial = true;
          result.diagnostics.push_back(Diagnostic::make(
              Status::Partial, "analysis.undecodable_bytes",
              std::to_string(stream.value().invalid_bytes) + " undecodable byte(s) skipped in '" +
                  section.name + "'",
              section.file_offset + (stream.value().first_invalid_address - section.address)));
        }
        if (stream.value().truncated) {
          result.partial = true;
          result.diagnostics.push_back(Diagnostic::make(
              Status::Partial,
              stream.value().stop_reason.empty() ? "analysis.decode_stopped"
                                                 : stream.value().stop_reason,
              "disassembly stopped inside section '" + section.name + "'", section.file_offset));
        }
      }
    }
  }
  if (decoder.has_value() && decoded >= options.max_instructions) {
    result.partial = true;
    result.diagnostics.push_back(
        Diagnostic::make(Status::ResourceLimit, "analysis.instruction_limit",
                         "analysis stopped at the configured instruction limit"));
  }

  // Function seeds: entry point, exported function symbols and call targets.
  std::set<std::uint64_t> seeds;
  if (image.has_entry_point()) {
    seeds.insert(image.entry_point);
  }
  std::set<std::uint64_t> named;
  for (const Symbol& symbol : image.symbols) {
    // Typed function symbols, and exports in executable code (PE export
    // tables carry no type: an export in .text is an entry point).
    const bool code_symbol = symbol.kind == SymbolKind::Function ||
                             (symbol.kind == SymbolKind::Export && symbol.exported);
    if (symbol.imported || !code_symbol || symbol.address == 0) {
      continue;
    }
    if (executable_contains(image, symbol.address)) {
      seeds.insert(symbol.address);
      named.insert(symbol.address);
    }
  }
  for (const Xref& xref : result.xrefs) {
    if (xref.kind == XrefKind::Call && executable_contains(image, xref.to)) {
      seeds.insert(xref.to);
    }
  }
  // Every named PLT stub is a function (G24-T4), also one that only a jump reaches (a tail call
  // or a conditional tail call into it).
  const std::map<std::uint64_t, std::string> stub_targets = plt_stub_targets(image, file);
  for (const auto& [address, name] : stub_targets) {
    if (executable_contains(image, address)) {
      seeds.insert(address);
    }
  }
  // Unwind tables (G23-T1): every FDE of `.eh_frame` names a function's range, stripped or not.
  // A start found only here is marked with the unwind provenance.
  // A table that could not be read in full may leave function starts out, so the result is
  // Partial and says why.
  std::set<std::uint64_t> unwind_starts;
  if (auto frames = read_eh_frame_of_image(image, file); frames) {
    for (const EhFrameFunction& frame : frames.value().functions) {
      if (executable_contains(image, frame.start)) {
        seeds.insert(frame.start);
        unwind_starts.insert(frame.start);
      }
    }
    if (frames.value().malformed_records > 0 || frames.value().truncated) {
      result.partial = true;
      result.diagnostics.push_back(Diagnostic::make(
          Status::Partial, "analysis.eh_frame_incomplete",
          ".eh_frame was not read in full (" + std::to_string(frames.value().malformed_records) +
              " unreadable records" + (frames.value().truncated ? ", walk stopped early" : "") +
              "); function starts it names may be missing",
          std::nullopt));
    }
  } else {
    result.partial = true;
    result.diagnostics.push_back(frames.diagnostic());
  }
  // PE x64 exception directory (G23-T2): each RUNTIME_FUNCTION names a function's range.
  if (auto pdata = read_pdata_of_image(image, file); pdata) {
    for (const PdataFunction& frame : pdata.value().functions) {
      if (executable_contains(image, frame.start)) {
        seeds.insert(frame.start);
        unwind_starts.insert(frame.start);
      }
    }
    if (pdata.value().malformed > 0 || pdata.value().truncated) {
      result.partial = true;
      result.diagnostics.push_back(
          Diagnostic::make(Status::Partial, "analysis.pdata_incomplete",
                           "the exception directory was not read in full (" +
                               std::to_string(pdata.value().malformed) + " unreadable entries" +
                               (pdata.value().truncated ? ", entry limit reached" : "") +
                               "); function starts it names may be missing",
                           std::nullopt));
    }
  } else {
    result.partial = true;
    result.diagnostics.push_back(pdata.diagnostic());
  }
  std::set<std::uint64_t> user_defined;
  for (const std::uint64_t address : options.user_function_starts) {
    if (executable_contains(image, address)) {
      seeds.insert(address);
      user_defined.insert(address);
    }
  }
  for (const std::uint64_t address : options.user_code_starts) {
    if (executable_contains(image, address)) {
      seeds.insert(address);
      user_defined.insert(address);
    }
  }
  for (const std::uint64_t address : options.removed_function_starts) {
    if (user_defined.count(address) == 0) {
      seeds.erase(address);
    }
  }
  // A user data range is data, so no start inside one survives, whoever proposed it.
  for (auto it = seeds.begin(); it != seeds.end();) {
    it = in_user_data(user_data, *it) ? seeds.erase(it) : std::next(it);
  }

  // The symbol that names each address: the first one in the image's order. One pass over the
  // symbols, not one per seed (unwind tables can give tens of thousands of seeds).
  std::unordered_map<std::uint64_t, const Symbol*> naming_symbol;
  for (const Symbol& symbol : image.symbols) {
    if (!symbol.imported && !symbol.name.empty() &&
        (symbol.kind == SymbolKind::Function || symbol.exported)) {
      naming_symbol.emplace(symbol.address, &symbol);
    }
  }
  // Import stubs (G24-T4): a PLT entry is named by the import its relocation names, `abort@plt`,
  // the form `objdump` and the link stage use. A symbol at the same address names it first.
  const std::map<std::uint64_t, std::string> stubs = plt_stub_imports(image, file);
  result.import_slots = got_import_slots(image, file);
  // PE: each imported name's IAT slot (pe.cpp gives the import symbol the slot's address). A call
  // or a jump through the slot (`call *slot(%rip)`) goes to that import.
  if (image.format == BinaryFormat::Pe) {
    for (const Symbol& symbol : image.symbols) {
      if (symbol.imported && symbol.address != 0 && !symbol.name.empty()) {
        result.import_slots.emplace(symbol.address, symbol.name);
      }
    }
  }
  for (const std::uint64_t address : seeds) {
    Function seed;
    seed.address = address;
    seed.from_symbol = named.count(address) != 0;
    seed.from_unwind = unwind_starts.count(address) != 0;
    if (const auto symbol = naming_symbol.find(address); symbol != naming_symbol.end()) {
      seed.name = symbol->second->name;
      seed.exported = symbol->second->exported;
    }
    if (const auto stub = stub_targets.find(address); stub != stub_targets.end()) {
      seed.stub_target = stub->second;
      if (stubs.contains(address)) {
        seed.import_name = stub->second;
      }
      if (seed.name.empty()) {
        seed.name = stub->second + "@plt";
      }
    }
    if (seed.name.empty()) {
      seed.name = synthetic_function_name(address);
    }
    result.functions.push_back(std::move(seed));
  }
  for (std::size_t i = 0; i < result.functions.size(); ++i) {
    result.functions[i].id = FunctionId{i + 1};
  }
  name_import_thunks(result, image.format);

  // No-return imports (G24-T3): the stubs and slots of the fixed list's names, bound to a runtime
  // library. The CFG walk stops after a call to one.
  AnalysisOptions walk = options;
  if (options.no_return_analysis) {
    std::map<std::uint64_t, std::string> import_stubs;
    for (const Function& function : result.functions) {
      if (!function.import_name.empty()) {
        import_stubs.emplace(function.address, function.import_name);
      }
    }
    result.no_return = bind_no_return_imports(image, file, import_stubs, result.import_slots);
    for (Function& function : result.functions) {
      if (const auto mark = result.no_return.find(function.address);
          mark != result.no_return.end()) {
        function.no_return = true;
        function.no_return_reason = mark->second;
      }
    }
    for (const auto& [address, reason] : result.no_return) {
      walk.no_return_targets.insert(address);
    }
  }
  // Targets the caller gave are marks too, so the CFG and the lifter agree on every one.
  for (const std::uint64_t address : options.no_return_targets) {
    result.no_return.emplace(address, "given by the caller of the analysis");
  }

  if (options.build_control_flow) {
    auto graph =
        build_control_flow_graph(image, result.instructions, result.functions, walk, file);
    // Propagation (owner decision 1): a function of the image whose every path ends in a call
    // that does not return is itself no-return. Each round rebuilds the graph with the new marks,
    // so code after a call to a newly marked function leaves its callers; at most 8 rounds.
    for (int round = 0; options.no_return_analysis && graph && round < 8; ++round) {
      result.cfg = std::move(graph.value());
      std::unordered_map<std::uint64_t, std::size_t> extent_at;
      for (std::size_t index = 0; index < result.cfg.functions.size(); ++index) {
        extent_at.emplace(result.cfg.functions[index].address, index);
      }
      for (Function& function : result.functions) {
        if (const auto found = extent_at.find(function.address); found != extent_at.end()) {
          function.has_extent = result.cfg.functions[found->second].has_extent;
        }
      }
      const std::vector<std::uint64_t> marked =
          propagate_no_return(result, walk.no_return_targets);
      if (marked.empty()) {
        graph = Result<ControlFlowGraph>(std::move(result.cfg));
        result.cfg = ControlFlowGraph{};
        break;
      }
      const std::unordered_set<std::uint64_t> newly(marked.begin(), marked.end());
      for (Function& function : result.functions) {
        if (newly.contains(function.address)) {
          function.no_return = true;
          function.no_return_reason = "propagated:every path ends in a call that does not return";
          result.no_return.emplace(function.address, function.no_return_reason);
          walk.no_return_targets.insert(function.address);
        }
      }
      graph = build_control_flow_graph(image, result.instructions, result.functions, walk, file);
    }
    if (!graph) {
      result.partial = true;
      result.diagnostics.push_back(graph.diagnostic());
    } else {
      result.cfg = std::move(graph.value());
      // Each graph function updates the first function at its address, found through an index
      // (a search per function was quadratic in the number of functions).
      std::unordered_map<std::uint64_t, std::size_t> function_at;
      for (std::size_t index = 0; index < result.functions.size(); ++index) {
        function_at.emplace(result.functions[index].address, index);
      }
      for (const Function& function : result.cfg.functions) {
        if (const auto found = function_at.find(function.address); found != function_at.end()) {
          Function& existing = result.functions[found->second];
          existing.end_address = function.end_address;
          existing.block_count = function.block_count;
          existing.has_extent = function.has_extent;
          existing.estimated = function.estimated;
        }
      }
      name_thunks(result);
      result.call_graph = build_call_graph(result.cfg, result.instructions);
      if (result.cfg.partial) {
        result.partial = true;
      }
      for (const Diagnostic& diagnostic : result.cfg.diagnostics) {
        result.diagnostics.push_back(diagnostic);
      }
    }
  }

  std::sort(result.xrefs.begin(), result.xrefs.end(), [](const Xref& a, const Xref& b) {
    if (a.from != b.from) {
      return a.from < b.from;
    }
    if (a.to != b.to) {
      return a.to < b.to;
    }
    return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
  });

  return result;
}

CallGraph build_call_graph(const ControlFlowGraph& cfg, std::span<const Instruction> instructions) {
  CallGraph graph;
  // Function entry by id, and blocks sorted by address for site lookup.
  std::unordered_map<std::uint64_t, std::uint64_t> entry_of;
  for (const Function& function : cfg.functions) {
    entry_of[function.id.value()] = function.address;
  }
  std::vector<const BasicBlock*> blocks;
  blocks.reserve(cfg.blocks.size());
  for (const BasicBlock& block : cfg.blocks) {
    blocks.push_back(&block);
  }
  std::sort(blocks.begin(), blocks.end(),
            [](const BasicBlock* a, const BasicBlock* b) { return a->address < b->address; });
  auto caller_of = [&](std::uint64_t site) -> std::optional<std::uint64_t> {
    auto it = std::upper_bound(
        blocks.begin(), blocks.end(), site,
        [](std::uint64_t value, const BasicBlock* block) { return value < block->address; });
    if (it == blocks.begin()) {
      return std::nullopt;
    }
    --it;
    if (site >= (*it)->end_address) {
      return std::nullopt;
    }
    const auto entry = entry_of.find((*it)->function.value());
    if (entry == entry_of.end()) {
      return std::nullopt;
    }
    return entry->second;
  };
  for (const Instruction& instruction : instructions) {
    if (instruction.classification != InstructionClass::Call) {
      continue;
    }
    const auto caller = caller_of(instruction.address);
    if (!caller) {
      ++graph.orphan_sites;
      continue;
    }
    if (instruction.direct_target.has_value()) {
      graph.edges.push_back({*caller, *instruction.direct_target, instruction.address});
    } else {
      graph.unresolved.push_back({*caller, instruction.address});
    }
  }
  std::sort(graph.edges.begin(), graph.edges.end(),
            [](const CallGraphEdge& a, const CallGraphEdge& b) {
              return a.caller != b.caller ? a.caller < b.caller : a.site < b.site;
            });
  return graph;
}

std::vector<CallGraphEdge> CallGraph::callers_of(std::uint64_t function) const {
  std::vector<CallGraphEdge> out;
  for (const CallGraphEdge& edge : edges) {
    if (edge.callee == function) {
      out.push_back(edge);
    }
  }
  return out;
}

std::vector<CallGraphEdge> CallGraph::callees_of(std::uint64_t function) const {
  std::vector<CallGraphEdge> out;
  for (const CallGraphEdge& edge : edges) {
    if (edge.caller == function) {
      out.push_back(edge);
    }
  }
  return out;
}

bool is_c_identifier(std::string_view text) noexcept {
  if (text.empty()) {
    return false;
  }
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    const bool digit = c >= '0' && c <= '9';
    if (!letter && !(digit && i > 0)) {
      return false;
    }
  }
  return true;
}

std::string call_target_name(const AnalysisResult& analysis, std::uint64_t address) {
  // analyze() seeds functions in address order (the seeds are a std::set), so a binary search
  // finds them; a caller that added functions out of order still gets a linear search.
  auto found = std::lower_bound(
      analysis.functions.begin(), analysis.functions.end(), address,
      [](const Function& function, std::uint64_t value) { return function.address < value; });
  if (found == analysis.functions.end() || found->address != address) {
    found = std::find_if(analysis.functions.begin(), analysis.functions.end(),
                         [address](const Function& function) { return function.address == address; });
    if (found == analysis.functions.end()) {
      return {};
    }
  }
  const std::string& name = !found->import_name.empty() ? found->import_name
                            : !found->stub_target.empty() ? found->stub_target
                                                          : found->name;
  if (name == synthetic_function_name(address) || !is_c_identifier(name)) {
    return {};
  }
  return name;
}

}  // namespace donkey
