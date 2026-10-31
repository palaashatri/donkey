#include "donkey/analysis/analysis.h"

#include <algorithm>
#include <optional>
#include <set>
#include <tuple>
#include <unordered_map>
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
      auto bytes = file.subspan(static_cast<std::size_t>(section.file_offset),
                                static_cast<std::size_t>(section.file_size));
      const std::size_t remaining = options.max_instructions - decoded;
      auto stream = decoder->decode(bytes, section.address, remaining);
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
    if (symbol.imported || symbol.kind != SymbolKind::Function || symbol.address == 0) {
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
  std::set<std::uint64_t> user_defined;
  for (const std::uint64_t address : options.user_function_starts) {
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

  for (const std::uint64_t address : seeds) {
    Function seed;
    seed.address = address;
    seed.from_symbol = named.count(address) != 0;
    for (const Symbol& symbol : image.symbols) {
      if (!symbol.imported && !symbol.name.empty() && symbol.address == address &&
          (symbol.kind == SymbolKind::Function || symbol.exported)) {
        seed.name = symbol.name;
        seed.exported = symbol.exported;
        break;
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

  if (options.build_control_flow) {
    auto graph = build_control_flow_graph(image, result.instructions, result.functions, options);
    if (!graph) {
      result.partial = true;
      result.diagnostics.push_back(graph.diagnostic());
    } else {
      result.cfg = std::move(graph.value());
      for (const Function& function : result.cfg.functions) {
        for (Function& existing : result.functions) {
          if (existing.address == function.address) {
            existing.end_address = function.end_address;
            existing.block_count = function.block_count;
            existing.has_extent = function.has_extent;
            existing.estimated = function.estimated;
            break;
          }
        }
      }
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

}  // namespace donkey
