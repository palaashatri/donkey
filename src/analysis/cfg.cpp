#include "donkey/analysis/cfg.h"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "donkey/analysis/analysis.h"

namespace donkey {
namespace {

constexpr std::size_t kMaxBlocks = 200'000;

std::string fallback_name(std::uint64_t address) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "sub_%llx", static_cast<unsigned long long>(address));
  return buffer;
}

bool terminates_flow(InstructionClass classification) {
  return classification == InstructionClass::Jump ||
         classification == InstructionClass::ConditionalJump ||
         classification == InstructionClass::Return ||
         classification == InstructionClass::Interrupt;
}

// ---- jump tables -----------------------------------------------------------

constexpr std::uint64_t kMaxJumpTableEntries = 4096;

std::string x86_family(const std::string& name) {
  static const char* const kRows[][5] = {
      {"rax", "eax", "ax", "al", "ah"}, {"rbx", "ebx", "bx", "bl", "bh"},
      {"rcx", "ecx", "cx", "cl", "ch"}, {"rdx", "edx", "dx", "dl", "dh"},
      {"rsi", "esi", "si", "sil", ""},  {"rdi", "edi", "di", "dil", ""},
      {"rbp", "ebp", "bp", "bpl", ""},  {"rsp", "esp", "sp", "spl", ""},
  };
  for (const auto& row : kRows) {
    for (const char* alias : row) {
      if (alias[0] != '\0' && name == alias) {
        return row[0];
      }
    }
  }
  if (name.size() >= 2 && name[0] == 'r' && name[1] >= '0' && name[1] <= '9') {
    std::size_t digits = 1;
    while (digits < name.size() && name[digits] >= '0' && name[digits] <= '9') {
      ++digits;
    }
    return name.substr(0, digits);
  }
  return name;
}

std::uint64_t width_mask(std::uint8_t width) {
  return width >= 8 ? ~0ULL : ((1ULL << (width * 8U)) - 1U);
}

bool same_memory(const MemoryOperand& a, const MemoryOperand& b) {
  return x86_family(a.base) == x86_family(b.base) && x86_family(a.index) == x86_family(b.index) &&
         a.scale == b.scale && a.displacement == b.displacement;
}

/// Concrete evaluation of the straight-line code between a jump table's
/// bounds check and its jump, for one selector value. Only the instructions
/// table dispatch uses are understood; anything else stops the evaluation.
class TableSlice {
 public:
  TableSlice(const BinaryImage& image, std::span<const std::byte> file, const Operand& selector,
             std::uint64_t value, bool x86_64)
      : image_(image), file_(file), selector_(selector), value_(value), x86_64_(x86_64) {
    if (selector.kind == OperandKind::Register) {
      registers_[x86_family(selector.reg)] = value & width_mask(selector.size);
    }
  }

  bool step(const Instruction& instruction) {
    const std::string& m = instruction.mnemonic;
    const auto& ops = instruction.structured_operands;
    if (m == "nop" || m == "endbr64" || m == "endbr32") {
      return true;
    }
    if (m == "cdqe") {
      auto eax = read_register("eax", 4);
      if (!eax) {
        return false;
      }
      return write_register(
          "rax", 8,
          static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(*eax))));
    }
    if (ops.size() != 2 || ops[0].kind != OperandKind::Register) {
      return false;
    }
    const Operand& dest = ops[0];
    const bool writes_selector = selector_.kind == OperandKind::Register &&
                                 x86_family(dest.reg) == x86_family(selector_.reg);
    if (m == "lea") {
      auto address = address_of(ops[1], instruction);
      return !writes_selector && address && write_register(dest.reg, dest.size, *address);
    }
    auto source = value_of(ops[1], instruction);
    if (!source) {
      return false;
    }
    std::uint64_t result = 0;
    if (m == "mov" || m == "movabs") {
      result = *source;
    } else if (m == "movsxd" || m == "movsx") {
      result = static_cast<std::uint64_t>(sign_extend(*source, ops[1].size));
    } else if (m == "movzx") {
      result = *source & width_mask(ops[1].size);
    } else {
      auto current = read_register(dest.reg, dest.size);
      if (!current) {
        return false;
      }
      if (m == "add") {
        result = *current + *source;
      } else if (m == "sub") {
        result = *current - *source;
      } else if (m == "shl" || m == "sal") {
        result = *current << (*source & 63U);
      } else if (m == "shr") {
        result = (*current & width_mask(dest.size)) >> (*source & 63U);
      } else if (m == "and") {
        result = *current & *source;
      } else if (m == "or") {
        result = *current | *source;
      } else {
        return false;
      }
    }
    if (writes_selector &&
        (result & width_mask(selector_.size)) != (value_ & width_mask(selector_.size))) {
      return false;  // the selector is changed, not just zero-extended (mov edi, edi)
    }
    return write_register(dest.reg, dest.size, result);
  }

  std::optional<std::uint64_t> jump_target(const Instruction& jump) {
    if (jump.structured_operands.size() != 1) {
      return std::nullopt;
    }
    return value_of(jump.structured_operands[0], jump);
  }

 private:
  static std::int64_t sign_extend(std::uint64_t value, std::uint8_t width) {
    if (width == 0 || width >= 8) {
      return static_cast<std::int64_t>(value);
    }
    const unsigned bits = width * 8U;
    const std::uint64_t sign = 1ULL << (bits - 1U);
    value &= width_mask(width);
    return static_cast<std::int64_t>((value ^ sign) - sign);
  }

  std::optional<std::uint64_t> read_register(const std::string& name, std::uint8_t width) {
    if (name == "rip" || name.empty()) {
      return std::nullopt;
    }
    const auto it = registers_.find(x86_family(name));
    if (it == registers_.end()) {
      return std::nullopt;
    }
    const unsigned shift = (name.size() == 2 && name[1] == 'h') ? 8U : 0U;
    return (it->second >> shift) & width_mask(width == 0 ? 8 : width);
  }

  bool write_register(const std::string& name, std::uint8_t width, std::uint64_t value) {
    const std::string family = x86_family(name);
    if (width >= 8 || width == 0) {
      registers_[family] = value;
    } else if (width == 4) {
      registers_[family] = value & 0xffffffffULL;  // 32-bit writes zero-extend
    } else {
      return false;  // partial-register merges are not needed for dispatch
    }
    return true;
  }

  std::optional<std::uint64_t> address_of(const Operand& operand, const Instruction& at) {
    if (operand.kind != OperandKind::Memory) {
      return std::nullopt;
    }
    const MemoryOperand& mem = operand.memory;
    std::uint64_t address = static_cast<std::uint64_t>(mem.displacement);
    if (mem.base == "rip") {
      address += at.address + at.length;
    } else if (!mem.base.empty()) {
      auto base = read_register(mem.base, 8);
      if (!base) {
        return std::nullopt;
      }
      address += *base;
    }
    if (!mem.index.empty()) {
      auto index = read_register(mem.index, 8);
      if (!index) {
        return std::nullopt;
      }
      address += *index * static_cast<std::uint64_t>(mem.scale == 0 ? 1 : mem.scale);
    }
    return x86_64_ ? address : (address & 0xffffffffULL);
  }

  std::optional<std::uint64_t> value_of(const Operand& operand, const Instruction& at) {
    switch (operand.kind) {
      case OperandKind::Immediate:
        return static_cast<std::uint64_t>(operand.immediate);
      case OperandKind::Register:
        return read_register(operand.reg, operand.size);
      case OperandKind::Memory: {
        if (selector_.kind == OperandKind::Memory &&
            same_memory(operand.memory, selector_.memory)) {
          return value_ & width_mask(operand.size);
        }
        auto address = address_of(operand, at);
        if (!address) {
          return std::nullopt;
        }
        return read_image(*address, operand.size == 0 ? (x86_64_ ? 8 : 4) : operand.size);
      }
      case OperandKind::Unknown:
        break;
    }
    return std::nullopt;
  }

  /// Table bytes come only from file-backed, non-writable sections: a
  /// writable table could be changed at run time.
  std::optional<std::uint64_t> read_image(std::uint64_t address, std::size_t size) const {
    for (const Section& section : image_.sections) {
      if (!section.has_file_data || section.writable || address < section.address ||
          address - section.address >= section.file_size ||
          section.file_size - (address - section.address) < size) {
        continue;
      }
      const std::uint64_t offset = section.file_offset + (address - section.address);
      if (offset > file_.size() || file_.size() - offset < size) {
        return std::nullopt;
      }
      std::uint64_t value = 0;
      for (std::size_t i = 0; i < size; ++i) {
        value |= static_cast<std::uint64_t>(file_[static_cast<std::size_t>(offset + i)])
                 << (8U * i);
      }
      return value;
    }
    return std::nullopt;
  }

  const BinaryImage& image_;
  std::span<const std::byte> file_;
  const Operand& selector_;
  std::uint64_t value_;
  bool x86_64_;
  std::unordered_map<std::string, std::uint64_t> registers_;
};

bool flags_writer(const std::string& m) {
  return m == "cmp" || m == "test" || m == "add" || m == "sub" || m == "and" || m == "or" ||
         m == "xor" || m == "inc" || m == "dec" || m == "neg" || m == "shl" || m == "shr" ||
         m == "sar" || m == "imul" || m == "sal";
}

/// Recover the jump table behind the indirect jump `run.back()`, where `run`
/// is the straight-line path the traversal followed to reach it.
std::optional<JumpTable> resolve_jump_table(
    const BinaryImage& image, std::span<const std::byte> file,
    std::span<const Instruction> instructions, const std::vector<std::uint32_t>& run,
    const std::unordered_map<std::uint64_t, std::uint32_t>& index_by_address) {
  if (file.empty() || run.size() < 3 ||
      (image.architecture != Architecture::X86_64 && image.architecture != Architecture::X86)) {
    return std::nullopt;
  }
  const bool x86_64 = image.architecture == Architecture::X86_64;
  const Instruction& jump = instructions[run.back()];
  // The bounds check: the nearest `ja`/`jae` on the path, fed by a `cmp`.
  std::size_t check = run.size();
  for (std::size_t i = run.size() - 1; i-- > 0;) {
    const Instruction& candidate = instructions[run[i]];
    if (candidate.classification == InstructionClass::ConditionalJump) {
      if (candidate.mnemonic == "ja" || candidate.mnemonic == "jae") {
        check = i;
      }
      break;  // any other branch on the path: not a simple dispatch
    }
    if (candidate.classification != InstructionClass::Other) {
      return std::nullopt;
    }
  }
  if (check == run.size() || check == 0) {
    return std::nullopt;
  }
  const Instruction& branch = instructions[run[check]];
  std::size_t compare = check;
  for (std::size_t i = check; i-- > 0;) {
    const Instruction& candidate = instructions[run[i]];
    if (candidate.mnemonic == "cmp") {
      compare = i;
      break;
    }
    if (flags_writer(candidate.mnemonic) || candidate.classification != InstructionClass::Other) {
      return std::nullopt;
    }
  }
  if (compare == check) {
    return std::nullopt;
  }
  const Instruction& cmp = instructions[run[compare]];
  if (cmp.structured_operands.size() != 2 ||
      cmp.structured_operands[1].kind != OperandKind::Immediate ||
      (cmp.structured_operands[0].kind != OperandKind::Register &&
       cmp.structured_operands[0].kind != OperandKind::Memory) ||
      !branch.direct_target.has_value()) {
    return std::nullopt;
  }
  const Operand& selector = cmp.structured_operands[0];
  const std::uint64_t bound = static_cast<std::uint64_t>(cmp.structured_operands[1].immediate) &
                              width_mask(selector.size == 0 ? 4 : selector.size);
  const std::uint64_t count = branch.mnemonic == "ja" ? bound + 1 : bound;
  if (count == 0 || count > kMaxJumpTableEntries) {
    return std::nullopt;
  }
  JumpTable table;
  table.jump_address = jump.address;
  table.check_address = cmp.address;
  table.default_target = branch.direct_target.value();
  table.selector = selector;
  for (std::uint64_t value = 0; value < count; ++value) {
    TableSlice slice(image, file, selector, value, x86_64);
    for (std::size_t i = check + 1; i + 1 < run.size(); ++i) {
      if (!slice.step(instructions[run[i]])) {
        return std::nullopt;
      }
    }
    auto target = slice.jump_target(jump);
    if (!target) {
      return std::nullopt;
    }
    const std::uint64_t address = *target & (x86_64 ? ~0ULL : 0xffffffffULL);
    const Section* section = image.section_for_va(address);
    if (section == nullptr || !section->executable || !index_by_address.contains(address)) {
      return std::nullopt;  // one bad entry: the whole table is unproven
    }
    table.targets.push_back(address);
  }
  return table;
}

}  // namespace

const char* cfg_edge_kind_name(CfgEdgeKind kind) noexcept {
  switch (kind) {
    case CfgEdgeKind::Unknown:
      return "unknown";
    case CfgEdgeKind::Jump:
      return "jump";
    case CfgEdgeKind::ConditionalTrue:
      return "conditional_true";
    case CfgEdgeKind::ConditionalFalse:
      return "conditional_false";
    case CfgEdgeKind::Indirect:
      return "indirect";
    case CfgEdgeKind::Call:
      return "call";
    case CfgEdgeKind::JumpTable:
      return "jump_table";
  }
  return "unknown";
}

Result<ControlFlowGraph> build_control_flow_graph(const BinaryImage& image,
                                                  std::span<const Instruction> instructions,
                                                  std::span<const Function> seeds,
                                                  const AnalysisOptions& options,
                                                  std::span<const std::byte> file) {
  if (options.cancellation_token.is_cancelled()) {
    return make_error<ControlFlowGraph>(Status::Cancelled, "analysis.cancelled",
                                        "control-flow analysis was cancelled");
  }
  ControlFlowGraph graph;

  std::unordered_map<std::uint64_t, std::uint32_t> index_by_address;
  index_by_address.reserve(instructions.size() * 2);
  for (std::uint32_t i = 0; i < instructions.size(); ++i) {
    index_by_address.emplace(instructions[i].address, i);
  }

  std::size_t decoded_limit = options.max_instructions;
  std::size_t decoded = 0;

  for (std::size_t seed_index = 0; seed_index < seeds.size(); ++seed_index) {
    if (options.cancellation_token.is_cancelled()) {
      return make_error<ControlFlowGraph>(Status::Cancelled, "analysis.cancelled",
                                          "control-flow analysis was cancelled");
    }
    Function function = seeds[seed_index];
    function.id = FunctionId{static_cast<std::uint64_t>(seed_index + 1)};
    function.block_count = 0;
    function.has_extent = false;
    function.end_address = function.address;

    std::unordered_set<std::uint64_t> visited;
    std::vector<std::uint64_t> worklist;
    std::vector<std::uint64_t> reached;
    worklist.push_back(function.address);

    bool indirect = false;
    bool truncated = false;
    // Jump tables recovered in this function: jump address -> jump_tables index.
    std::unordered_map<std::uint64_t, std::size_t> tables_here;

    while (!worklist.empty()) {
      if (options.cancellation_token.is_cancelled()) {
        return make_error<ControlFlowGraph>(Status::Cancelled, "analysis.cancelled",
                                            "control-flow analysis was cancelled");
      }
      std::uint64_t address = worklist.back();
      worklist.pop_back();
      std::vector<std::uint32_t> run;  // straight-line path, for jump tables
      while (true) {
        const auto found = index_by_address.find(address);
        if (found == index_by_address.end()) {
          break;
        }
        if (visited.contains(address)) {
          break;
        }
        if (decoded >= decoded_limit) {
          truncated = true;
          break;
        }
        visited.insert(address);
        reached.push_back(address);
        ++decoded;
        run.push_back(found->second);
        if (run.size() > 64) {
          run.erase(run.begin());
        }

        const Instruction& instruction = instructions[found->second];
        const std::uint64_t next = address + instruction.length;
        switch (instruction.classification) {
          case InstructionClass::Call:
            if (instruction.direct_target.has_value()) {
              graph.edges.push_back(
                  CfgEdge{address, instruction.direct_target.value(), CfgEdgeKind::Call});
            }
            address = next;
            continue;
          case InstructionClass::Jump:
            if (instruction.direct_target.has_value()) {
              worklist.push_back(instruction.direct_target.value());
            } else if (auto table =
                           resolve_jump_table(image, file, instructions, run, index_by_address)) {
              for (const std::uint64_t target : table->targets) {
                worklist.push_back(target);
              }
              tables_here.emplace(address, graph.jump_tables.size());
              graph.jump_tables.push_back(std::move(*table));
            } else {
              indirect = true;
            }
            break;
          case InstructionClass::ConditionalJump:
            if (instruction.direct_target.has_value()) {
              worklist.push_back(instruction.direct_target.value());
            } else {
              indirect = true;
            }
            address = next;
            continue;
          case InstructionClass::Return:
          case InstructionClass::Interrupt:
            break;
          case InstructionClass::Unknown:
          case InstructionClass::Other:
            address = next;
            continue;
        }
        break;
      }
      if (truncated) {
        break;
      }
    }

    if (truncated) {
      graph.partial = true;
      graph.diagnostics.push_back(Diagnostic::make(
          Status::Partial, "analysis.instruction_limit",
          "control-flow traversal hit the instruction limit; extents are lower bounds",
          function.address));
    }

    if (reached.empty()) {
      function.estimated = true;
      graph.functions.push_back(std::move(function));
      continue;
    }

    std::sort(reached.begin(), reached.end());
    std::vector<std::uint64_t> leaders;
    leaders.push_back(function.address);
    for (const std::uint64_t address : reached) {
      const Instruction& instruction = instructions[index_by_address[address]];
      if (!terminates_flow(instruction.classification)) {
        continue;
      }
      if (instruction.direct_target.has_value() &&
          visited.contains(instruction.direct_target.value())) {
        leaders.push_back(instruction.direct_target.value());
      }
      if (auto table = tables_here.find(address); table != tables_here.end()) {
        for (const std::uint64_t target : graph.jump_tables[table->second].targets) {
          if (visited.contains(target)) {
            leaders.push_back(target);
          }
        }
      }
      if (instruction.classification != InstructionClass::Return &&
          instruction.classification != InstructionClass::Interrupt &&
          visited.contains(address + instruction.length)) {
        leaders.push_back(address + instruction.length);
      }
    }
    std::sort(leaders.begin(), leaders.end());
    leaders.erase(std::unique(leaders.begin(), leaders.end()), leaders.end());

    std::unordered_map<std::uint64_t, std::size_t> block_by_address;
    std::uint64_t previous_end = 0;
    bool have_previous = false;
    for (const std::uint64_t address : reached) {
      const bool is_leader = std::binary_search(leaders.begin(), leaders.end(), address);
      const bool gap = have_previous && previous_end != address;
      if (is_leader || gap || !have_previous) {
        BasicBlock block;
        block.id = BasicBlockId{static_cast<std::uint64_t>(graph.blocks.size() + 1)};
        block.function = function.id;
        block.address = address;
        block.end_address = address;
        block.first_instruction = index_by_address[address];
        block.instruction_count = 0;
        block_by_address.emplace(address, graph.blocks.size());
        graph.blocks.push_back(block);
        if (graph.blocks.size() > kMaxBlocks) {
          graph.partial = true;
          break;
        }
      }
      BasicBlock& block = graph.blocks.back();
      block.instruction_count += 1;
      const Instruction& instruction = instructions[index_by_address[address]];
      block.end_address = address + instruction.length;
      previous_end = block.end_address;
      have_previous = true;
    }

    function.block_count = static_cast<std::uint32_t>(block_by_address.size());
    function.has_extent = !block_by_address.empty();
    function.estimated = indirect || truncated;
    if (function.has_extent) {
      std::uint64_t start = 0;
      std::uint64_t end = 0;
      bool first = true;
      for (const auto& [address, index] : block_by_address) {
        const BasicBlock& block = graph.blocks[index];
        if (first || address < start) {
          start = address;
        }
        if (first || block.end_address > end) {
          end = block.end_address;
        }
        first = false;
      }
      function.address = start;
      function.end_address = end;
    }
    if (function.name.empty()) {
      function.name = fallback_name(function.address);
    }
    graph.functions.push_back(std::move(function));

    // Block-level edges for the function we just emitted.
    const std::size_t begin = graph.blocks.size() - block_by_address.size();
    for (std::size_t index = begin; index < graph.blocks.size(); ++index) {
      const BasicBlock& block = graph.blocks[index];
      if (block.instruction_count == 0) {
        continue;
      }
      const Instruction& last = instructions[block.first_instruction + block.instruction_count - 1];
      const std::uint64_t fallthrough = last.address + last.length;
      switch (last.classification) {
        case InstructionClass::Jump:
          if (last.direct_target.has_value()) {
            graph.edges.push_back(
                CfgEdge{last.address, last.direct_target.value(), CfgEdgeKind::Jump});
          } else if (auto table = tables_here.find(last.address); table != tables_here.end()) {
            std::vector<std::uint64_t> distinct = graph.jump_tables[table->second].targets;
            std::sort(distinct.begin(), distinct.end());
            distinct.erase(std::unique(distinct.begin(), distinct.end()), distinct.end());
            for (const std::uint64_t target : distinct) {
              graph.edges.push_back(CfgEdge{last.address, target, CfgEdgeKind::JumpTable});
            }
          } else {
            graph.edges.push_back(CfgEdge{last.address, 0, CfgEdgeKind::Indirect});
          }
          break;
        case InstructionClass::ConditionalJump:
          if (last.direct_target.has_value()) {
            graph.edges.push_back(
                CfgEdge{last.address, last.direct_target.value(), CfgEdgeKind::ConditionalTrue});
          } else {
            graph.edges.push_back(CfgEdge{last.address, 0, CfgEdgeKind::Indirect});
          }
          if (block_by_address.contains(fallthrough)) {
            graph.edges.push_back(
                CfgEdge{last.address, fallthrough, CfgEdgeKind::ConditionalFalse});
          }
          break;
        case InstructionClass::Return:
        case InstructionClass::Interrupt:
          break;
        case InstructionClass::Unknown:
        case InstructionClass::Other:
        case InstructionClass::Call:
          // A block that ends without a branch is a fallthrough tail; the next
          // block only exists when it is contiguous, which the leader scan
          // already guarantees.
          if (index + 1 < graph.blocks.size() &&
              block.end_address == graph.blocks[index + 1].address) {
            graph.edges.push_back(CfgEdge{block.end_address, graph.blocks[index + 1].address,
                                          CfgEdgeKind::ConditionalFalse});
          }
          break;
      }
    }
  }

  return graph;
}

}  // namespace donkey
