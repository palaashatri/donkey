#include "donkey/analysis/cfg.h"

#include <algorithm>
#include <cstdio>
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
  }
  return "unknown";
}

Result<ControlFlowGraph> build_control_flow_graph(const BinaryImage& image,
                                                  std::span<const Instruction> instructions,
                                                  std::span<const Function> seeds,
                                                  const AnalysisOptions& options) {
  (void)image;
  ControlFlowGraph graph;

  std::unordered_map<std::uint64_t, std::uint32_t> index_by_address;
  index_by_address.reserve(instructions.size() * 2);
  for (std::uint32_t i = 0; i < instructions.size(); ++i) {
    index_by_address.emplace(instructions[i].address, i);
  }

  std::size_t decoded_limit = options.max_instructions;
  std::size_t decoded = 0;

  for (std::size_t seed_index = 0; seed_index < seeds.size(); ++seed_index) {
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

    while (!worklist.empty()) {
      std::uint64_t address = worklist.back();
      worklist.pop_back();
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
