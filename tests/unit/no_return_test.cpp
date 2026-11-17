// No-return calls (G24-T3): the version reader, the fixed list and its provider binding, the CFG
// and lifter effects, propagation, the verifier rules and the evaluator. Fixtures: see
// tests/fixtures/stubs/PROVENANCE.md; the oracle for each address is `objdump -d` on the same file.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/analysis/no_return.h"
#include "donkey/binary/elf_versions.h"
#include "donkey/binary/image.h"
#include "donkey/ir/eval.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"
#include "ir_internal.h"

namespace {

using donkey::AnalysisOptions;
using donkey::AnalysisResult;
using donkey::BinaryImage;

std::string fixture(const std::string& directory, const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/" + directory + "/" + name;
}

struct Analyzed {
  donkey::LoadedBinary binary;
  AnalysisResult analysis;
};

Analyzed analyze_fixture(const std::string& name) {
  auto loaded = donkey::load_binary(fixture("stubs", name));
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  Analyzed out{std::move(loaded.value()), {}};
  auto analysis = donkey::analyze(out.binary.image, out.binary.data);
  EXPECT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
  out.analysis = std::move(analysis.value());
  return out;
}

const donkey::Function* function_at(const AnalysisResult& analysis, std::uint64_t address) {
  for (const donkey::Function& function : analysis.functions) {
    if (function.address == address) {
      return &function;
    }
  }
  return nullptr;
}

bool has_edge(const AnalysisResult& analysis, std::uint64_t from, std::uint64_t to) {
  for (const donkey::CfgEdge& edge : analysis.cfg.edges) {
    if (edge.from == from && edge.to == to && edge.kind != donkey::CfgEdgeKind::Call) {
      return true;
    }
  }
  return false;
}

bool has_edge_from(const AnalysisResult& analysis, std::uint64_t from) {
  for (const donkey::CfgEdge& edge : analysis.cfg.edges) {
    if (edge.from == from && edge.kind != donkey::CfgEdgeKind::Call) {
      return true;
    }
  }
  return false;
}

/// A raw x86-64 image of `bytes` at 0x1000 (int3 padding to `size`), with a function symbol at
/// each of `starts`.
std::pair<std::vector<std::byte>, BinaryImage> raw_image(
    std::initializer_list<std::pair<std::size_t, std::vector<std::uint8_t>>> pieces,
    std::size_t size, std::initializer_list<std::uint64_t> starts) {
  std::vector<std::byte> data(size, std::byte{0xcc});
  for (const auto& [offset, bytes] : pieces) {
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      data[offset + i] = static_cast<std::byte>(bytes[i]);
    }
  }
  BinaryImage image;
  image.path = "<synthetic>";
  image.architecture = donkey::Architecture::X86_64;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = data.size();
  donkey::Section section;
  section.id = donkey::SectionId{1};
  section.name = ".text";
  section.file_size = data.size();
  section.address = 0x1000;
  section.virtual_size = data.size();
  section.readable = true;
  section.executable = true;
  section.has_file_data = true;
  image.sections.push_back(section);
  std::size_t n = 0;
  for (const std::uint64_t start : starts) {
    donkey::Symbol symbol;
    symbol.name = "f" + std::to_string(n++);
    symbol.address = start;
    symbol.kind = donkey::SymbolKind::Function;
    symbol.exported = true;
    image.symbols.push_back(symbol);
  }
  return {std::move(data), std::move(image)};
}

/// `.gnu.version_r` bytes: one Verneed for the file at string offset `file`, with one Vernaux per
/// (index, name offset) pair.
std::vector<std::byte> version_needs(std::uint32_t file,
                                     std::vector<std::pair<std::uint16_t, std::uint32_t>> entries) {
  std::vector<std::byte> out;
  auto put16 = [&](std::uint16_t v) {
    out.push_back(static_cast<std::byte>(v & 0xffU));
    out.push_back(static_cast<std::byte>(v >> 8U));
  };
  auto put32 = [&](std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
      out.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xffU));
    }
  };
  put16(1);
  put16(static_cast<std::uint16_t>(entries.size()));
  put32(file);
  put32(16);  // aux
  put32(0);   // next
  for (std::size_t i = 0; i < entries.size(); ++i) {
    put32(0);  // hash
    put16(0);  // flags
    put16(entries[i].first);
    put32(entries[i].second);
    put32(i + 1 < entries.size() ? 16 : 0);
  }
  return out;
}

std::vector<std::byte> strings(const std::string& text) {
  std::vector<std::byte> out;
  for (const char c : text) {
    out.push_back(static_cast<std::byte>(c));
  }
  out.push_back(std::byte{0});
  return out;
}

}  // namespace

// --- The version reader -------------------------------------------------------------------------

TEST(ElfVersions, ReadsTheVersionNeedsOfOneFile) {
  // "\0libc.so.6\0GLIBC_2.2.5\0GLIBC_2.34"
  const auto names = strings(std::string("\0libc.so.6\0GLIBC_2.2.5\0GLIBC_2.34", 33));
  const auto needs = donkey::read_version_needs(version_needs(1, {{3, 11}, {2, 23}}), names);
  ASSERT_TRUE(needs.has_value()) << needs.diagnostic().message;
  ASSERT_EQ(needs.value().by_index.size(), 2U);
  EXPECT_EQ(needs.value().by_index.at(3).file, "libc.so.6");
  EXPECT_EQ(needs.value().by_index.at(3).version, "GLIBC_2.2.5");
  EXPECT_EQ(needs.value().by_index.at(2).version, "GLIBC_2.34");
}

TEST(ElfVersions, RefusesBrokenTables) {
  const auto names = strings(std::string("\0libc.so.6\0GLIBC_2.2.5", 22));
  // An entry past the end of the section.
  auto truncated = version_needs(1, {{2, 11}});
  truncated.resize(truncated.size() - 4);
  EXPECT_EQ(donkey::read_version_needs(truncated, names).diagnostic().code,
            "elf.version_needs.truncated");
  // The reserved indexes 0 and 1.
  EXPECT_EQ(donkey::read_version_needs(version_needs(1, {{1, 11}}), names).diagnostic().code,
            "elf.version_needs.index");
  // Two entries with one index.
  EXPECT_EQ(
      donkey::read_version_needs(version_needs(1, {{2, 11}, {2, 11}}), names).diagnostic().code,
      "elf.version_needs.duplicate");
  // A name outside the string table.
  EXPECT_EQ(donkey::read_version_needs(version_needs(1, {{2, 400}}), names).diagnostic().code,
            "elf.version_needs.name");
  // A Verneed whose next offset lands on its own Vernaux, which was already read: a loop.
  auto self = version_needs(1, {{2, 11}});
  self[12] = std::byte{0x10};  // next = 16
  EXPECT_EQ(donkey::read_version_needs(self, names).diagnostic().code, "elf.version_needs.loop");
  // The entry limit.
  EXPECT_EQ(donkey::read_version_needs(version_needs(1, {{2, 11}, {3, 11}}), names, 2)
                .diagnostic()
                .code,
            "elf.version_needs.limit");
}

// readelf -V on stubs_x86_64: abort's version index names GLIBC_2.2.5 of libc.so.6.
TEST(ElfVersions, NamesTheProviderOfEachVersionedImport) {
  auto loaded = donkey::load_binary(fixture("stubs", "stubs_x86_64"));
  ASSERT_TRUE(loaded.has_value());
  const auto versions = donkey::read_import_versions(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(versions.has_value()) << versions.diagnostic().message;
  ASSERT_TRUE(versions.value().contains("abort"));
  EXPECT_EQ(versions.value().at("abort").file, "libc.so.6");
  EXPECT_EQ(versions.value().at("abort").version, "GLIBC_2.2.5");
}

// --- The fixed list and its binding -------------------------------------------------------------

TEST(Analysis, NoReturnNamesComeOnlyFromTheFixedList) {
  EXPECT_TRUE(donkey::is_known_no_return_name("abort"));
  EXPECT_TRUE(donkey::is_known_no_return_name("__stack_chk_fail"));
  EXPECT_TRUE(donkey::is_known_no_return_name("ExitProcess"));
  // error() returns when its status is 0.
  EXPECT_FALSE(donkey::is_known_no_return_name("error"));
  EXPECT_FALSE(donkey::is_known_no_return_name("error_at_line"));
  EXPECT_FALSE(donkey::is_known_no_return_name("frobnicate"));
  EXPECT_FALSE(donkey::is_known_no_return_name("RaiseException"));
  EXPECT_TRUE(donkey::is_runtime_library("libc.so.6"));
  EXPECT_TRUE(donkey::is_runtime_library("libc.musl-x86_64.so.1"));
  EXPECT_TRUE(donkey::is_runtime_library("KERNEL32.dll"));
  EXPECT_FALSE(donkey::is_runtime_library("libmyexit.so.1"));
}

// stubs_x86_64: `1060 <abort@plt>` is marked with its evidence; `1070 <puts@plt>` is not.
TEST(Analysis, AVersionedRuntimeImportIsMarkedWithItsEvidence) {
  const Analyzed analyzed = analyze_fixture("stubs_x86_64");
  const donkey::Function* abort_stub = function_at(analyzed.analysis, 0x1060);
  ASSERT_NE(abort_stub, nullptr);
  EXPECT_TRUE(abort_stub->no_return);
  EXPECT_EQ(abort_stub->no_return_reason,
            "known-name:abort version:GLIBC_2.2.5 file:libc.so.6");
  const donkey::Function* puts_stub = function_at(analyzed.analysis, 0x1070);
  ASSERT_NE(puts_stub, nullptr);
  EXPECT_FALSE(puts_stub->no_return);
}

// exit_consumer imports an unversioned `exit` and needs libmyexit.so.1 (which exports an `exit`
// that returns) before libc.so.6: two needed libraries can provide the name, one of them not a
// runtime library, so it is not marked. objdump: `1150: call 1050 <exit@plt>`, then
// `1155: lea 0x7(%rbx),%eax`, which stays in the function with its fall-through edge.
TEST(Analysis, ANoReturnNameFromAnotherLibraryKeepsItsFallThrough) {
  const Analyzed analyzed = analyze_fixture("exit_consumer");
  const donkey::Function* stub = function_at(analyzed.analysis, 0x1050);
  ASSERT_NE(stub, nullptr);
  EXPECT_EQ(stub->name, "exit@plt");
  EXPECT_FALSE(stub->no_return);
  const donkey::Function* caller = function_at(analyzed.analysis, 0x1149);
  ASSERT_NE(caller, nullptr);
  EXPECT_FALSE(caller->no_return);
  // The call does not end a block: 0x1149 to 0x115a is one block, so the add and ret after the
  // call stay on the caller's path.
  EXPECT_EQ(caller->end_address, 0x115aU);
  EXPECT_EQ(caller->block_count, 1U);
}

TEST(Analysis, ANoReturnNameExportedByTwoNeededLibrariesIsNotMarked) {
  // The same fixture, read through the binding function directly: the name is on the list, its
  // import is unversioned, and DT_NEEDED names a library that is not a runtime library.
  auto loaded = donkey::load_binary(fixture("stubs", "exit_consumer"));
  ASSERT_TRUE(loaded.has_value());
  const auto marks = donkey::bind_no_return_imports(loaded.value().image, loaded.value().data,
                                                    {{0x1050, "exit"}}, {});
  EXPECT_TRUE(marks.empty());
}

// --- CFG ----------------------------------------------------------------------------------------

// f0 (0x1000): call 0x1010; mov eax, 1; ret.  f1 (0x1010): ret, marked no-return by the caller.
// The bytes after the call are not f0's: no other path reaches them.
TEST(Cfg, NoReturnCallEndsTheBlock) {
  auto [data, image] = raw_image(
      {{0x0, {0xe8, 0x0b, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3}}, {0x10, {0xc3}}},
      0x11, {0x1000, 0x1010});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1010);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const donkey::Function* f0 = function_at(result.value(), 0x1000);
  ASSERT_NE(f0, nullptr);
  EXPECT_EQ(f0->end_address, 0x1005U);
  EXPECT_EQ(f0->block_count, 1U);
  EXPECT_FALSE(has_edge_from(result.value(), 0x1000));
  // Without the mark the bytes after the call are f0's.
  auto plain = donkey::analyze(image, data);
  ASSERT_TRUE(plain.has_value());
  EXPECT_EQ(function_at(plain.value(), 0x1000)->end_address, 0x100bU);
}

// f0 (0x1000): test edi, edi; je 0x100b; call 0x1010; 0x100b: ret.  The ret after the call is
// reached by the je, so it stays in f0, but the call has no fall-through edge to it.
TEST(Cfg, BytesReachedByAnotherPathStayInTheFunction) {
  auto [data, image] = raw_image({{0x0, {0x85, 0xff, 0x74, 0x07, 0xe8, 0x07, 0x00, 0x00, 0x00,
                                         0x90, 0x90, 0xc3}},
                                  {0x10, {0xc3}}},
                                 0x11, {0x1000, 0x1010});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1010);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const donkey::Function* f0 = function_at(result.value(), 0x1000);
  ASSERT_NE(f0, nullptr);
  EXPECT_EQ(f0->end_address, 0x100cU);
  EXPECT_FALSE(f0->no_return);  // the je path returns
  EXPECT_FALSE(has_edge(result.value(), 0x1004, 0x1009));
  EXPECT_TRUE(has_edge(result.value(), 0x1002, 0x100b));
}

// Propagation from proven marks only. 0x1040 is marked by the caller. f0 (0x1000) only calls it:
// no-return. f1 (0x1010) calls f0 and then returns: no-return too, found in the next round,
// once f0's mark cuts its fall-through. f2 (0x1020) has a path that returns: not marked.
TEST(Analysis, PropagationUsesOnlyProvenMarks) {
  auto [data, image] = raw_image(
      {{0x00, {0xe8, 0x3b, 0x00, 0x00, 0x00, 0xc3}},             // f0: call 0x1040; ret
       {0x10, {0xe8, 0xeb, 0xff, 0xff, 0xff, 0x31, 0xc0, 0xc3}},  // f1: call 0x1000; xor; ret
       {0x20, {0x85, 0xff, 0x74, 0x05, 0xe8, 0x17, 0x00, 0x00, 0x00, 0xc3}},  // f2
       {0x40, {0xc3}}},
      0x41, {0x1000, 0x1010, 0x1020, 0x1040});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1040);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(function_at(result.value(), 0x1000)->no_return);
  EXPECT_EQ(function_at(result.value(), 0x1000)->no_return_reason,
            "propagated:every path ends in a call that does not return");
  EXPECT_TRUE(function_at(result.value(), 0x1010)->no_return);
  EXPECT_FALSE(function_at(result.value(), 0x1020)->no_return);
  // The mark is not taken from the target's own `ret`: 0x1040 is the caller's assumption, and
  // the analysis does not mark it itself.
  EXPECT_FALSE(function_at(result.value(), 0x1040)->no_return);
  // Off: nothing is marked.
  options.no_return_analysis = false;
  options.no_return_targets.clear();
  auto off = donkey::analyze(image, data, options);
  ASSERT_TRUE(off.has_value());
  EXPECT_FALSE(function_at(off.value(), 0x1000)->no_return);
}

// --- IR -----------------------------------------------------------------------------------------

// stubs_x86_64, objdump: `1169: endbr64; ... 1179: call 1060 <abort@plt>`, the path for a
// negative argument. The call is the last real statement of its block, followed by an
// unreachable return, and the pseudocode prints no `return` after it.
TEST(Ir, NoReturnCallHasNoSuccessorAndNoReturnStatement) {
  const Analyzed analyzed = analyze_fixture("stubs_x86_64");
  const donkey::Function* check = function_at(analyzed.analysis, 0x1169);
  ASSERT_NE(check, nullptr);
  auto lifted = donkey::lift_function(analyzed.binary.image, analyzed.analysis, *check);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  bool found = false;
  for (const donkey::IrBlock& block : lifted.value().blocks) {
    for (std::size_t i = 0; i < block.statements.size(); ++i) {
      if (block.statements[i].op != donkey::IrOp::Call || !block.statements[i].no_return) {
        continue;
      }
      found = true;
      ASSERT_EQ(i + 2, block.statements.size());
      EXPECT_EQ(block.statements[i + 1].op, donkey::IrOp::Return);
      EXPECT_TRUE(block.statements[i + 1].unreachable);
    }
  }
  EXPECT_TRUE(found);
  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::size_t at = text.value().find("abort();");
  ASSERT_NE(at, std::string::npos) << text.value();
  const std::size_t line_end = text.value().find('\n', at);
  const std::string next_line =
      text.value().substr(line_end + 1, text.value().find('\n', line_end + 1) - line_end - 1);
  EXPECT_EQ(next_line.find("return"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("the returned register is not determined"), std::string::npos)
      << text.value();
  EXPECT_EQ(text.value().find("some return paths carry no value"), std::string::npos)
      << text.value();
}

TEST(Ir, VerifierRejectsANoReturnCallWithASuccessor) {
  donkey::IrFunction function;
  function.address = 0x1000;
  donkey::IrBlock block;
  block.address = 0x1000;
  donkey::IrStatement call;
  call.op = donkey::IrOp::Call;
  call.width = 8;
  call.a = donkey::IrOperand::constant_value(0x2000, 8);
  call.no_return = true;
  block.statements.push_back(call);
  donkey::IrStatement branch;
  branch.op = donkey::IrOp::Branch;
  branch.width = 8;
  branch.a = donkey::IrOperand::block_ref(1);
  block.statements.push_back(branch);
  function.blocks.push_back(block);
  donkey::IrBlock next;
  next.address = 0x1010;
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.width = 8;
  next.statements.push_back(ret);
  function.blocks.push_back(next);
  EXPECT_EQ(donkey::verify_ir(function).diagnostic().code, "ir.no_return_call_not_last");

  // An unreachable return that follows no such call.
  donkey::IrFunction lone;
  lone.address = 0x1000;
  donkey::IrBlock only;
  only.address = 0x1000;
  donkey::IrStatement unreachable = ret;
  unreachable.unreachable = true;
  only.statements.push_back(unreachable);
  lone.blocks.push_back(only);
  EXPECT_EQ(donkey::verify_ir(lone).diagnostic().code, "ir.unreachable_return_without_call");

  // The well-formed pair is accepted.
  function.blocks[0].statements[1] = unreachable;
  function.blocks.pop_back();
  EXPECT_TRUE(donkey::verify_ir(function).has_value());
}

// Owner decision 3: the returning paths are compared, the path through the no-return call is
// not. check(5) returns 10 on the compiled code (objdump: `lea (%rdi,%rdi,1),%eax`); check(-1)
// reaches abort, and the evaluator stops with ir.eval_no_return instead of inventing a value.
TEST(Ir, NoReturnPathsAreNotCompared) {
  const Analyzed analyzed = analyze_fixture("stubs_x86_64");
  const donkey::Function* check = function_at(analyzed.analysis, 0x1169);
  ASSERT_NE(check, nullptr);
  auto lifted = donkey::lift_function(analyzed.binary.image, analyzed.analysis, *check);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  donkey::IrEvalMemory memory(analyzed.binary.image, analyzed.binary.data);
  const std::uint64_t five[] = {5};
  auto returned = donkey::evaluate_ir(lifted.value(), five, memory);
  ASSERT_TRUE(returned.has_value()) << returned.diagnostic().message;
  EXPECT_EQ(returned.value().return_value & 0xffffffffU, 10U);
  const std::uint64_t negative[] = {0xffffffffU};
  donkey::IrEvalMemory fresh(analyzed.binary.image, analyzed.binary.data);
  auto stopped = donkey::evaluate_ir(lifted.value(), negative, fresh);
  ASSERT_FALSE(stopped.has_value());
  EXPECT_EQ(stopped.diagnostic().code, "ir.eval_no_return");
}

namespace {

/// if (rdi == 0) { abort(); } return rax; with abort a no-return call.
donkey::IrFunction no_return_arm_function() {
  donkey::IrFunction function;
  function.address = 0x1000;
  function.name = "checked";
  donkey::IrBlock test;
  test.address = 0x1000;
  donkey::IrStatement compare;
  compare.op = donkey::IrOp::Compare;
  compare.a = donkey::IrOperand::register_ref("rdi", 8);
  compare.b = donkey::IrOperand::constant_value(0, 8);
  compare.condition = donkey::IrCondition::NotEqual;
  compare.width = 8;
  test.statements.push_back(compare);
  donkey::IrStatement branch;
  branch.op = donkey::IrOp::CondBranch;
  branch.condition = donkey::IrCondition::NotEqual;
  branch.a = donkey::IrOperand::register_ref("rax", 8);
  branch.b = donkey::IrOperand::block_ref(2);
  branch.width = 8;
  test.statements.push_back(branch);
  function.blocks.push_back(test);
  donkey::IrBlock fail;
  fail.address = 0x1008;
  donkey::IrStatement call;
  call.op = donkey::IrOp::Call;
  call.width = 8;
  call.a = donkey::IrOperand::constant_value(0x2000, 8);
  call.no_return = true;
  fail.statements.push_back(call);
  donkey::IrStatement end;
  end.op = donkey::IrOp::Return;
  end.width = 8;
  end.unreachable = true;
  fail.statements.push_back(end);
  function.blocks.push_back(fail);
  donkey::IrBlock ok;
  ok.address = 0x1010;
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.width = 8;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ok.statements.push_back(ret);
  function.blocks.push_back(ok);
  function.call_names[0x2000] = "abort";
  return function;
}

}  // namespace

// The unreachable end of a no-return block prints nothing but is still the block's end for the
// control-flow check, in the layout structurer and in the goto structurer (a regression: without
// the tag the check saw the block fall through, and refused every candidate).
TEST(Ir, ANoReturnBlockIsStructured) {
  const donkey::IrFunction function = no_return_arm_function();
  const auto verified = donkey::verify_ir(function);
  ASSERT_TRUE(verified.has_value()) << verified.diagnostic().code << ": "
                                    << verified.diagnostic().message;
  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_EQ(text.value().find("labeled blocks"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("abort();"), std::string::npos) << text.value();
  const donkey::StructureVerdict verdict = donkey::classify_structure(function);
  EXPECT_EQ(verdict.cls, donkey::StructureClass::Structured) << verdict.reason;
  EXPECT_EQ(verdict.oracle_rejections, 0U) << verdict.oracle_detail;
  // The goto structurer, called on its own, is accepted by the check too.
  const auto gotos = donkey::detail::structure_with_gotos(function, nullptr);
  ASSERT_TRUE(gotos.has_value());
  const auto mismatch = donkey::detail::check_structured_control_flow(function, gotos->lines);
  EXPECT_FALSE(mismatch.has_value()) << mismatch.value_or("");
}
