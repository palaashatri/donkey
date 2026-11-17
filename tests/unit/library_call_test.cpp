// Calls through import stubs with library prototypes (G22-T4): the arguments and result come from
// the prototype, the caller stays Partial (an import is not executed), and an argument register
// past the prototype that the caller writes and does not read is reported, never taken as an
// argument. Fixtures: tests/fixtures/stubs (PROVENANCE.md there) and synthetic code.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"

namespace {

using donkey::IrFunction;
using donkey::IrOp;
using donkey::IrStatement;

donkey::BinaryImage raw_image(std::size_t size) {
  donkey::BinaryImage image;
  image.path = "<synthetic>";
  image.architecture = donkey::Architecture::X86_64;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = size;
  image.entry_point = 0x1000;
  donkey::Section section;
  section.id = donkey::SectionId{1};
  section.name = ".text";
  section.type = "synthetic";
  section.file_size = size;
  section.address = 0x1000;
  section.virtual_size = size;
  section.readable = true;
  section.executable = true;
  section.has_file_data = true;
  image.sections.push_back(section);
  donkey::Segment segment;
  segment.name = ".text";
  segment.file_size = size;
  segment.virtual_address = 0x1000;
  segment.virtual_size = size;
  segment.readable = true;
  segment.executable = true;
  image.segments.push_back(segment);
  return image;
}

std::vector<std::byte> bytes(std::initializer_list<int> values) {
  std::vector<std::byte> out;
  for (const int value : values) {
    out.push_back(static_cast<std::byte>(value));
  }
  return out;
}

/// Lifts the function at 0x1000 of `code`, with `prototypes` and no same-image call resolution
/// (the callee at 0x1010 stands in for an import stub).
IrFunction lift_with(const std::vector<std::byte>& code,
                     std::map<std::uint64_t, donkey::CallPrototype> prototypes,
                     donkey::BinaryFormat format = donkey::BinaryFormat::Raw) {
  donkey::BinaryImage image = raw_image(code.size());
  image.format = format;
  auto analyzed = donkey::analyze(image, code);
  EXPECT_TRUE(analyzed.has_value());
  IrFunction none;
  if (!analyzed) {
    return none;
  }
  const auto& functions = analyzed.value().functions;
  const auto found = std::find_if(functions.begin(), functions.end(),
                                  [](const donkey::Function& f) { return f.address == 0x1000; });
  EXPECT_NE(found, functions.end());
  if (found == functions.end()) {
    return none;
  }
  donkey::LiftOptions options;
  options.resolve_calls = false;
  options.call_prototypes = std::move(prototypes);
  auto lifted = donkey::lift_function(image, analyzed.value(), *found, options);
  EXPECT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  return lifted ? lifted.value() : none;
}

const IrStatement* the_call(const IrFunction& function) {
  for (const auto& block : function.blocks) {
    for (const IrStatement& statement : block.statements) {
      if (statement.op == IrOp::Call) {
        return &statement;
      }
    }
  }
  return nullptr;
}

bool has_note(const IrFunction& function, const std::string& part) {
  return std::any_of(function.notes.begin(), function.notes.end(),
                     [&](const std::string& note) { return note.find(part) != std::string::npos; });
}

donkey::CallPrototype prototype(std::vector<std::uint8_t> widths, std::uint8_t result,
                                bool variadic = false) {
  donkey::CallPrototype out;
  out.parameter_widths = std::move(widths);
  out.return_width = result;
  out.variadic = variadic;
  out.source = "test-lib 1";
  return out;
}

// 0x1000: mov edx, 1; 0x1005: call 0x1010; 0x100a: ret; 0x1010: ret (the "import").
const std::vector<std::byte> kDeadRdx = bytes({0xba, 0x01, 0x00, 0x00, 0x00, 0xe8, 0x06, 0x00, 0x00,
                                               0x00, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3});

}  // namespace

// stubs_x86_64: `117e: ... call 1070 <puts@plt>`. With `int puts(char *)` at the stub, the call
// passes rdi (8 bytes) and its result is rax; the caller is Partial and says why.
TEST(Ir, LibraryPrototypeSuppliesTheArgumentsOfAnImportCall) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/stubs/stubs_x86_64");
  ASSERT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(analysis.has_value());
  const auto& functions = analysis.value().functions;
  const auto caller = std::find_if(functions.begin(), functions.end(),
                                   [](const donkey::Function& f) { return f.address == 0x117e; });
  ASSERT_NE(caller, functions.end());
  donkey::LiftOptions options;
  options.call_prototypes[0x1070] = prototype({8}, 4);
  auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *caller, options);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  const IrStatement* call = the_call(lifted.value());
  ASSERT_NE(call, nullptr);
  ASSERT_EQ(call->call_arguments.size(), 1U);
  EXPECT_EQ(call->call_arguments[0].reg, "rdi");
  EXPECT_EQ(call->call_arguments[0].width, 8U);
  EXPECT_EQ(call->dest.reg, "rax");
  EXPECT_EQ(call->signature_source, "test-lib 1");
  EXPECT_FALSE(call->signature_inferred);
  EXPECT_TRUE(lifted.value().partial);
  EXPECT_TRUE(has_note(lifted.value(), "a call to an imported function is not executed"));
  EXPECT_FALSE(has_note(lifted.value(), "follow no modelled ABI"));
  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("rax = puts(rdi); /* prototype from test-lib 1 */"),
            std::string::npos)
      << text.value();
}

TEST(Ir, VariadicPrototypeLeavesTheCallPartial) {
  const IrFunction function = lift_with(kDeadRdx, {{0x1010, prototype({8}, 4, true)}});
  const IrStatement* call = the_call(function);
  ASSERT_NE(call, nullptr);
  EXPECT_EQ(call->call_arguments.size(), 1U);  // the fixed part only
  EXPECT_TRUE(function.partial);
  EXPECT_TRUE(has_note(function, "variadic call shows its fixed arguments only"));
  // A variadic callee may read rdx: no mismatch is reported.
  EXPECT_FALSE(has_note(function, "possible argument mismatch"));
}

// `mov edx, 1` before a call to a one-parameter function, and rdx is not read before the call: the
// prototype is applied unchanged (one argument) and the write is reported, with its address.
TEST(Ir, UnreadArgumentRegisterWriteIsReportedAsAPossibleMismatch) {
  const IrFunction function = lift_with(kDeadRdx, {{0x1010, prototype({4}, 4)}});
  const IrStatement* call = the_call(function);
  ASSERT_NE(call, nullptr);
  ASSERT_EQ(call->call_arguments.size(), 1U);
  EXPECT_EQ(call->call_arguments[0].reg, "rdi");
  EXPECT_EQ(call->call_arguments[0].width, 4U);
  EXPECT_TRUE(has_note(function, "possible argument mismatch: rdx is written at 0x1000"));
  EXPECT_TRUE(function.partial);
}

// The same dead write with a three-parameter prototype: rdx is an argument, nothing is reported.
TEST(Ir, ArgumentRegisterWithinThePrototypeIsNotAMismatch) {
  const IrFunction function = lift_with(kDeadRdx, {{0x1010, prototype({8, 8, 4}, 0)}});
  const IrStatement* call = the_call(function);
  ASSERT_NE(call, nullptr);
  ASSERT_EQ(call->call_arguments.size(), 3U);
  EXPECT_EQ(call->call_arguments[2].reg, "rdx");
  EXPECT_EQ(call->dest.kind, donkey::IrOperandKind::None);  // void
  EXPECT_FALSE(has_note(function, "possible argument mismatch"));
}

// 0x1000: mov edx, 1; 0x1005: add eax, edx; 0x1007: call 0x1010; 0x100c: ret. The caller reads rdx
// for its own use: that is not evidence of an argument, and not a mismatch.
TEST(Ir, CallerReadOfAnArgumentRegisterIsNotAnExtraArgument) {
  const auto code = bytes({0xba, 0x01, 0x00, 0x00, 0x00, 0x01, 0xd0, 0xe8, 0x04, 0x00, 0x00, 0x00,
                           0xc3, 0x90, 0x90, 0x90, 0xc3});
  const IrFunction function = lift_with(code, {{0x1010, prototype({8}, 4)}});
  const IrStatement* call = the_call(function);
  ASSERT_NE(call, nullptr);
  EXPECT_EQ(call->call_arguments.size(), 1U);
  EXPECT_FALSE(has_note(function, "possible argument mismatch"));
}

// A Windows x64 call passes its arguments in other registers: a PE image takes no prototype here.
TEST(Ir, APeCallTakesNoLibraryPrototype) {
  const IrFunction function =
      lift_with(kDeadRdx, {{0x1010, prototype({8}, 4)}}, donkey::BinaryFormat::Pe);
  const IrStatement* call = the_call(function);
  ASSERT_NE(call, nullptr);
  EXPECT_TRUE(call->call_arguments.empty());
  EXPECT_TRUE(call->signature_source.empty());
  EXPECT_TRUE(has_note(function, "follow no modelled ABI"));
}

// A prototype with a parameter the lifter cannot pass in an integer register (width 0 here, as for
// a struct) is not used: the call stays unresolved.
TEST(Ir, APrototypeWithANonIntegerParameterIsNotUsed) {
  const IrFunction function = lift_with(kDeadRdx, {{0x1010, prototype({0}, 4)}});
  const IrStatement* call = the_call(function);
  ASSERT_NE(call, nullptr);
  EXPECT_TRUE(call->call_arguments.empty());
  EXPECT_TRUE(has_note(function, "follow no modelled ABI"));
}

// The verifier accepts arguments from a library prototype, and still refuses arguments with no
// signature at all.
TEST(Ir, VerifierAcceptsLibraryArgumentsAndRefusesUnsourcedOnes) {
  IrFunction function;
  function.address = 0x1000;
  function.name = "f";
  donkey::IrBlock block;
  block.address = 0x1000;
  IrStatement call;
  call.op = IrOp::Call;
  call.a = donkey::IrOperand::constant_value(0x1010, 8);
  call.width = 8;
  call.call_arguments.push_back(donkey::IrOperand::register_ref("rdi", 8));
  call.signature_source = "test-lib 1";
  block.statements.push_back(call);
  IrStatement ret;
  ret.op = IrOp::Return;
  ret.width = 8;
  block.statements.push_back(ret);
  function.blocks.push_back(block);
  EXPECT_TRUE(donkey::verify_ir(function).has_value());
  function.blocks[0].statements[0].signature_source.clear();
  const auto refused = donkey::verify_ir(function);
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "ir.call_signature");
}
