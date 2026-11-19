// G21-T7: every executable model of a C library function agrees with the host's own C library on
// random inputs: the same result and the same memory afterwards. Undefined inputs (an overlapping
// memcpy, a read outside the buffer) are refused by the model and never run on the host.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "donkey/ir/eval.h"
#include "donkey/ir/libc_models.h"

namespace {

constexpr std::uint64_t kBase = 0x10000;
constexpr std::size_t kSize = 256;

/// One run of a model and of the host function on the same bytes.
struct ModelInput {
  std::vector<std::uint8_t> bytes;  // the buffer before the call
  std::vector<std::uint64_t> offsets;
  std::uint64_t value = 0;  // the int or size argument, where the model takes one
};

std::vector<std::uint8_t> random_bytes(std::mt19937_64& rng, bool text) {
  std::vector<std::uint8_t> bytes(kSize);
  for (std::uint8_t& b : bytes) {
    // Text: a small alphabet with NULs, so strings end inside the buffer and sets match often.
    b = text ? static_cast<std::uint8_t>("abcab\0xyz\x80\xff"[rng() % 11])
             : static_cast<std::uint8_t>(rng());
  }
  bytes.back() = 0;  // every string ends inside the buffer
  return bytes;
}

/// Runs `name` on the model and on the host; returns false when the model refuses the input.
bool agree(const std::string& name, const ModelInput& run, std::string& why) {
  const donkey::LibcModel* model = donkey::find_libc_model(name);
  if (model == nullptr) {
    why = "no model";
    return false;
  }
  donkey::IrEvalMemory memory;
  EXPECT_TRUE(memory.add_region(kBase, run.bytes));
  std::vector<std::uint8_t> host = run.bytes;
  std::uint8_t* base = host.data();
  std::vector<std::uint64_t> arguments;
  std::size_t next_offset = 0;
  for (const donkey::LibcArgument kind : model->arguments) {
    if (kind == donkey::LibcArgument::Pointer) {
      arguments.push_back(kBase + run.offsets[next_offset++]);
    } else if (kind == donkey::LibcArgument::Int) {
      arguments.push_back(run.value & 0xffffffffU);
    } else {
      arguments.push_back(run.value);
    }
  }
  std::size_t steps = 0;
  const auto modelled = donkey::run_libc_model(*model, arguments, memory, steps, 1'000'000);
  if (!modelled) {
    why = modelled.diagnostic().code;
    return false;
  }
  const auto pointer = [&](std::size_t i) {
    return reinterpret_cast<char*>(base + run.offsets[i]);
  };
  const auto as_address = [&](const void* p) -> std::uint64_t {
    return p == nullptr
               ? 0
               : kBase + static_cast<std::uint64_t>(static_cast<const std::uint8_t*>(p) - base);
  };
  const int c = static_cast<int>(static_cast<std::uint32_t>(run.value));
  const std::size_t n = run.value;
  std::uint64_t expected = 0;
  if (name == "strlen") {
    expected = std::strlen(pointer(0));
  } else if (name == "strnlen") {
    expected = strnlen(pointer(0), n);
  } else if (name == "memchr") {
    expected = as_address(std::memchr(pointer(0), c, n));
  } else if (name == "strchr") {
    expected = as_address(std::strchr(pointer(0), c));
  } else if (name == "strrchr") {
    expected = as_address(std::strrchr(pointer(0), c));
  } else if (name == "strspn") {
    expected = std::strspn(pointer(0), pointer(1));
  } else if (name == "strcspn") {
    expected = std::strcspn(pointer(0), pointer(1));
  } else if (name == "memcpy") {
    expected = as_address(std::memcpy(pointer(0), pointer(1), n));
  } else if (name == "memmove") {
    expected = as_address(std::memmove(pointer(0), pointer(1), n));
  } else if (name == "memset") {
    expected = as_address(std::memset(pointer(0), c, n));
  } else {
    ADD_FAILURE() << "no host function for " << name;
  }
  EXPECT_EQ(modelled.value(), expected) << name;
  const std::vector<std::uint8_t>* after = memory.region(kBase);
  EXPECT_TRUE(after != nullptr && *after == host) << name << ": the memory differs afterwards";
  return true;
}

}  // namespace

TEST(LibcModels, AgreeWithTheHostCLibrary) {
  std::mt19937_64 rng(20261118);
  std::size_t compared = 0;
  for (const donkey::LibcModel& model : donkey::libc_models()) {
    const std::string name(model.name);
    std::size_t pointers = 0;
    for (const donkey::LibcArgument kind : model.arguments) {
      pointers += kind == donkey::LibcArgument::Pointer ? 1 : 0;
    }
    for (int round = 0; round < 400; ++round) {
      ModelInput run;
      run.bytes = random_bytes(rng, round % 4 != 3);
      for (std::size_t i = 0; i < pointers; ++i) {
        run.offsets.push_back(rng() % 128);
      }
      // Sizes stay inside the buffer. A searched-for character is ASCII on even rounds (often one
      // of the text's own); on odd rounds it may carry bits above the low byte or be past ASCII,
      // which C libraries treat differently, so the model must refuse it.
      run.value = round % 2 == 0   ? (run.bytes[rng() % 64] & 0x7fU)
                  : round % 5 == 1 ? (rng() & 0xffff'ffffU)
                                   : run.bytes[rng() % 64] | (rng() % 4) << 8;
      if (model.arguments.back() == donkey::LibcArgument::Size) {
        run.value = round % 7 == 0 ? 0 : rng() % 128;
      }
      if (name == "memset") {
        // memset(p, int, size): an int and a size; keep the size in the buffer.
        run.value = rng() % 128;
      }
      std::string why;
      const bool searches = name == "strchr" || name == "strrchr" ||
                            (name == "memchr" && (run.value & 0xffff'ffffU) > 0x7f);
      const bool outside_ascii = searches && (run.value & 0xffff'ffffU) > 0x7f;
      const bool overlapping =
          pointers == 2 && run.value > 0 &&
          (run.offsets[0] > run.offsets[1] ? run.offsets[0] - run.offsets[1]
                                           : run.offsets[1] - run.offsets[0]) < run.value;
      if (agree(name, run, why)) {
        ++compared;
        EXPECT_FALSE(name == "memcpy" && overlapping) << "an overlapping memcpy was run";
        EXPECT_FALSE(outside_ascii) << name << " searched for a character outside ASCII";
      } else {
        EXPECT_TRUE(((name == "memcpy" && overlapping) || outside_ascii) && why == "ir.eval_model")
            << name << ": " << why;
      }
    }
  }
  EXPECT_GT(compared, 3000U);
}

// memchr, strchr, strrchr and memset take an int and use its low byte: a value with other bits
// set finds or writes the same byte the host does.
// memset stores the low byte of its int, as every C library does. memchr, strchr and strrchr search
// only for an ASCII character: past it, C libraries differ (Microsoft's strrchr does not find a
// character whose int has bits above the low byte; glibc's does), so the model refuses the call.
TEST(LibcModels, ASearchOutsideAsciiIsRefused) {
  ModelInput run;
  run.bytes.assign(kSize, 'a');
  run.bytes[10] = 'Q';
  run.bytes[200] = 0;
  run.offsets = {0};
  std::string why;
  run.value = 'Q';
  for (const char* name : {"strchr", "strrchr"}) {
    EXPECT_TRUE(agree(name, run, why)) << name << ": " << why;
  }
  for (const std::uint64_t value :
       {std::uint64_t{0x100} | 'Q', std::uint64_t{0x80}, std::uint64_t{0xffffffffU}}) {
    run.value = value;
    for (const char* name : {"strchr", "strrchr"}) {
      EXPECT_FALSE(agree(name, run, why)) << name << " of 0x" << std::hex << value;
      EXPECT_EQ(why, "ir.eval_model") << name;
    }
  }
  EXPECT_TRUE(agree("memset", ModelInput{run.bytes, {0}, 0x40}, why)) << why;
}

// strchr finds the terminator when asked for 0, and a string that runs past the mapped buffer is
// refused, not read on.
TEST(LibcModels, TheTerminatorIsPartOfTheStringAndUnmappedBytesAreRefused) {
  ModelInput run;
  run.bytes.assign(kSize, 'a');
  run.bytes[50] = 0;
  run.offsets = {0};
  run.value = 0;
  std::string why;
  EXPECT_TRUE(agree("strchr", run, why)) << why;
  EXPECT_TRUE(agree("strrchr", run, why)) << why;

  donkey::IrEvalMemory memory;
  ASSERT_TRUE(memory.add_region(kBase, std::vector<std::uint8_t>(16, 'a')));
  std::size_t steps = 0;
  const std::uint64_t at = kBase;
  const auto result =
      donkey::run_libc_model(*donkey::find_libc_model("strlen"), {&at, 1}, memory, steps, 1000);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "ir.eval_memory");
  EXPECT_EQ(steps, 17U);  // 16 bytes read, the 17th refused
}

// A model that would run past the step budget stops with ir.eval_step_limit.
TEST(LibcModels, TheStepBudgetBoundsAModel) {
  donkey::IrEvalMemory memory;
  ASSERT_TRUE(memory.add_region(kBase, std::vector<std::uint8_t>(4096, 'a')));
  std::size_t steps = 0;
  const std::uint64_t at = kBase;
  const auto result =
      donkey::run_libc_model(*donkey::find_libc_model("strlen"), {&at, 1}, memory, steps, 100);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "ir.eval_step_limit");
  EXPECT_EQ(steps, 100U);
}

// Functions whose result ISO C leaves partly to the implementation have no model.
TEST(LibcModels, OnlyFullyDefinedFunctionsHaveModels) {
  for (const char* name : {"memcmp", "strcmp", "strncmp", "strcoll", "printf", "malloc"}) {
    EXPECT_EQ(donkey::find_libc_model(name), nullptr) << name;
  }
  EXPECT_EQ(donkey::libc_models().size(), 10U);
}

namespace {

/// `rax = <name>(<arguments>); return rax;` as one block.
donkey::IrFunction modelled_call(const std::string& name,
                                 std::vector<donkey::IrOperand> arguments) {
  donkey::IrFunction function;
  donkey::IrBlock block;
  block.address = 0x1000;
  donkey::IrStatement call;
  call.op = donkey::IrOp::Call;
  call.width = 8;
  call.source_address = 0x1000;
  call.a = donkey::IrOperand::constant_value(0x2000, 8);
  call.call_arguments = std::move(arguments);
  call.dest = donkey::IrOperand::register_ref("rax", 8);
  call.call_model = name;
  block.statements.push_back(call);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.width = 8;
  ret.source_address = 0x1005;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  block.statements.push_back(ret);
  function.blocks.push_back(block);
  return function;
}

}  // namespace

// The evaluator runs a modelled call on its own memory: rax = strlen(rdi) with rdi the first
// argument.
TEST(LibcModels, TheEvaluatorRunsAModelledCall) {
  const donkey::IrFunction function =
      modelled_call("strlen", {donkey::IrOperand::register_ref("rdi", 8)});
  ASSERT_TRUE(donkey::verify_ir(function).has_value());
  donkey::IrEvalMemory memory;
  std::vector<std::uint8_t> text(32, 'x');
  text[11] = 0;
  ASSERT_TRUE(memory.add_region(kBase, text));
  const std::uint64_t argument = kBase;
  const auto result = donkey::evaluate_ir(function, {&argument, 1}, memory);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_EQ(result.value().return_value, 11U);
  EXPECT_GE(result.value().steps, 12U);  // the model's bytes count as steps
}

// A modelled call must name a function with a model and pass exactly its arguments.
TEST(LibcModels, TheVerifierRejectsAModelledCallWithoutItsModel) {
  const auto rdi = donkey::IrOperand::register_ref("rdi", 8);
  const auto rsi = donkey::IrOperand::register_ref("rsi", 8);
  EXPECT_TRUE(donkey::verify_ir(modelled_call("strspn", {rdi, rsi})).has_value());
  for (const donkey::IrFunction& bad :
       {modelled_call("strcmp", {rdi, rsi}), modelled_call("strlen", {rdi, rsi})}) {
    const auto verified = donkey::verify_ir(bad);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.diagnostic().code, "ir.call_signature");
  }
}
