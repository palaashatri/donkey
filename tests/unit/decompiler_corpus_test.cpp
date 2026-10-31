// M8 differential decompiler test. tests/corpus/corpus.c is built at -O0,
// -O2 and -O3 with the host compiler. For every corpus function this test
// lifts it from the built library, runs the IR in the interpreter
// (donkey/ir/eval.h) and calls the compiled function itself with the same
// inputs. A function the decompiler reports Complete that computes anything
// different is a failure. The full outcome matrix is written to
// decompiler-corpus-report.json in the build tree and printed.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/ir/eval.h"
#include "donkey/ir/lift.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

using donkey::IrCallingConvention;

/// Argument kinds: i int32, u uint32, l int64, U uint64, c int8, s int16,
/// b uint8, w uint16, n element count (0..64), P/Q pointers to 64 input
/// ints, B pointer to 256 input bytes, O pointer to 64 output ints, S pointer
/// to a struct corpus_point (read and written). Return: i u l U or v (void).
struct CorpusFunction {
  const char* name;
  char returns;
  const char* arguments;
};

constexpr CorpusFunction kCorpus[] = {
    {"c_add3", 'i', "iii"},
    {"c_add64", 'l', "ll"},
    {"c_sub_mul", 'i', "ii"},
    {"c_mul_add", 'i', "iii"},
    {"c_mix", 'u', "u"},
    {"c_mix64", 'U', "U"},
    {"c_neg", 'i', "i"},
    {"c_not", 'u', "u"},
    {"c_shifts", 'i', "ii"},
    {"c_ushift", 'u', "uu"},
    {"c_rotl5", 'u', "u"},
    {"c_trunc8", 'i', "i"},
    {"c_zext16", 'u', "u"},
    {"c_sext32", 'l', "i"},
    {"c_lea_like", 'i', "ii"},
    {"c_abs", 'i', "i"},
    {"c_max", 'i', "ii"},
    {"c_umin", 'u', "uu"},
    {"c_clamp", 'i', "iii"},
    {"c_sign", 'i', "i"},
    {"c_classify", 'i', "u"},
    {"c_both", 'i', "ii"},
    {"c_popcount", 'u', "u"},
    {"c_fib", 'u', "u"},
    {"c_sum_to", 'i', "i"},
    {"c_collatz_steps", 'u', "u"},
    {"c_sum_array", 'u', "Pn"},
    {"c_dot", 'i', "PQn"},
    {"c_count_eq", 'i', "Pni"},
    {"c_index_of_max", 'i', "Pn"},
    {"c_bytes_sum", 'u', "Bn"},
    {"c_store_pair", 'v', "Oii"},
    {"c_fill", 'v', "Oni"},
    {"c_point_sum", 'l', "S"},
    {"c_point_move", 'v', "Si"},
    {"c_switch_dense", 'i', "i"},
    {"c_switch_sparse", 'i', "i"},
    {"c_many_args", 'l', "lllllllll"},
    {"c_narrow_args", 'i', "csbw"},
};

struct Library {
  const char* level;
  const char* path;
};

const Library kLibraries[] = {
    {"O0", DONKEY_CORPUS_O0_PATH},
    {"O2", DONKEY_CORPUS_O2_PATH},
    {"O3", DONKEY_CORPUS_O3_PATH},
};

constexpr std::uint64_t kP = 0x10000000ULL;
constexpr std::uint64_t kQ = 0x10010000ULL;
constexpr std::uint64_t kB = 0x10020000ULL;
constexpr std::uint64_t kO = 0x10030000ULL;
constexpr std::uint64_t kS = 0x10040000ULL;

struct CorpusPoint {  // must match struct corpus_point
  std::int32_t x;
  std::int32_t y;
  std::int64_t z;
  std::uint8_t tag;
};

std::uint64_t width_mask(char kind) {
  switch (kind) {
    case 'i':
    case 'u':
      return 0xffffffffULL;
    case 'l':
    case 'U':
      return ~0ULL;
    default:
      return 0;
  }
}

class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed) {}
  std::uint64_t next() {
    state_ ^= state_ << 13U;
    state_ ^= state_ >> 7U;
    state_ ^= state_ << 17U;
    return state_;
  }

 private:
  std::uint64_t state_;
};

/// A value of an argument kind, already extended to 64 bits the way a
/// caller passes it in a register.
std::uint64_t scalar(char kind, Rng& rng, int vector) {
  static const std::int64_t kEdges[] = {
      0, 1, -1, 2, 7, -8, 63, 64, 127, -128, 255, 4096, 0x7fffffff, -0x7fffffff - 1, 1000, 100, 10};
  const bool edge = vector < static_cast<int>(std::size(kEdges));
  const std::int64_t e = edge ? kEdges[vector] : 0;
  switch (kind) {
    case 'i':
      return static_cast<std::uint64_t>(
          static_cast<std::int64_t>(static_cast<std::int32_t>(edge ? e : rng.next())));
    case 'u':
      return static_cast<std::uint32_t>(edge ? e : rng.next());
    case 'l':
      return edge ? static_cast<std::uint64_t>(e) : rng.next();
    case 'U':
      return edge ? static_cast<std::uint64_t>(e) : rng.next();
    case 'c':
      return static_cast<std::uint64_t>(
          static_cast<std::int64_t>(static_cast<std::int8_t>(edge ? e : rng.next())));
    case 's':
      return static_cast<std::uint64_t>(
          static_cast<std::int64_t>(static_cast<std::int16_t>(edge ? e : rng.next())));
    case 'b':
      return static_cast<std::uint8_t>(edge ? e : rng.next());
    case 'w':
      return static_cast<std::uint16_t>(edge ? e : rng.next());
    case 'n':
      return rng.next() % 65;
    default:
      return 0;
  }
}

void* open_library(const char* path) {
#if defined(_WIN32)
  return reinterpret_cast<void*>(LoadLibraryA(path));
#else
  return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
}

void* find_symbol(void* library, const char* name) {
#if defined(_WIN32)
  return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(library), name));
#else
  return dlsym(library, name);
#endif
}

// Every corpus argument and return value is of integer class, so on SysV,
// Win64 and AAPCS64 a call through this uniform 64-bit signature passes
// each argument in the register (or stack slot) the real prototype uses.
using Native = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
                                 std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
                                 std::uint64_t);

struct Outcome {
  std::string level;
  std::string function;
  std::string lift;     ///< Complete / Partial / Unsupported / Missing
  std::string verdict;  ///< verified / WRONG / agrees / differs / not-evaluated
  std::string detail;
  int vectors = 0;
};

IrCallingConvention host_convention() {
#if defined(_WIN32)
  return IrCallingConvention::Win64;
#elif defined(__aarch64__) || defined(_M_ARM64)
  return IrCallingConvention::Aapcs64;
#else
  return IrCallingConvention::SysV64;
#endif
}

TEST(DecompilerCorpus, CompleteResultsAgreeWithTheCompiledCode) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  std::vector<Outcome> outcomes;
  for (const Library& library : kLibraries) {
    auto loaded = donkey::load_binary(library.path);
    ASSERT_TRUE(loaded.has_value()) << library.path << ": " << loaded.diagnostic().message;
    donkey::AnalysisOptions analysis_options;
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, analysis_options);
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
    void* handle = open_library(library.path);
    ASSERT_NE(handle, nullptr) << "cannot load " << library.path;

    donkey::IrEvalOptions eval_options;
    eval_options.architecture = loaded.value().image.architecture;
    eval_options.convention = host_convention();

    for (const CorpusFunction& entry : kCorpus) {
      Outcome outcome;
      outcome.level = library.level;
      outcome.function = entry.name;
      const donkey::Function* function = nullptr;
      for (const auto& f : analysis.value().functions) {
        if (f.name == entry.name || f.name == std::string("_") + entry.name) {
          function = &f;
        }
      }
      void* symbol = find_symbol(handle, entry.name);
      if (function == nullptr || symbol == nullptr) {
        outcome.lift = "Missing";
        outcome.verdict = "not-evaluated";
        outcome.detail = function == nullptr ? "not found by analysis" : "not exported";
        outcomes.push_back(outcome);
        continue;
      }
      auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
      if (!lifted) {
        outcome.lift = "Unsupported";
        outcome.verdict = "not-evaluated";
        outcome.detail = lifted.diagnostic().code;
        outcomes.push_back(outcome);
        continue;
      }
      const bool complete = !lifted.value().partial;
      outcome.lift = complete ? "Complete" : "Partial";
      const auto native = reinterpret_cast<Native>(symbol);

      Rng rng(0x5EEDULL ^ std::hash<std::string>{}(entry.name));
      bool mismatch = false;
      std::string eval_error;
      for (int vector = 0; vector < 48 && !mismatch && eval_error.empty(); ++vector) {
        // Inputs shared by both sides.
        std::vector<std::int32_t> p(64);
        std::vector<std::int32_t> q(64);
        std::vector<std::uint8_t> bytes(256);
        for (auto& v : p) {
          v = static_cast<std::int32_t>(rng.next() % 2001) - 1000;
        }
        for (auto& v : q) {
          v = static_cast<std::int32_t>(rng.next() % 2001) - 1000;
        }
        for (auto& v : bytes) {
          v = static_cast<std::uint8_t>(rng.next());
        }
        if (vector % 3 == 0) {
          p[5] = p[9] = 17;  // something for count_eq to find
        }
        std::vector<std::int32_t> out_native(64, -7);
        CorpusPoint point_native{static_cast<std::int32_t>(rng.next() % 1000),
                                 static_cast<std::int32_t>(rng.next() % 1000),
                                 static_cast<std::int64_t>(rng.next() % 100000), 250};

        std::uint64_t native_args[9] = {};
        std::uint64_t ir_args[9] = {};
        const std::size_t count = std::strlen(entry.arguments);
        for (std::size_t i = 0; i < count; ++i) {
          const char kind = entry.arguments[i];
          switch (kind) {
            case 'P':
              native_args[i] = reinterpret_cast<std::uintptr_t>(p.data());
              ir_args[i] = kP;
              break;
            case 'Q':
              native_args[i] = reinterpret_cast<std::uintptr_t>(q.data());
              ir_args[i] = kQ;
              break;
            case 'B':
              native_args[i] = reinterpret_cast<std::uintptr_t>(bytes.data());
              ir_args[i] = kB;
              break;
            case 'O':
              native_args[i] = reinterpret_cast<std::uintptr_t>(out_native.data());
              ir_args[i] = kO;
              break;
            case 'S':
              native_args[i] = reinterpret_cast<std::uintptr_t>(&point_native);
              ir_args[i] = kS;
              break;
            default:
              native_args[i] = ir_args[i] = scalar(kind, rng, vector);
          }
        }

        donkey::IrEvalMemory memory(loaded.value().image, loaded.value().data);
        auto as_bytes = [](const void* data, std::size_t size) {
          const auto* b = static_cast<const std::uint8_t*>(data);
          return std::vector<std::uint8_t>(b, b + size);
        };
        memory.add_region(kP, as_bytes(p.data(), p.size() * 4));
        memory.add_region(kQ, as_bytes(q.data(), q.size() * 4));
        memory.add_region(kB, as_bytes(bytes.data(), bytes.size()));
        memory.add_region(kO, as_bytes(out_native.data(), out_native.size() * 4));
        memory.add_region(kS, as_bytes(&point_native, sizeof(point_native)));

        auto ir =
            donkey::evaluate_ir(lifted.value(), std::span(ir_args, count), memory, eval_options);
        const std::uint64_t got_native =
            native(native_args[0], native_args[1], native_args[2], native_args[3], native_args[4],
                   native_args[5], native_args[6], native_args[7], native_args[8]);
        if (!ir) {
          eval_error = ir.diagnostic().code + ": " + ir.diagnostic().message;
          break;
        }
        ++outcome.vectors;
        const std::uint64_t m = width_mask(entry.returns);
        if ((ir.value().return_value & m) != (got_native & m)) {
          mismatch = true;
          char text[160];
          std::snprintf(text, sizeof(text), "vector %d: IR returned 0x%llx, compiled code 0x%llx",
                        vector, static_cast<unsigned long long>(ir.value().return_value & m),
                        static_cast<unsigned long long>(got_native & m));
          outcome.detail = text;
        }
        // Memory written through pointer arguments must match too.
        if (std::strchr(entry.arguments, 'O') != nullptr &&
            *memory.region(kO) != as_bytes(out_native.data(), out_native.size() * 4)) {
          mismatch = true;
          outcome.detail = "vector " + std::to_string(vector) + ": output buffer differs";
        }
        if (std::strchr(entry.arguments, 'S') != nullptr &&
            *memory.region(kS) != as_bytes(&point_native, sizeof(point_native))) {
          mismatch = true;
          outcome.detail = "vector " + std::to_string(vector) + ": struct contents differ";
        }
      }
      if (!eval_error.empty()) {
        outcome.verdict = "not-evaluated";
        outcome.detail = eval_error;
      } else if (mismatch) {
        outcome.verdict = complete ? "WRONG" : "differs";
      } else {
        outcome.verdict = complete ? "verified" : "agrees";
      }
      outcomes.push_back(outcome);
    }
  }

  // Report: matrix by optimisation level.
  std::map<std::string, std::map<std::string, int>> totals;
  std::string json = "{\n  \"schema\": \"donkey.decompiler_corpus.v1\",\n";
  json += "  \"compiler\": \"" DONKEY_CORPUS_COMPILER "\",\n";
  json += "  \"outcomes\": [";
  bool first = true;
  for (const Outcome& o : outcomes) {
    ++totals[o.level][o.lift + "/" + o.verdict];
    std::string detail;
    for (char ch : o.detail) {
      if (ch == '"' || ch == '\\') {
        detail.push_back('\\');
      }
      detail.push_back(ch);
    }
    json += std::string(first ? "\n" : ",\n") + "    {\"level\": \"" + o.level +
            "\", \"function\": \"" + o.function + "\", \"lift\": \"" + o.lift +
            "\", \"verdict\": \"" + o.verdict + "\", \"vectors\": " + std::to_string(o.vectors) +
            ", \"detail\": \"" + detail + "\"}";
    first = false;
  }
  json += "\n  ]\n}\n";
  std::ofstream(DONKEY_CORPUS_REPORT, std::ios::binary | std::ios::trunc) << json;
  for (const auto& [level, counts] : totals) {
    std::printf("[corpus %s]", level.c_str());
    for (const auto& [kind, n] : counts) {
      std::printf(" %s=%d", kind.c_str(), n);
    }
    std::printf("\n");
  }
  for (const Outcome& o : outcomes) {
    if (o.verdict != "verified") {
      std::printf("  %s %-18s %-11s %-13s %s\n", o.level.c_str(), o.function.c_str(),
                  o.lift.c_str(), o.verdict.c_str(), o.detail.c_str());
    }
  }

  for (const Outcome& o : outcomes) {
    EXPECT_NE(o.verdict, "WRONG") << o.level << " " << o.function
                                  << " is reported Complete but computes something else: "
                                  << o.detail;
  }
}

// A17: the dense switch compiled without optimisation dispatches through a
// jump table. The analysis recovers all eight targets from the bounds check
// and the table bytes, and the decompiler shows a switch, not a tail call.
TEST(DecompilerCorpus, JumpTableIsRecoveredWithEvidence) {
  auto loaded = donkey::load_binary(DONKEY_CORPUS_O0_PATH);
  ASSERT_TRUE(loaded.has_value());
  if (loaded.value().image.architecture != donkey::Architecture::X86_64) {
    GTEST_SKIP() << "jump-table recovery is implemented for x86 only";
  }
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = nullptr;
  for (const auto& f : analysis.value().functions) {
    if (f.name == "c_switch_dense" || f.name == "_c_switch_dense") {
      function = &f;
    }
  }
  ASSERT_NE(function, nullptr);
  const donkey::JumpTable* table = nullptr;
  for (const auto& candidate : analysis.value().cfg.jump_tables) {
    if (candidate.jump_address >= function->address &&
        candidate.jump_address < function->end_address) {
      table = &candidate;
    }
  }
  ASSERT_NE(table, nullptr) << "no jump table recovered in c_switch_dense";
  EXPECT_EQ(table->targets.size(), 8U);
  for (const std::uint64_t target : table->targets) {
    EXPECT_GE(target, function->address);
    EXPECT_LT(target, function->end_address);
  }
  EXPECT_FALSE(function->estimated) << "a recovered table leaves no unknown successor";
  auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
  ASSERT_TRUE(lifted.has_value());
  EXPECT_FALSE(lifted.value().partial);
  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value());
  EXPECT_NE(text.value().find("switch ("), std::string::npos) << text.value();
}

}  // namespace
