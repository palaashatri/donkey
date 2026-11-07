// M8 differential decompiler test. tests/corpus/corpus.c is built at -O0,
// -O2 and -O3 with the host compiler. For every corpus function this test
// lifts it from the built library, runs the IR in the interpreter
// (donkey/ir/eval.h) and calls the compiled function itself with the same
// inputs. A function the decompiler reports Complete that computes anything
// different is a failure. The full outcome matrix is written to
// decompiler-corpus-report.json in the build tree and printed.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/ir/debug_names.h"
#include "donkey/ir/eval.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"
#include "donkey/ir/prototype.h"
#include "donkey/project/types.h"

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
    {"c_add128_hi", 'U', "UUUU"},
    {"c_sub128_hi", 'U', "UUUU"},
    {"c_add_wraps", 'i', "UU"},
    {"c_mulhi_u64", 'U', "UU"},
    {"c_mulhi_s64", 'U', "UU"},
    {"c_udiv32", 'u', "uu"},
    {"c_urem32", 'u', "uu"},
    {"c_sdiv32", 'i', "ii"},
    {"c_srem32", 'i', "ii"},
    {"c_udiv64", 'U', "UU"},
    {"c_urem64", 'U', "UU"},
    {"c_sdiv64", 'U', "UU"},
    {"c_srem64", 'U', "UU"},
    {"c_div10", 'U', "U"},
    {"c_popcount64", 'u', "U"},
    {"c_ctz64_guarded", 'u', "U"},
    {"c_clz64_guarded", 'u', "U"},
    {"c_bswap32", 'u', "u"},
    {"c_bswap64", 'U', "U"},
    {"c_bit_test", 'i', "Uu"},
};

struct Library {
  const char* level;
  const char* path;
};

const Library kLibraries[] = {
    {"O0", DONKEY_CORPUS_O0_PATH},
    {"O2", DONKEY_CORPUS_O2_PATH},
    {"O3", DONKEY_CORPUS_O3_PATH},
#ifdef DONKEY_CORPUS_O3_V2_PATH
    {"O3-x86-64-v2", DONKEY_CORPUS_O3_V2_PATH},
#endif
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
  // Windows on Arm uses AAPCS64 for integer arguments, like every other
  // AArch64 platform; only Windows x64 has its own convention.
#if defined(__aarch64__) || defined(_M_ARM64)
  return IrCallingConvention::Aapcs64;
#elif defined(_WIN32)
  return IrCallingConvention::Win64;
#else
  return IrCallingConvention::SysV64;
#endif
}

// The number of input vectors per function. The compiled and interpreted runs
// use the same inputs.
constexpr int kVectorCount = 48;

/// The inputs of one vector. The compiled function gets them as real pointers
/// and the IR gets the addresses of the mapped regions (kP, kQ, ...).
struct VectorInputs {
  std::vector<std::int32_t> p = std::vector<std::int32_t>(64);
  std::vector<std::int32_t> q = std::vector<std::int32_t>(64);
  std::vector<std::uint8_t> bytes = std::vector<std::uint8_t>(256);
  std::vector<std::int32_t> out = std::vector<std::int32_t>(64, -7);
  CorpusPoint point{};
  std::size_t count = 0;
  std::uint64_t native_args[9] = {};
  std::uint64_t ir_args[9] = {};
};

// Fills `in` for one vector. The random draws happen in a fixed order, so
// vector N of a function always receives the same inputs.
void fill_vector_inputs(VectorInputs& in, const CorpusFunction& entry, Rng& rng, int vector) {
  for (auto& v : in.p) {
    v = static_cast<std::int32_t>(rng.next() % 2001) - 1000;
  }
  for (auto& v : in.q) {
    v = static_cast<std::int32_t>(rng.next() % 2001) - 1000;
  }
  for (auto& v : in.bytes) {
    v = static_cast<std::uint8_t>(rng.next());
  }
  if (vector % 3 == 0) {
    in.p[5] = in.p[9] = 17;  // something for count_eq to find
  }
  in.point = CorpusPoint{static_cast<std::int32_t>(rng.next() % 1000),
                         static_cast<std::int32_t>(rng.next() % 1000),
                         static_cast<std::int64_t>(rng.next() % 100000), 250};
  in.count = std::strlen(entry.arguments);
  for (std::size_t i = 0; i < in.count; ++i) {
    const char kind = entry.arguments[i];
    switch (kind) {
      case 'P':
        in.native_args[i] = reinterpret_cast<std::uintptr_t>(in.p.data());
        in.ir_args[i] = kP;
        break;
      case 'Q':
        in.native_args[i] = reinterpret_cast<std::uintptr_t>(in.q.data());
        in.ir_args[i] = kQ;
        break;
      case 'B':
        in.native_args[i] = reinterpret_cast<std::uintptr_t>(in.bytes.data());
        in.ir_args[i] = kB;
        break;
      case 'O':
        in.native_args[i] = reinterpret_cast<std::uintptr_t>(in.out.data());
        in.ir_args[i] = kO;
        break;
      case 'S':
        in.native_args[i] = reinterpret_cast<std::uintptr_t>(&in.point);
        in.ir_args[i] = kS;
        break;
      default:
        in.native_args[i] = in.ir_args[i] = scalar(kind, rng, vector);
    }
  }
}

std::vector<std::uint8_t> bytes_of(const void* data, std::size_t size) {
  const auto* b = static_cast<const std::uint8_t*>(data);
  return std::vector<std::uint8_t>(b, b + size);
}

/// Mapped memory for one vector: the image, plus copies of the pointer
/// arguments so that the IR's writes can be read back afterwards.
donkey::IrEvalMemory vector_memory(const donkey::BinaryImage& image,
                                   std::span<const std::byte> file, const VectorInputs& in) {
  donkey::IrEvalMemory memory(image, file);
  memory.add_region(kP, bytes_of(in.p.data(), in.p.size() * 4));
  memory.add_region(kQ, bytes_of(in.q.data(), in.q.size() * 4));
  memory.add_region(kB, bytes_of(in.bytes.data(), in.bytes.size()));
  memory.add_region(kO, bytes_of(in.out.data(), in.out.size() * 4));
  memory.add_region(kS, bytes_of(&in.point, sizeof(in.point)));
  return memory;
}

/// The function the analysis names `name`, with or without the Mach-O leading
/// underscore. The last match wins.
const donkey::Function* find_corpus_function(const donkey::AnalysisResult& analysis,
                                             const char* name) {
  const donkey::Function* found = nullptr;
  for (const auto& f : analysis.functions) {
    if (f.name == name || f.name == std::string("_") + name) {
      found = &f;
    }
  }
  return found;
}

/// One version of a function: the lifter's output ("lift") or the function as
/// a pass left it.
struct PassSnapshot {
  std::string pass;
  donkey::IrFunction function;
};

/// Everything a caller can see of one run: whether the IR verifies, the outcome
/// (a return value or an error code), and every mapped region afterwards. Two
/// versions of a function agree when these are equal.
struct Observation {
  bool verified = false;
  bool partial = false;  ///< IrFunction::partial, which decides how the result is reported
  bool evaluated = false;
  std::string error;  ///< error code when not evaluated
  std::uint64_t return_value = 0;
  std::vector<std::vector<std::uint8_t>> regions;  ///< kP, kQ, kB, kO, kS
  bool operator==(const Observation&) const = default;
};

Observation observe(const donkey::IrFunction& function, bool verified, const VectorInputs& in,
                    const donkey::BinaryImage& image, std::span<const std::byte> file,
                    const donkey::IrEvalOptions& options) {
  Observation observation;
  observation.verified = verified;
  observation.partial = function.partial;
  donkey::IrEvalMemory memory = vector_memory(image, file, in);
  auto result = donkey::evaluate_ir(function, std::span(in.ir_args, in.count), memory, options);
  if (result) {
    observation.evaluated = true;
    observation.return_value = result.value().return_value;
  } else {
    observation.error = result.diagnostic().code;
  }
  for (const std::uint64_t base : {kP, kQ, kB, kO, kS}) {
    const auto* bytes = memory.region(base);
    observation.regions.push_back(bytes != nullptr ? *bytes : std::vector<std::uint8_t>{});
  }
  return observation;
}

std::string outcome_text(const Observation& observation) {
  if (!observation.evaluated) {
    return "error " + observation.error;
  }
  char text[40];
  std::snprintf(text, sizeof(text), "returned 0x%llx",
                static_cast<unsigned long long>(observation.return_value));
  return text;
}

std::string describe_difference(const Observation& before, const Observation& after) {
  if (before.verified != after.verified) {
    return "changed whether the IR verifies";
  }
  if (before.partial != after.partial) {
    return "changed whether the function is reported Partial";
  }
  if (before.evaluated != after.evaluated || before.error != after.error ||
      before.return_value != after.return_value) {
    return "changed the outcome from " + outcome_text(before) + " to " + outcome_text(after);
  }
  return "left a mapped region with different contents";
}

/// Compares every version with the first (the lifter's output) on all corpus
/// vectors. Returns "" when they all agree, otherwise a description of the
/// first difference.
std::string first_difference(const std::vector<PassSnapshot>& versions, const CorpusFunction& entry,
                             const donkey::BinaryImage& image, std::span<const std::byte> file,
                             const donkey::IrEvalOptions& options) {
  std::vector<bool> verified;
  for (const PassSnapshot& version : versions) {
    verified.push_back(donkey::verify_ir(version.function).has_value());
  }
  Rng rng(0x5EEDULL ^ std::hash<std::string>{}(entry.name));
  for (int vector = 0; vector < kVectorCount; ++vector) {
    VectorInputs in;
    fill_vector_inputs(in, entry, rng, vector);
    const Observation expected =
        observe(versions.front().function, verified.front(), in, image, file, options);
    for (std::size_t i = 1; i < versions.size(); ++i) {
      const Observation got = observe(versions[i].function, verified[i], in, image, file, options);
      if (got != expected) {
        return "vector " + std::to_string(vector) + ": after the '" + versions[i].pass +
               "' pass the IR " + describe_difference(expected, got);
      }
    }
  }
  return "";
}

/// The pseudocode of a function, or the error code that rendering reported.
std::string render_or_error(const donkey::IrFunction& function) {
  auto text = donkey::format_pseudocode(function);
  return text.has_value() ? text.value() : "error " + text.diagnostic().code;
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
      // Only verified IR is ever shown: IR the verifier rejects is not a
      // decompilation, and must never be counted as one.
      auto verified = donkey::verify_ir(lifted.value());
      if (!verified.has_value()) {
        outcome.lift = "Rejected";
        outcome.verdict = "not-evaluated";
        outcome.detail = verified.diagnostic().code + ": " + verified.diagnostic().message;
        outcomes.push_back(outcome);
        continue;
      }
      const bool complete = !lifted.value().partial;
      outcome.lift = complete ? "Complete" : "Partial";
      const auto native = reinterpret_cast<Native>(symbol);

      Rng rng(0x5EEDULL ^ std::hash<std::string>{}(entry.name));
      bool mismatch = false;
      std::string eval_error;
      for (int vector = 0; vector < kVectorCount && !mismatch && eval_error.empty(); ++vector) {
        VectorInputs in;
        fill_vector_inputs(in, entry, rng, vector);
        donkey::IrEvalMemory memory = vector_memory(loaded.value().image, loaded.value().data, in);

        auto ir = donkey::evaluate_ir(lifted.value(), std::span(in.ir_args, in.count), memory,
                                      eval_options);
        const std::uint64_t got_native =
            native(in.native_args[0], in.native_args[1], in.native_args[2], in.native_args[3],
                   in.native_args[4], in.native_args[5], in.native_args[6], in.native_args[7],
                   in.native_args[8]);
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
            *memory.region(kO) != bytes_of(in.out.data(), in.out.size() * 4)) {
          mismatch = true;
          outcome.detail = "vector " + std::to_string(vector) + ": output buffer differs";
        }
        if (std::strchr(entry.arguments, 'S') != nullptr &&
            *memory.region(kS) != bytes_of(&in.point, sizeof(in.point))) {
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
    EXPECT_NE(o.lift, "Rejected") << o.level << " " << o.function
                                  << ": the lifter produced IR its verifier rejects: " << o.detail;
    EXPECT_NE(o.verdict, "WRONG") << o.level << " " << o.function
                                  << " is reported Complete but computes something else: "
                                  << o.detail;
  }

  // The carry-chain functions are Complete under Clang 18.1 on x86-64 at every
  // level. A fall back to Partial would hide a wrong carry, so it must fail here.
#if defined(__x86_64__) || defined(_M_X64)
  if (std::strstr(DONKEY_CORPUS_COMPILER, "Clang 18") != nullptr) {
    for (const Outcome& o : outcomes) {
      if (o.function != "c_add128_hi" && o.function != "c_sub128_hi" &&
          o.function != "c_add_wraps") {
        continue;
      }
      EXPECT_EQ(o.lift, "Complete") << o.level << " " << o.function;
      EXPECT_EQ(o.verdict, "verified") << o.level << " " << o.function << ": " << o.detail;
      EXPECT_EQ(o.vectors, kVectorCount) << o.level << " " << o.function;
    }
  }
#endif
}

// A17: the dense switch compiled without optimisation dispatches through a
// jump table on x86-64. The analysis recovers all eight targets from the
// bounds check and the table bytes, and the decompiler shows a switch, not a
// tail call.
//
// AArch64 (G03-T3): neither GCC nor Clang gives c_switch_dense a code jump
// table there (-O0 is a compare chain, -O2 a lookup of constants), so the
// recogniser is measured on the jump-table fixture instead: a 16-case switch
// whose cases depend on the second argument, built at -O2.
TEST(DecompilerCorpus, JumpTableIsRecoveredWithEvidence) {
  auto corpus = donkey::load_binary(DONKEY_CORPUS_O0_PATH);
  ASSERT_TRUE(corpus.has_value());
  const donkey::Architecture architecture = corpus.value().image.architecture;
  if (architecture != donkey::Architecture::X86_64 &&
      architecture != donkey::Architecture::AArch64) {
    GTEST_SKIP() << "jump-table recovery is implemented for x86-64 and AArch64 only";
  }
  const bool aarch64 = architecture == donkey::Architecture::AArch64;
  const char* name = aarch64 ? "jt_dispatch16" : "c_switch_dense";
  auto loaded = donkey::load_binary(aarch64 ? DONKEY_JUMP_TABLE_O2_PATH : DONKEY_CORPUS_O0_PATH);
  ASSERT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = nullptr;
  for (const auto& f : analysis.value().functions) {
    if (f.name == name || f.name == std::string("_") + name) {
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
  ASSERT_NE(table, nullptr) << "no jump table recovered in " << name;
  EXPECT_EQ(table->targets.size(), aarch64 ? 16U : 8U);
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

// The jump-table fixture (G03-T3) is measured on its own, so that the corpus
// counts above stay as they are. It must lift Complete on every host with a
// code jump table, and the IR must agree with the compiled code on every
// input vector.
constexpr CorpusFunction kJumpTableFixture[] = {
    {"jt_dispatch16", 'i', "ii"},
};

TEST(DecompilerCorpus, JumpTableFixtureAgreesWithTheCompiledCode) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  auto loaded = donkey::load_binary(DONKEY_JUMP_TABLE_O2_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
  void* handle = open_library(DONKEY_JUMP_TABLE_O2_PATH);
  ASSERT_NE(handle, nullptr) << "cannot load " << DONKEY_JUMP_TABLE_O2_PATH;

  donkey::IrEvalOptions eval_options;
  eval_options.architecture = loaded.value().image.architecture;
  eval_options.convention = host_convention();

  for (const CorpusFunction& entry : kJumpTableFixture) {
    const donkey::Function* function = nullptr;
    for (const auto& f : analysis.value().functions) {
      if (f.name == entry.name || f.name == std::string("_") + entry.name) {
        function = &f;
      }
    }
    void* symbol = find_symbol(handle, entry.name);
    ASSERT_NE(function, nullptr) << entry.name << " not found by analysis";
    ASSERT_NE(symbol, nullptr) << entry.name << " not exported";
    auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
    ASSERT_TRUE(lifted.has_value()) << entry.name << ": " << lifted.diagnostic().code;
    auto verified = donkey::verify_ir(lifted.value());
    ASSERT_TRUE(verified.has_value()) << entry.name << ": " << verified.diagnostic().code << ": "
                                      << verified.diagnostic().message;
    EXPECT_FALSE(lifted.value().partial) << entry.name << " should lift Complete";

    const auto native = reinterpret_cast<Native>(symbol);
    Rng rng(0x5EEDULL ^ std::hash<std::string>{}(entry.name));
    for (int vector = 0; vector < kVectorCount; ++vector) {
      VectorInputs in;
      fill_vector_inputs(in, entry, rng, vector);
      donkey::IrEvalMemory memory = vector_memory(loaded.value().image, loaded.value().data, in);
      auto ir = donkey::evaluate_ir(lifted.value(), std::span(in.ir_args, in.count), memory,
                                    eval_options);
      ASSERT_TRUE(ir.has_value()) << entry.name << ": " << ir.diagnostic().code;
      const std::uint64_t got_native =
          native(in.native_args[0], in.native_args[1], in.native_args[2], in.native_args[3],
                 in.native_args[4], in.native_args[5], in.native_args[6], in.native_args[7],
                 in.native_args[8]);
      const std::uint64_t m = width_mask(entry.returns);
      EXPECT_EQ(ir.value().return_value & m, got_native & m) << entry.name << " vector " << vector;
    }
  }
}

// M8 struct recovery: at -O2 c_point_sum reads every field of
// struct corpus_point through its untouched pointer argument; the inferred
// layout must be exactly the real one (offsets and widths).
TEST(DecompilerCorpus, StructLayoutRecoveredBehindAPointerArgument) {
  auto loaded = donkey::load_binary(DONKEY_CORPUS_O2_PATH);
  ASSERT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = nullptr;
  for (const auto& f : analysis.value().functions) {
    if (f.name == "c_point_sum" || f.name == "_c_point_sum") {
      function = &f;
    }
  }
  ASSERT_NE(function, nullptr);
  auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
  ASSERT_TRUE(lifted.has_value());
  ASSERT_EQ(lifted.value().pointer_structs.size(), 1U);
  const auto& fields = lifted.value().pointer_structs.front().fields;
  const std::vector<std::pair<std::int64_t, std::uint8_t>> real = {{0, 4}, {4, 4}, {8, 8}, {16, 1}};
  ASSERT_EQ(fields.size(), real.size());
  for (std::size_t i = 0; i < real.size(); ++i) {
    EXPECT_EQ(fields[i].offset, real[i].first) << "field " << i;
    EXPECT_EQ(fields[i].width, real[i].second) << "field " << i;
  }
  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value());
  EXPECT_NE(text.value().find("->f_8"), std::string::npos) << text.value();
}

// G04-T0: every pass that runs after lifting must keep the IR's meaning. Each
// corpus function is lifted with passes disabled, then the passes are run and
// the hook records the function after each one. Every version is interpreted
// on all corpus vectors and must give the same observation as the lifter's
// output, Partial functions included. The test also checks that the hook saw
// each pass, and that the pipeline matches what lift_function produces.
// G04-T2 measurement: the total number of pseudocode statement lines across the corpus,
// before and after the statement passes (the state after recover_pointer_structs is "before").
// The statement passes must make it smaller at every level.
TEST(DecompilerCorpus, StatementPassesShortenThePseudocode) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  for (const Library& library : kLibraries) {
    auto loaded = donkey::load_binary(library.path);
    ASSERT_TRUE(loaded.has_value()) << library.path << ": " << loaded.diagnostic().message;
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;

    std::vector<std::size_t> before_lines;
    std::vector<std::size_t> after_lines;
    for (const CorpusFunction& entry : kCorpus) {
      const donkey::Function* function = find_corpus_function(analysis.value(), entry.name);
      ASSERT_NE(function, nullptr) << entry.name;
      donkey::LiftOptions raw_options;
      raw_options.run_passes = false;
      auto raw =
          donkey::lift_function(loaded.value().image, analysis.value(), *function, raw_options);
      ASSERT_TRUE(raw.has_value()) << entry.name;

      donkey::PassOptions pass_options;
      pass_options.architecture = loaded.value().image.architecture;
      pass_options.format = loaded.value().image.format;
      donkey::IrFunction before;
      pass_options.after_pass = [&before](std::string_view pass, const donkey::IrFunction& after) {
        if (pass == "recover_pointer_structs") {
          before = after;
        }
      };
      donkey::IrFunction piped = raw.value();
      donkey::run_ir_passes(piped, pass_options);

      // Statement lines: the lines of the body that hold a C statement. Headers, notes,
      // labels and braces are not counted, so the measure does not depend on them.
      const auto count_lines = [](const donkey::IrFunction& f) -> std::size_t {
        auto text = donkey::format_pseudocode(f);
        if (!text.has_value()) {
          return 0;
        }
        std::size_t count = 0;
        std::size_t start = 0;
        const std::string& body = text.value();
        while (start < body.size()) {
          std::size_t end = body.find('\n', start);
          if (end == std::string::npos) {
            end = body.size();
          }
          const std::string_view line(body.data() + start, end - start);
          const std::size_t first = line.find_first_not_of(' ');
          if (first != std::string_view::npos && line.substr(first, 2) != "//" &&
              line.find(';') != std::string_view::npos) {
            ++count;
          }
          start = end + 1;
        }
        return count;
      };
      const std::size_t lines_before = count_lines(before);
      const std::size_t lines_after = count_lines(piped);
      if (lines_before == 0 || lines_after == 0) {
        continue;  // the function does not render; the other tests report it
      }
      before_lines.push_back(lines_before);
      after_lines.push_back(lines_after);
    }
    ASSERT_FALSE(before_lines.empty()) << library.level;
    // The assertion is on the total over the corpus. A median over 59 functions moves only
    // when half of them change, so it hid a drop of 54 lines at AArch64 O0.
    std::size_t total_before = 0;
    std::size_t total_after = 0;
    for (const std::size_t lines : before_lines) {
      total_before += lines;
    }
    for (const std::size_t lines : after_lines) {
      total_after += lines;
    }
    std::printf(
        "pseudocode statement lines, total over %zu functions at %s: before %zu, after %zu\n",
        before_lines.size(), library.level, total_before, total_after);
    EXPECT_LT(total_after, total_before) << library.level;
  }
}

TEST(DecompilerCorpus, EveryPassPreservesSemantics) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  std::size_t checked = 0;
  for (const Library& library : kLibraries) {
    auto loaded = donkey::load_binary(library.path);
    ASSERT_TRUE(loaded.has_value()) << library.path << ": " << loaded.diagnostic().message;
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;

    donkey::IrEvalOptions eval_options;
    eval_options.architecture = loaded.value().image.architecture;
    eval_options.convention = host_convention();

    for (const CorpusFunction& entry : kCorpus) {
      const donkey::Function* function = find_corpus_function(analysis.value(), entry.name);
      ASSERT_NE(function, nullptr)
          << library.level << " " << entry.name << " was not found by the analysis";

      donkey::LiftOptions raw_options;
      raw_options.run_passes = false;
      auto raw =
          donkey::lift_function(loaded.value().image, analysis.value(), *function, raw_options);
      ASSERT_TRUE(raw.has_value())
          << library.level << " " << entry.name << ": " << raw.diagnostic().code;

      std::vector<PassSnapshot> versions{{"lift", raw.value()}};
      donkey::PassOptions pass_options;
      pass_options.architecture = loaded.value().image.architecture;
      pass_options.format = loaded.value().image.format;
      pass_options.after_pass = [&versions](std::string_view pass,
                                            const donkey::IrFunction& after) {
        versions.push_back({std::string(pass), after});
      };
      donkey::IrFunction piped = raw.value();
      donkey::run_ir_passes(piped, pass_options);

      std::vector<std::string> passes;
      for (const PassSnapshot& version : versions) {
        passes.push_back(version.pass);
      }
      EXPECT_EQ(passes, (std::vector<std::string>{
                            "lift", "infer_signature", "recover_pointer_structs",
                            "propagate_copies", "remove_dead_temporaries",
                            "remove_dead_register_writes", "remove_dead_temporaries"}))
          << library.level << " " << entry.name << ": the hook must see every pass, in order";

      auto production = donkey::lift_function(loaded.value().image, analysis.value(), *function);
      ASSERT_TRUE(production.has_value());
      EXPECT_EQ(render_or_error(piped), render_or_error(production.value()))
          << library.level << " " << entry.name
          << ": the passes checked here must be the ones lift_function runs";

      const std::string difference = first_difference(versions, entry, loaded.value().image,
                                                      loaded.value().data, eval_options);
      EXPECT_EQ(difference, "") << library.level << " " << entry.name << ": " << difference;
      ++checked;
    }
  }
  EXPECT_EQ(checked, std::size(kLibraries) * std::size(kCorpus));
}

// The checker must not be vacuous: a pass that turns the first addition of
// c_add3 into a subtraction has to be reported.
TEST(DecompilerCorpus, EveryPassCheckRejectsAChangedMeaning) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  const CorpusFunction& add3 = kCorpus[0];
  ASSERT_STREQ(add3.name, "c_add3");
  auto loaded = donkey::load_binary(DONKEY_CORPUS_O0_PATH);
  ASSERT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = find_corpus_function(analysis.value(), add3.name);
  ASSERT_NE(function, nullptr);
  donkey::LiftOptions raw_options;
  raw_options.run_passes = false;
  auto raw = donkey::lift_function(loaded.value().image, analysis.value(), *function, raw_options);
  ASSERT_TRUE(raw.has_value());

  donkey::IrFunction broken = raw.value();
  std::size_t changed = 0;
  for (donkey::IrBlock& block : broken.blocks) {
    for (donkey::IrStatement& statement : block.statements) {
      if (statement.op == donkey::IrOp::Add && changed == 0) {
        statement.op = donkey::IrOp::Sub;
        ++changed;
      }
    }
  }
  ASSERT_EQ(changed, 1U) << "c_add3 has no addition to change";

  donkey::IrEvalOptions eval_options;
  eval_options.architecture = loaded.value().image.architecture;
  eval_options.convention = host_convention();
  const std::vector<PassSnapshot> versions{{"lift", raw.value()}, {"broken", broken}};
  const std::string difference =
      first_difference(versions, add3, loaded.value().image, loaded.value().data, eval_options);
  EXPECT_NE(difference, "") << "the checker accepted an addition turned into a subtraction";
}

// A pass that changes only the Partial flag changes how the result is reported,
// even when every execution is identical. Setting the flag and clearing it must
// each be reported.
TEST(DecompilerCorpus, EveryPassCheckRejectsAChangedPartialFlag) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  const CorpusFunction& add3 = kCorpus[0];
  ASSERT_STREQ(add3.name, "c_add3");
  auto loaded = donkey::load_binary(DONKEY_CORPUS_O0_PATH);
  ASSERT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = find_corpus_function(analysis.value(), add3.name);
  ASSERT_NE(function, nullptr);
  donkey::LiftOptions raw_options;
  raw_options.run_passes = false;
  auto raw = donkey::lift_function(loaded.value().image, analysis.value(), *function, raw_options);
  ASSERT_TRUE(raw.has_value());
  ASSERT_FALSE(raw.value().partial) << "c_add3 at O0 must be Complete for this check";

  donkey::IrFunction flagged = raw.value();
  flagged.partial = true;
  donkey::IrEvalOptions eval_options;
  eval_options.architecture = loaded.value().image.architecture;
  eval_options.convention = host_convention();

  const std::vector<PassSnapshot> setting{{"lift", raw.value()}, {"set partial", flagged}};
  const std::vector<PassSnapshot> clearing{{"lift", flagged}, {"clear partial", raw.value()}};
  EXPECT_NE(first_difference(setting, add3, loaded.value().image, loaded.value().data, eval_options)
                .find("reported Partial"),
            std::string::npos)
      << "the checker accepted a pass that set the Partial flag";
  EXPECT_NE(
      first_difference(clearing, add3, loaded.value().image, loaded.value().data, eval_options)
          .find("reported Partial"),
      std::string::npos)
      << "the checker accepted a pass that cleared the Partial flag";
}

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
// G01-T2: scalar floating-point functions from corpus_fp.c. They all have the
// prototype double f(double, double, double, double), so the arguments arrive in
// xmm0 to xmm3 and the result is in xmm0. The IR receives each argument in the XMM
// register its parameter names; the native call uses the double prototype.
constexpr const char* kFloatFunctions[] = {
    "fp_add",
    "fp_sub",
    "fp_mul",
    "fp_div",
    "fp_poly",
    "fp_hypot_sqrt",
    "fp_lt",
    "fp_eq_select",
    "fp_ne_select",
    "fp_max",
    "fp_min",
    "fp_truncate_int",
    "fp_scale_by_int",
    "fp_through_single",
    "fp_single_add",
    "fp_sum_array",
    "fp_dot3",
    "fp_branchy",
    "fp_loop_reduce",
    "fp_mean4",
    "fp_lerp",
    "fp_clamp01",
    "fp_capped_root",
    "fp_int_quotient",
    "fp_compare_chain",
    "fp_single_mix",
};

using NativeDouble = double (*)(double, double, double, double);

std::uint64_t double_bits_of(double value) {
  std::uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof bits);
  return bits;
}

double double_of_bits(std::uint64_t bits) {
  double value = 0.0;
  std::memcpy(&value, &bits, sizeof value);
  return value;
}

// Both NaN is equal whatever the payload; otherwise the bits must match, so the sign of
// a zero or the exact value of a rounded result is checked.
bool same_double_result(std::uint64_t ir_bits, std::uint64_t native_bits) {
  const double ir = double_of_bits(ir_bits);
  const double native = double_of_bits(native_bits);
  if (std::isnan(ir) || std::isnan(native)) {
    return std::isnan(ir) && std::isnan(native);
  }
  return ir_bits == native_bits;
}

double next_double_input(Rng& rng) {
  static const double kSpecial[] = {0.0,
                                    -0.0,
                                    1.0,
                                    2.5,
                                    0.5,
                                    3.0,
                                    1e300,
                                    -1e-300,
                                    4.9e-324,
                                    std::numeric_limits<double>::infinity(),
                                    -std::numeric_limits<double>::infinity(),
                                    std::numeric_limits<double>::quiet_NaN()};
  const std::uint64_t draw = rng.next();
  if (draw % 3 == 0) {
    return kSpecial[(draw >> 8U) % (sizeof kSpecial / sizeof kSpecial[0])];
  }
  // A value in [-64, 64) with a fraction, so comparisons and small integers both occur.
  const double unit = static_cast<double>(rng.next() >> 11U) / 9007199254740992.0;
  return unit * 128.0 - 64.0;
}

TEST(DecompilerCorpus, FloatResultsAgreeWithTheCompiledCode) {
#if !defined(DONKEY_CORPUS_FP_O0_PATH)
  GTEST_SKIP() << "the floating-point corpus was not built";
#else
  auto loaded = donkey::load_binary(DONKEY_CORPUS_FP_O0_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
  void* handle = open_library(DONKEY_CORPUS_FP_O0_PATH);
  ASSERT_NE(handle, nullptr) << "cannot load " << DONKEY_CORPUS_FP_O0_PATH;

  donkey::IrEvalOptions eval_options;
  eval_options.architecture = loaded.value().image.architecture;
  eval_options.convention = host_convention();

  int complete = 0;
  int total = 0;
  std::uint64_t seed = 0x5EEDF10ULL;
  for (const char* name : kFloatFunctions) {
    ++total;
    ++seed;
    const donkey::Function* function = nullptr;
    for (const auto& f : analysis.value().functions) {
      if (f.name == name || f.name == std::string("_") + name) {
        function = &f;
      }
    }
    void* symbol = find_symbol(handle, name);
    ASSERT_NE(function, nullptr) << name << " not found by analysis";
    ASSERT_NE(symbol, nullptr) << name << " not exported";
    auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
    ASSERT_TRUE(lifted.has_value()) << name << ": " << lifted.diagnostic().code;
    auto verified = donkey::verify_ir(lifted.value());
    ASSERT_TRUE(verified.has_value()) << name << ": " << verified.diagnostic().message;
    if (lifted.value().partial) {
      std::printf("float corpus: %s is Partial\n", name);
      for (const std::string& note : lifted.value().notes) {
        std::printf("  note: %s\n", note.c_str());
      }
      continue;  // Partial is reported, not compared: only Complete results are claims.
    }
    ++complete;

    const auto native = reinterpret_cast<NativeDouble>(symbol);
    Rng rng(seed);
    for (int vector = 0; vector < kVectorCount; ++vector) {
      double args[4] = {};
      for (double& arg : args) {
        arg = next_double_input(rng);
      }
      // Each IR parameter reads one floating-point register (xmm0 to xmm3 on x86-64, or
      // v0 to v3 on AArch64, named as d, s or v), so it takes that argument.
      std::vector<std::uint64_t> ir_args;
      for (const donkey::IrParameter& parameter : lifted.value().parameters) {
        const std::string& reg = parameter.abi_register;
        const bool xmm = reg.rfind("xmm", 0) == 0;
        const bool scalar = reg.size() == 2 && (reg[0] == 'd' || reg[0] == 's' || reg[0] == 'v');
        ASSERT_TRUE(xmm || scalar) << name << " reads " << reg;
        const auto index = static_cast<std::size_t>(xmm ? reg[3] - '0' : reg[1] - '0');
        ASSERT_LT(index, 4U);
        ir_args.push_back(double_bits_of(args[index]));
      }
      // The image is mapped so that constants in .rodata (loaded with rip-relative
      // moves) read as they do in the process.
      donkey::IrEvalMemory memory(loaded.value().image, loaded.value().data);
      auto ir = donkey::evaluate_ir(lifted.value(), ir_args, memory, eval_options);
      ASSERT_TRUE(ir.has_value()) << name << ": " << ir.diagnostic().code;
      const double got_native = native(args[0], args[1], args[2], args[3]);
      EXPECT_TRUE(same_double_result(ir.value().return_value, double_bits_of(got_native)))
          << name << " vector " << vector << ": IR " << double_of_bits(ir.value().return_value)
          << ", native " << got_native;
    }
  }
  std::printf("float corpus: %d of %d Complete\n", complete, total);
  EXPECT_GE(total, 20);
  // A scalar SSE result depends on the MXCSR rounding mode, which the caller may set, so the
  // functions that round are Partial (see the lifter's rounding note). Only the ones whose
  // results do not round can be Complete, and every value above is still checked against the
  // compiled code either way. The measured counts at -O0 are 6 of 26 with GCC 13.3 and 5 of 26
  // with Clang 18.1, so the floor is the smaller of the two.
  EXPECT_GE(complete, 5) << complete << " of " << total << " float functions are Complete";
#endif
}
#else
TEST(DecompilerCorpus, FloatResultsAgreeWithTheCompiledCode) {
  GTEST_SKIP() << "the floating-point corpus runs on x86-64 and AArch64 hosts";
}
#endif

// G04-T4: the parameters of a function in a -g binary take their names from the debug
// information. The module fixture's donkey_module_answer(int value) is built at -O0 -g.
TEST(DecompilerCorpus, ParameterNamesComeFromTheDebugInformation) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  auto loaded = donkey::load_binary(DONKEY_TEST_MODULE_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  // The module's debug information. On macOS it is in the .dSYM bundle that the build makes with
  // dsymutil; the image itself has no .debug_info section.
  std::string debug_path = DONKEY_TEST_MODULE_PATH;
#if defined(__APPLE__)
  const std::string module_name = debug_path.substr(debug_path.find_last_of('/') + 1);
  debug_path += ".dSYM/Contents/Resources/DWARF/" + module_name;
#endif
  auto debug_file = donkey::load_binary(debug_path);
  ASSERT_TRUE(debug_file.has_value()) << debug_file.diagnostic().message;
  auto info = donkey::read_debug_info(debug_file.value().image, debug_file.value().data);
  ASSERT_TRUE(info.has_value()) << info.diagnostic().message;
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = nullptr;
  for (const auto& candidate : analysis.value().functions) {
    // Mach-O prefixes every C symbol with an underscore.
    if (candidate.name == "donkey_module_answer" || candidate.name == "_donkey_module_answer") {
      function = &candidate;
    }
  }
  ASSERT_NE(function, nullptr);
  const donkey::DebugFunction* debug = info.value().function_at(function->address);
  ASSERT_NE(debug, nullptr);
  auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
  ASSERT_TRUE(lifted.has_value());

  donkey::IrFunction named = lifted.value();
  auto before = donkey::format_pseudocode(named);
  ASSERT_TRUE(before.has_value());
  EXPECT_NE(before.value().find("(u32 a0)"), std::string::npos) << before.value();

  auto applied = donkey::apply_debug_parameter_names(named, *debug, info.value());
  ASSERT_TRUE(applied.has_value())
      << applied.diagnostic().code << ": " << applied.diagnostic().message;
  auto text = donkey::format_pseudocode(named);
  ASSERT_TRUE(text.has_value());
  // The width spelling (u32) is the decompiler's; the name is the debug information's.
  EXPECT_NE(text.value().find("donkey_module_answer(u32 value)"), std::string::npos)
      << text.value();
  EXPECT_EQ(text.value().find("a0"), std::string::npos) << text.value();

  // A debug function that does not match the code (one parameter too many) is refused,
  // and the function keeps its inferred names.
  donkey::DebugFunction extra = *debug;
  extra.parameters.push_back(donkey::DebugParameter{"extra", debug->parameters.front().type});
  donkey::IrFunction unchanged = lifted.value();
  auto refused = donkey::apply_debug_parameter_names(unchanged, extra, info.value());
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "ir.debug_names_arity");
  auto kept = donkey::format_pseudocode(unchanged);
  ASSERT_TRUE(kept.has_value());
  EXPECT_EQ(kept.value(), before.value());
}

#if defined(DONKEY_TEST_LOCALS_PATH)
// At -O0 the parameters and locals of donkey_locals_sum are stored at rsp offsets the
// frame adjustment moves: the debug information's CFA offsets name them (G04-T4). A function
// whose debug information lists no slots is unchanged.
TEST(DecompilerCorpus, FrameSlotsTakeTheNamesOfTheDebugInformation) {
#if defined(_WIN32) || !defined(__x86_64__)
  // The -O0 frame of donkey_locals_sum is a System V x86-64 frame here (Linux and FreeBSD). The
  // Windows x64 frame, with its arguments in rcx and rdx, and the AArch64 frame have no test yet.
  GTEST_SKIP() << "the -O0 frame layout checked here is a System V x86-64 frame";
#endif
  auto loaded = donkey::load_binary(DONKEY_TEST_LOCALS_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto info = donkey::read_debug_info(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(info.has_value()) << info.diagnostic().message;
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = nullptr;
  for (const auto& candidate : analysis.value().functions) {
    if (candidate.name == "donkey_locals_sum") {
      function = &candidate;
    }
  }
  ASSERT_NE(function, nullptr);
  const donkey::DebugFunction* debug = info.value().function_at(function->address);
  ASSERT_NE(debug, nullptr);
  ASSERT_EQ(debug->stack_slots.size(), 4U);
  auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
  ASSERT_TRUE(lifted.has_value());

  donkey::IrFunction named = lifted.value();
  auto before = donkey::format_pseudocode(named);
  ASSERT_TRUE(before.has_value());
  // GCC stores the locals at rsp - 0x8 .. 0x18; Clang at rsp - 0x4 .. 0x10. Both are frame slots.
  EXPECT_NE(before.value().find("*(u32 *)(rsp - "), std::string::npos) << before.value();

  auto applied = donkey::apply_debug_stack_names(named, *debug, info.value());
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().code;
  EXPECT_TRUE(applied.value());
  auto text = donkey::format_pseudocode(named);
  ASSERT_TRUE(text.has_value());
  // The parameter stores and the loads and stores of the locals use the slot names.
  EXPECT_NE(text.value().find("first = (u32)rdi;"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("second = (u32)rsi;"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("total = (u32)rax;"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("scaled = (u32)rax;"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("*(u32 *)(rsp - "), std::string::npos) << text.value();

  // With no slots in the debug information nothing is named, and the text is unchanged.
  donkey::DebugFunction bare = *debug;
  bare.stack_slots.clear();
  donkey::IrFunction unchanged = lifted.value();
  auto none = donkey::apply_debug_stack_names(unchanged, bare, info.value());
  ASSERT_TRUE(none.has_value());
  EXPECT_FALSE(none.value());
  auto kept = donkey::format_pseudocode(unchanged);
  ASSERT_TRUE(kept.has_value());
  EXPECT_EQ(kept.value(), before.value());
}
#endif
// G05-T3: a prototype applied to a recovered function names the structure and its
// members, and types the parameter. Printing shows p->z, and the function still
// computes the same value, because a prototype changes names and types only.

donkey::TypeDefinition scalar_type(std::uint64_t id, const char* name, std::uint64_t size,
                                   bool is_signed) {
  donkey::TypeDefinition definition;
  definition.id = donkey::TypeId(id);
  definition.kind = donkey::TypeKind::Integer;
  definition.name = name;
  definition.size = size;
  definition.is_signed = is_signed;
  return definition;
}

// struct corpus_point (tests/corpus/corpus.c) as the type store describes it, and the
// IR prototype made from it. The CLI and UI that would make this for a user are G05-T4.
donkey::IrPrototype corpus_point_prototype() {
  donkey::TypeTable types;
  types.put(scalar_type(1, "int", 4, true));
  types.put(scalar_type(2, "long long", 8, true));
  types.put(scalar_type(3, "unsigned char", 1, false));
  donkey::TypeDefinition point;
  point.id = donkey::TypeId(4);
  point.kind = donkey::TypeKind::Struct;
  point.name = "corpus_point";
  point.size = 24;
  point.fields = {
      donkey::TypeField{"x", 0, donkey::TypeId(1)},
      donkey::TypeField{"y", 4, donkey::TypeId(1)},
      donkey::TypeField{"z", 8, donkey::TypeId(2)},
      donkey::TypeField{"tag", 16, donkey::TypeId(3)},
  };
  types.put(point);
  EXPECT_TRUE(types.validate().has_value());

  donkey::IrTypeLayout layout;
  layout.name = "corpus_point";
  for (const donkey::TypeField& field : point.fields) {
    layout.fields.push_back(donkey::IrTypeField{
        field.name, field.offset, static_cast<std::uint8_t>(types.size_of(field.type).value())});
  }
  donkey::IrPrototype prototype;
  prototype.name = "c_point_sum";
  prototype.return_width = 8;
  prototype.parameters.push_back(donkey::IrPrototypeParameter{"p", 8, false, layout});
  return prototype;
}

void store_little_endian(std::vector<std::uint8_t>& bytes, std::size_t offset, std::size_t size,
                         std::uint64_t value) {
  for (std::size_t i = 0; i < size; ++i) {
    bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
  }
}

TEST(DecompilerCorpus, AppliedPrototypeNamesStructFields) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  auto loaded = donkey::load_binary(DONKEY_CORPUS_O2_PATH);
  ASSERT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = find_corpus_function(analysis.value(), "c_point_sum");
  ASSERT_NE(function, nullptr);
  auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
  ASSERT_TRUE(lifted.has_value());
  const donkey::IrFunction& ir = lifted.value();

  // struct corpus_point { int x; int y; long long z; unsigned char tag; } at 0, 4, 8, 16:
  // x = 3, y = 5, z = 100, tag = 7.
  std::vector<std::uint8_t> point(24, 0);
  store_little_endian(point, 0, 4, 3);
  store_little_endian(point, 4, 4, 5);
  store_little_endian(point, 8, 8, 100);
  store_little_endian(point, 16, 1, 7);
  constexpr std::uint64_t kPoint = 0x10000;
  const std::array<std::uint64_t, 1> arguments{kPoint};
  donkey::IrEvalOptions eval_options;
  eval_options.architecture = loaded.value().image.architecture;
  eval_options.convention = host_convention();
  const auto evaluate = [&](const donkey::IrFunction& candidate) {
    donkey::IrEvalMemory memory;
    EXPECT_TRUE(memory.add_region(kPoint, point, false));
    return donkey::evaluate_ir(candidate, arguments, memory, eval_options);
  };
  auto before = evaluate(ir);
  ASSERT_TRUE(before.has_value()) << before.diagnostic().code;
  EXPECT_EQ(before.value().return_value, 120U);  // 3 + 2 * 5 + 100 + 7

  donkey::IrFunction applied_function = ir;
  auto applied = donkey::apply_prototype(applied_function, corpus_point_prototype());
  ASSERT_TRUE(applied.has_value())
      << applied.diagnostic().code << ": " << applied.diagnostic().message;
  ASSERT_TRUE(donkey::verify_ir(applied_function).has_value());
  auto text = donkey::format_pseudocode(applied_function);
  ASSERT_TRUE(text.has_value());
  EXPECT_NE(text.value().find("(struct corpus_point *p)"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("p->z"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("p->tag"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("f_8"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("a0_fields"), std::string::npos) << text.value();

  // A prototype changes no statement, so the function computes the same value.
  auto after = evaluate(applied_function);
  ASSERT_TRUE(after.has_value()) << after.diagnostic().code;
  EXPECT_EQ(after.value().return_value, before.value().return_value);
}

TEST(DecompilerCorpus, AppliedPrototypeThatContradictsTheFunctionIsRefused) {
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
  GTEST_SKIP() << "the corpus oracle runs on x86-64 and AArch64 hosts";
#endif
  auto loaded = donkey::load_binary(DONKEY_CORPUS_O2_PATH);
  ASSERT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, {});
  ASSERT_TRUE(analysis.has_value());
  const donkey::Function* function = find_corpus_function(analysis.value(), "c_point_sum");
  ASSERT_NE(function, nullptr);
  auto lifted = donkey::lift_function(loaded.value().image, analysis.value(), *function);
  ASSERT_TRUE(lifted.has_value());
  const donkey::IrFunction& ir = lifted.value();
  auto before = donkey::format_pseudocode(ir);
  ASSERT_TRUE(before.has_value());

  // Each refusal names its code, and the function is left exactly as it was.
  const auto refused = [&](donkey::IrPrototype prototype, const char* code) {
    donkey::IrFunction copy = ir;
    auto result = donkey::apply_prototype(copy, prototype);
    ASSERT_FALSE(result.has_value()) << code;
    EXPECT_EQ(result.diagnostic().code, code);
    auto after = donkey::format_pseudocode(copy);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after.value(), before.value());
  };
  const donkey::IrPrototype good = corpus_point_prototype();

  // z is read as 8 bytes at offset 8; a 4-byte member there is refused.
  donkey::IrPrototype narrow = good;
  narrow.parameters[0].pointee->fields[2].width = 4;
  refused(narrow, "ir.prototype_field");

  // Offset 8 has no member at all.
  donkey::IrPrototype missing = good;
  missing.parameters[0].pointee->fields.erase(missing.parameters[0].pointee->fields.begin() + 2);
  refused(missing, "ir.prototype_field");

  // The argument is 8 bytes; a 4-byte parameter does not match it.
  donkey::IrPrototype four = good;
  four.parameters[0].width = 4;
  refused(four, "ir.prototype_parameter");

  // The function takes one argument.
  donkey::IrPrototype none = good;
  none.parameters.clear();
  refused(none, "ir.prototype_arity");

  // The function returns 8 bytes.
  donkey::IrPrototype narrow_return = good;
  narrow_return.return_width = 4;
  refused(narrow_return, "ir.prototype_return");

  // A parameter name must be a C identifier.
  donkey::IrPrototype bad_name = good;
  bad_name.parameters[0].name = "p q";
  refused(bad_name, "ir.prototype_name");
}

}  // namespace
