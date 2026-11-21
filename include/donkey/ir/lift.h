#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/result.h"
#include "donkey/ir/ir.h"

namespace donkey {

/// The summaries of the direct callees of one image (G21-T2): each callee's System V signature,
/// the registers it may change, and how many levels of calls lie below it. Summaries are computed
/// on first use and kept; a callee that cannot be resolved is remembered as such. The contents are
/// private; see lift.cpp.
class CallSummaryCache {
 public:
  CallSummaryCache();
  ~CallSummaryCache();
  CallSummaryCache(const CallSummaryCache&) = delete;
  CallSummaryCache& operator=(const CallSummaryCache&) = delete;

  /// The contents, defined in lift.cpp.
  struct Impl;

 private:
  friend class CallSummaryAccess;
  std::unique_ptr<Impl> impl_;
};

/// A callee's prototype from a type library (G22-T4), for a call through an import stub. Only
/// integer and pointer parameters and results are described; anything else has no prototype here.
struct CallPrototype {
  /// The width in bytes (1 to 8) of each fixed parameter, in order.
  std::vector<std::uint8_t> parameter_widths;
  /// The width of the result; 0 for void.
  std::uint8_t return_width = 0;
  /// Variadic: only the fixed parameters are passed as arguments.
  bool variadic = false;
  /// The library that declared it (`musl-libc 1.2.4`), printed with the call.
  std::string source;
};

struct LiftOptions {
  std::size_t max_statements = 200'000;
  std::size_t max_blocks = 20'000;
  /// Run run_ir_passes on the lifted function (the default). Tests set this to
  /// false to see the lifter's output and run the passes themselves.
  bool run_passes = true;
  /// Resolve a direct call to a function of the same image: its inferred integer signature gives
  /// the arguments and the result (G21). A callee's own calls are resolved the same way, bottom-up
  /// (G21-T2), up to the depth the interpreter runs.
  bool resolve_calls = true;
  /// The summaries of the callees, shared by the lifts of one image (G21-T2). One cache serves the
  /// lifts of one image and one analysis with the same max_statements and max_blocks, since a
  /// summary depends on them. The cache is not thread-safe: use it from one thread. Null: the lift
  /// makes its own cache for the duration of the call.
  std::shared_ptr<CallSummaryCache> call_summaries;
  /// Library prototypes by call target (an import stub's address), G22-T4. A direct call to one of
  /// them, on x86-64 System V, carries the prototype's arguments and result; it stays Partial.
  /// Shared, not copied, by the copies of these options the lift and its call summaries make.
  std::shared_ptr<const std::map<std::uint64_t, CallPrototype>> call_prototypes;
};

/// Lift one function's basic blocks into IR. The lifters model a documented
/// x86-64 and AArch64 subset; every other instruction or architecture becomes
/// an Unsupported statement/error and marks the function partial. They never
/// execute code and never invent behaviour they did not decode.
[[nodiscard]] Result<IrFunction> lift_function(const BinaryImage& image,
                                               const AnalysisResult& analysis,
                                               const Function& function,
                                               const LiftOptions& options = {});

}  // namespace donkey
