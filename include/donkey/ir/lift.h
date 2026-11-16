#pragma once

#include <cstdint>
#include <memory>

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
