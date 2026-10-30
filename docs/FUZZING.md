# Fuzzing Guide — Donkey

Donkey uses LLVM `libFuzzer` combined with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) to fuzz untrusted input parsers, the CFG/analysis engine, semantic instruction lifters, the IR verifier, and pseudocode emitters.

## Targets

| Target | Source | Coverage Scope | Corpus Path |
|---|---|---|---|
| `fuzz_binary` | `fuzz/fuzz_binary.cpp` | `parse_binary` → `analyze` → `lift_function` → `verify_ir` → `format_pseudocode` | `tests/fuzz/corpus/binary` |
| `fuzz_ir` | `fuzz/fuzz_ir.cpp` | Randomized `IrFunction` mutation, statement generation, verifier agreement, pseudocode rendering | `tests/fuzz/corpus/ir` |

## Building Fuzzers

Fuzz targets require an LLVM Clang toolchain with `libFuzzer` runtime (on macOS, Homebrew LLVM e.g. `/opt/homebrew/opt/llvm` is used because AppleClang omits the libFuzzer runtime):

```bash
# Configure with fuzz preset
cmake --preset fuzz-macos

# Build fuzz targets
cmake --build build/fuzz-macos --parallel
```

On Linux:
```bash
cmake --preset fuzz-linux
cmake --build build/fuzz-linux --parallel
```

## Running Fuzzers

Run fuzzers pointing to the persistent corpus directories:

```bash
# Fuzz binary ingestion pipeline (60 seconds or custom duration)
./build/fuzz-macos/fuzz/fuzz_binary tests/fuzz/corpus/binary -max_total_time=60 -rss_limit_mb=1024

# Fuzz IR verifier and structurer
./build/fuzz-macos/fuzz/fuzz_ir tests/fuzz/corpus/ir -max_total_time=60 -rss_limit_mb=1024
```

## Crash Reproduction and Minimization

When libFuzzer discovers a crash or invariant violation, it produces a file named `crash-<sha1>` (or `leak-<sha1>`, `timeout-<sha1>`).

### 1. Reproducing the Crash

Run the fuzzer executable directly with the crash artifact:

```bash
ASAN_OPTIONS=symbolize=1 ./build/fuzz-macos/fuzz/fuzz_binary crash-<sha1>
```

### 2. Automated Test Case Minimization

Use libFuzzer's `-minimize_crash=1` flag to find the smallest input reproducing the failure:

```bash
./build/fuzz-macos/fuzz/fuzz_binary -minimize_crash=1 -max_total_time=60 crash-<sha1> -exact_artifact_path=minimized-<sha1>
```

### 3. Adding to Regression Test Suite

Once minimized:
1. Verify the root cause in the parser or IR verifier.
2. Add a deterministic test case in `tests/unit/binary_test.cpp` or `tests/unit/ir_test.cpp`.
3. Add the minimized input to the persistent corpus `tests/fuzz/corpus/binary` or `tests/fuzz/corpus/ir`.
4. Fix the defect and assert all unit tests and fuzzing runs pass cleanly.
