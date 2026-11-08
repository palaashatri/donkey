# Scale benchmark (G16)

Status: **first real-binary series recorded** (G16-T1, partly). Two inputs are measured: generated
programs and one real large binary (the LLVM 18 shared library). There is still one real binary, no
UI frame-time measurement, and no incremental re-analysis (G16-T2).

## What is measured

`tools/bench/scale_benchmark.py` measures `donkey-cli analyze` on each input and records the wall-clock
time, the peak resident memory of the analyser process itself (`wait4` on its pid, so no compiler and
no other child is included), the size and SHA-256 of the input, and the status and counts the analysis
reported. It has two modes:

- **Generated programs** (the default): C programs of 2,000 to 80,000 functions (fixed seed, so the
  source is the same on every run), compiled with `gcc -O2`, with an instruction cap of 4,000,000.
- **Real binaries** (`--binary PATH`, repeatable): existing files, measured as they are. They are not
  built, changed or downloaded by the script.

```bash
cmake --preset headless-linux -DCMAKE_BUILD_TYPE=Release
cmake --build --preset headless-linux --parallel --target donkey-cli

# Generated programs
python3 tools/bench/scale_benchmark.py --cli build/headless-linux/apps/donkey-cli/donkey-cli \
    --work bench-work --sizes 2000 10000 20000 40000 80000 --json bench-results.json

# A real binary, at one instruction budget
python3 tools/bench/scale_benchmark.py --cli build/headless-linux/apps/donkey-cli/donkey-cli \
    --work bench-work --binary /usr/lib/llvm-18/lib/libLLVM.so.1 --max-instructions 1000000 \
    --json llvm-1000000.json
```

The manual workflow `.github/workflows/benchmark.yml` runs both: the generated programs (`scale`) and
the real binary at 1,000,000 and 10,000,000 instructions (`real-binary`). The real-binary job installs
the input from the Ubuntu archive at one exact package version, `libllvm18=1:18.1.3-1ubuntu1`, which
apt verifies by signature, and it uploads the file's SHA-256 with the results.

The job ran on the hosted `ubuntu-24.04` runner in run 42467464472 (branch
`agent/binary/G15-T2-link-imports`, commit `c39a421`): the install, the Release build and both
measurements succeeded, and the `scale-benchmark` and `real-binary-benchmark` artifacts were uploaded.
The numbers in this document are from the local machine above, not from that runner.

## Machine of the recorded runs

| | |
|---|---|
| Platform | Ubuntu 24.04.5 LTS, Linux 6.18.44 x86-64 (`Linux-6.18.44-fc-v310-x86_64-with-glibc2.39`) |
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz |
| Logical CPUs | 4 |
| Memory | 16,086 MB |
| Compiler (generated programs) | gcc 13.3.0, `-O2` |
| Builds measured | `headless-linux` Release (`-DCMAKE_BUILD_TYPE=Release`) and Debug |

A virtual machine with a shared CPU, not a dedicated benchmark host. One run per size and budget.
Memory is reported in MB, meaning MiB (KiB divided by 1024).

## Real binary: `libLLVM.so.1`

| | |
|---|---|
| File | `/usr/lib/llvm-18/lib/libLLVM.so.1`, 123,215,144 bytes |
| SHA-256 | `5c3a63957e28c15cdf1503892074f032d29b72e36a9824a77dfa87e48a0dafb0` |
| Package | `libllvm18 1:18.1.3-1ubuntu1` (Apache-2.0 with LLVM exceptions) |

| Instruction budget | Status | Instructions decoded | Functions | Blocks | Analysis time (s) | Peak RSS (MB) |
|---:|---|---:|---:|---:|---:|---:|
| 1,000,000 | Partial | 1,000,000 | 42,501 | 180,579 | 6.97 | 1,002.7 |
| 10,000,000 | Partial | 10,000,000 | 66,254 | 200,000 | 31.14 | 9,400.9 |
| 40,000,000 | Partial | 14,046,537 | 76,489 | 200,000 | 37.69 | 12,250.3 |

Every run is **Partial**, and the diagnostics say why:

- **1,000,000:** the instruction budget was reached (`analysis.instruction_limit`). The control-flow
  traversal stopped in 5,873 functions, reported as one diagnostic with that count, and 782
  undecodable bytes in `.text` were skipped (`analysis.undecodable_bytes`).
- **10,000,000:** the instruction budget was reached during decoding, and the block bound was reached
  (`analysis.block_limit`, a resource limit). 200,000 blocks are reported, and 1,282 undecodable bytes
  in `.text` were skipped.
- **40,000,000:** decoding stopped at 14,046,537 instructions, below the budget, because the block
  bound was reached (`analysis.block_limit`). The bound, not the budget, is what stopped it.

So no run covers the whole library. The analysis reports that instead of presenting a truncated result
as complete, which is the behaviour the design requires.

## Generated programs (`gcc -O2`)

Functions in source, binary bytes, instructions, blocks, status, analysis time and peak RSS, for the
Release build (`headless-linux`, Release). The 80,000-function row was measured again after the block
bound was fixed (see Corrections); the other rows are complete analyses, below the bound, so the fix does
not change them.

| Functions in source | Binary bytes | Instructions | Blocks | Status | Analysis time (s) | Peak RSS (MB) |
|---:|---:|---:|---:|---|---:|---:|
| 2,000 | 230,544 | 28876 | 5718 | Complete | 0.07 | 29.6 |
| 10,000 | 1,072,656 | 135490 | 29396 | Complete | 0.32 | 133.3 |
| 20,000 | 2,124,032 | 266100 | 59303 | Complete | 0.81 | 256.1 |
| 40,000 | 4,206,304 | 519569 | 119909 | Complete | 3.29 | 412.7 |
| 80,000 | 8,284,832 | 1002254 | 200000 | Partial | 14.75 | 787.8 |

The 80,000-function run is **Partial**, not a measurement of the whole program: the control-flow graph
reached its block bound (200,000 blocks) and stopped, with the diagnostic `analysis.block_limit`.

## Debug build (`headless-linux`)

The same generated inputs with the Debug build, for comparison. All runs are complete.

| Functions in source | Binary bytes | Instructions | Blocks | Status | Analysis time (s) | Peak RSS (MB) |
|---:|---:|---:|---:|---|---:|---:|
| 2,000 | 230,544 | 28876 | 5718 | Complete | 0.29 | 31.2 |
| 10,000 | 1,072,656 | 135490 | 29396 | Complete | 1.99 | 134.6 |
| 20,000 | 2,124,032 | 266100 | 59303 | Complete | 5.55 | 257.9 |
| 40,000 | 4,206,304 | 519569 | 119909 | Complete | 16.58 | 414.1 |

## What the numbers say

- **Memory is about 0.9 to 1.0 KB per decoded instruction on the real binary** (1,002.7 MB for 1,000,000
  instructions; 9,400.9 MB for 10,000,000) and about 800 bytes on the generated programs. The
  per-instruction and per-block data structures are the place to look first. Memory is not yet bounded
  for large inputs: the 40,000,000-budget run needs 12 GB of this 16 GB machine, which is why the CI job
  stops at 10,000,000 instructions.
- **Time grows faster than the program** on the generated programs in complete Release runs: about 4.9
  times from 2,000 to 10,000 functions, 2.5 times from 10,000 to 20,000, and 4.1 times from 20,000 to
  40,000, where the instruction count only doubles. The cause is not identified yet. On the real binary,
  a tenfold budget (1,000,000 to 10,000,000 instructions) costs about 4.5 times the time.
- **The Debug build is about five times slower** at the same sizes, so the Release numbers are the ones
  to quote.
- Incremental re-analysis (G16-T2) would avoid repeating the whole pass after an edit. It does not
  remove the growth above by itself.

## Corrections

Two defects were found by this benchmark and fixed in the same change. The numbers above are from the
fixed code.

- **The block bound was not exact.** The check ran after a block was made, and the traversal went on to
  the next function after the bound was reached, so each later function added a block. The earlier
  80,000-function row reported 214,429 blocks, and the earlier 40,000,000-budget libLLVM run reported
  261,415, against a bound of 200,000. The graph now stops before making a block that would exceed the
  bound, and it does not traverse further functions once the bound is reached. Regression tests:
  `Cfg.TheBlockBoundIsReportedOnce` (asserts the exact bound) and `Cfg.TheBlockBoundHoldsAcrossFunctions`
  (five functions; before the fix the graph held 200,002 blocks).
- **The instruction budget was reported once per function.** A large binary produced one
  `analysis.instruction_limit` diagnostic for each truncated function (5,873 for libLLVM at one million
  instructions). It is now one diagnostic that gives the number of functions and the first address.
  Regression test: `Cfg.TheInstructionLimitIsReportedOnceForAllFunctions`.

## Limits

- **One real binary.** libLLVM is a real, large, redistributable shared library, but the real-world
  corpus the ledger asks for (G16-T1, including Firefox's `libxul`, which is not redistributable and is
  not committed) is not complete. Its results say nothing about other code.
- **The budgets in use all stop the analysis early**, so these numbers measure how far the analysis
  gets before a bound, not the cost of a complete analysis of libLLVM.
- **The generated programs are simple** (small functions, direct calls, a few strings). Real binaries
  have more indirect control flow, more data and debug information, so the cost per instruction differs.
- **One run per size and budget** on a shared virtual machine. Treat the times as indicative.
- **The UI frame-time measurement** of G16-T1 (with the UI scripts) is not part of this benchmark.
