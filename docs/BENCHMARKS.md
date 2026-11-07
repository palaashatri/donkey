# Scale benchmark (G16)

Status: **first step** (G16-T1). A reproducible script and two measured series on one machine. There
is no real-world corpus yet, and no incremental re-analysis (G16-T2).

## What is measured

`tools/bench/scale_benchmark.py` generates C programs of 2,000 to 80,000 functions (fixed seed, so
the source is the same on every run), compiles them with `gcc -O2`, and runs `donkey-cli analyze`
on each, with an instruction cap of 4,000,000. For each binary it records the wall-clock time and
the peak resident memory of the analyser process itself (`wait4` on its pid, so the compiler's
memory is not included), and the status the analysis reported. The analysis is the default one:
instructions, functions, control-flow blocks, xrefs and strings.

```bash
cmake --preset release-headless
cmake --build --preset release-headless --parallel --target donkey-cli
python3 tools/bench/scale_benchmark.py --cli build/release-headless/apps/donkey-cli/donkey-cli \
    --work bench-work --sizes 2000 10000 20000 40000 80000 --json bench-results.json
```

The manual workflow `.github/workflows/benchmark.yml` runs the same measurement on
`ubuntu-24.04` and uploads `bench-results.json`. Its inputs are generated, not downloaded: the plan's
pinned download of a large real binary (an LLVM `clang` release) is not in it yet.

## Machine of the recorded runs

| | |
|---|---|
| Platform | Linux-6.18.44-fc-v300-x86_64-with-glibc2.39 |
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz |
| Logical CPUs | 4 |
| Memory | 16,086 MB |
| Compiler | gcc 13.3.0 (Ubuntu 24.04 package), `-O2` for the inputs |
| Builds measured | `release-headless` (Release) and `headless-linux` (Debug) |

A virtual machine with a shared CPU, not a dedicated benchmark host. One run per size.

## Results: Release (`release-headless`)

| Functions in source | Binary bytes | Instructions | Blocks | Status | Analysis time (s) | Peak RSS (MB) |
|---:|---:|---:|---:|---|---:|---:|
| 2,000 | 230,544 | 28876 | 5718 | Complete | 0.07 | 29.6 |
| 10,000 | 1,072,656 | 135490 | 29396 | Complete | 0.32 | 133.3 |
| 20,000 | 2,124,032 | 266100 | 59303 | Complete | 0.81 | 256.1 |
| 40,000 | 4,206,304 | 519569 | 119909 | Complete | 3.29 | 412.7 |
| 80,000 | 8,284,832 | 1002254 | 214429 | Partial | 13.56 | 786.7 |

The 80,000-function run is **Partial**, not a measurement of the whole program: the control-flow
graph reached its block bound (200,000 blocks) and stopped. The analysis now says so with the
diagnostic `analysis.block_limit`; before this change the partial result carried no reason. Its time
is the time of the partial analysis and is not part of the scaling comparison below.

## Results: Debug (`headless-linux`)

The same inputs with the Debug build, for comparison. All runs are complete.

| Functions in source | Binary bytes | Instructions | Blocks | Status | Analysis time (s) | Peak RSS (MB) |
|---:|---:|---:|---:|---|---:|---:|
| 2,000 | 230,544 | 28876 | 5718 | Complete | 0.29 | 31.2 |
| 10,000 | 1,072,656 | 135490 | 29396 | Complete | 1.99 | 134.6 |
| 20,000 | 2,124,032 | 266100 | 59303 | Complete | 5.55 | 257.9 |
| 40,000 | 4,206,304 | 519569 | 119909 | Complete | 16.58 | 414.1 |

## What the numbers say

- **Memory is about 800 bytes per decoded instruction** in both builds (412.7 MB for 519,569
  instructions at 40,000 functions). The per-instruction and per-block data structures are the place to
  look first; memory is not yet bounded for large inputs.
- **Time grows faster than the program** in the complete Release runs. Time per doubling of the
  input: about 4.9 times from 2,000 to 10,000 functions, 2.5 times from 10,000 to 20,000, and 4.1 times
  from 20,000 to 40,000, where the instruction count only doubles. The growth is therefore not
  steady, and the step from 20,000 to 40,000 is the one to profile. The cause is not identified yet.
- **The Debug build is about five times slower** at the same sizes, so the Release numbers are the ones
  to quote.
- Incremental re-analysis (G16-T2) would avoid repeating the whole pass after an edit. It does not
  remove the growth above by itself.
- An earlier measurement in this session reported 844 MB for the 40,000-function run. That figure
  was wrong: it was the peak of the C compiler, read through `RUSAGE_CHILDREN`. The script now reads
  the analyser's own usage. The tables above come from the corrected runs.

## Limits

- The inputs are synthetic and simple (small functions, direct calls, a few strings). Real binaries
  have more indirect control flow, more data and debug information, so the cost per instruction will
  differ. A real-world corpus is the missing part of G16-T1.
- The block bound (200,000) limits how large a complete analysis can be. Raising it is a design
  decision about memory, not part of this benchmark.
- One run per size on a shared virtual machine. Treat the times as indicative.
- The UI frame-time measurement of G16-T1 (with the UI scripts) is not part of this benchmark.
