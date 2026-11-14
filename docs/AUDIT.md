# Audit of Donkey on real binaries

This file records what Donkey does on real programs, measured on the binaries of this machine,
and how that changes. It is evidence for [`PARITY.md`](PARITY.md) section 3 and for the gap
ledger's "Donkey today" entries. It is not a capability list.

Two tables are kept: the **baseline**, measured on `main` at `1a92abf` before any audit fix, and
the **after** numbers, added when the fixes merge. Both use the same scripts in
[`tools/audit/`](../tools/audit/README.md).

## How it was measured

- **Scripts.** `audit.py` (function starts, timing and memory, and a robustness sweep) and
  `sample.py` (decompiles 300 randomly chosen `.text` functions per binary with a fixed seed, one
  process per function, and counts the outcomes). Both run `donkey-cli` from the Release headless
  build. They were run with `python3 -I`.
- **Reference tool.** radare2 5.5.0 (`r2`, `aaa` analysis) was the only reference tool that could be
  run on this machine. It is shown beside Donkey for every binary.
- **Ground truth.** Own binaries have symbols: the unstripped `donkey-cli` (1,973 symbols) and the
  AArch64 cross build (2,425 symbols) are scored against those symbols. System binaries are
  stripped, so they are scored against their `.eh_frame` FDE start addresses (the truth kind is
  `fde` in the logs). An FDE start is not a symbol: it is a function start the compiler recorded.
- **Own stripped binary.** The unstripped CLI was stripped and analysed with Donkey and r2, then
  scored against the symbols and against its own `.eh_frame` entries.
- **Not run.** IDA Pro, Ghidra and Binary Ninja were **not** run. No number here is a comparison
  with them. The parity rows that name them use their public documentation only.

## Baseline on `main` at `1a92abf` (2026-11-13)

### Function starts

Recall is the share of ground-truth starts found; precision is the share of found starts that are
true. Times are from the Donkey run on that binary.

| Binary | Ground truth | Donkey recall / precision | r2 recall / precision | Donkey time, peak RSS |
|---|---|---|---|---|
| own `donkey-cli`, unstripped | 1,973 symbols | 100.0 / 100.0 | 99.9 / 99.4 | 1.52 s, 641.0 MiB |
| own `donkey-cli`, stripped, vs symbols | 1,973 symbols | 85.8 / 100.0 | 85.6 / 100.0 | 1.27 s (stripped copy 8,301,584 bytes), 640.1 MiB |
| own `donkey-cli`, stripped, vs `.eh_frame` | 2,487 FDEs | 68.0 / 99.9 | 68.0 / 99.8 | |
| `/usr/bin/ls` | 185 FDEs | 50.3 / 98.9 | 49.2 / 96.8 | 0.05 s, 26.7 MiB |
| `/usr/bin/openssl` | 534 FDEs | 55.8 / 99.7 | 55.2 / 99.0 | 0.17 s, 94.9 MiB |
| `/usr/bin/bash` | 2,342 FDEs | 88.5 / 100.0 | 88.0 / 99.9 | 0.47 s, 213.4 MiB |
| `libsqlite3.so.0` | 2,772 FDEs | 76.7 / 100.0 | 76.4 / 99.9 | 0.51 s, 278.7 MiB |
| `libc.so.6` | 3,785 FDEs | 79.9 / 100.0 | 79.8 / 100.0 | 0.94 s, 339.4 MiB |
| `/usr/bin/git` | 4,472 FDEs | 68.9 / 100.0 | 67.4 / 99.6 | 1.56 s, 642.7 MiB |
| `/usr/bin/python3.12` | 11,415 FDEs | 33.0 / 100.0 | 32.8 / 99.9 | 1.29 s, 665.8 MiB |
| own AArch64 `donkey-cli` (cross build), vs symbols | 2,425 symbols | 99.8 / 100.0 | 99.8 / 99.1 | 1.65 s, 625.4 MiB |

Recall against `.eh_frame` is the main weakness: the starts that Donkey misses are the ones it
does not seed from anything except the entry point, exported symbols and call targets. The
analysis of the 8 MiB stripped binary took 1.27 s and 640 MiB peak RSS.

### Robustness sweep

200 system binaries were analysed by `audit.py`. All 200 finished (`ok`), with no crash and no
error. The total was 35.3 s; the slowest was `aarch64-linux-gnu-ld.gold` at 2.2 s.

### Decompiler sample (`sample.py`)

300 functions per binary were drawn at random (seed fixed), except the 94 functions of `ls`, which
has only 94. Total: **1,893 sampled functions**, drawn from 12,531 `.text` functions in those seven binaries
(`text_functions` per binary: `ls` 94, `bash` 2,073, `openssl` 299, `libsqlite3.so.0` 2,128,
`libc.so.6` 3,026, own x86-64 2,490, own AArch64 2,421).

| Binary | Sampled | Complete | Partial | InvalidIR | Unsupported | Crash |
|---|---|---|---|---|---|---|
| `ls` | 94 | 7 | 55 | 32 | 0 | 0 |
| `bash` | 300 | 34 | 166 | 100 | 0 | 0 |
| `openssl` | 299 | 15 | 198 | 86 | 0 | 0 |
| `libsqlite3.so.0` | 300 | 48 | 193 | 55 | 0 | 4 |
| `libc.so.6` | 300 | 46 | 155 | 39 | 58 | 2 |
| own `donkey-cli` (x86-64) | 300 | 28 | 181 | 91 | 0 | 0 |
| own `donkey-cli` (AArch64) | 300 | 31 | 152 | 86 | 31 | 0 |
| **All** | **1,893** | **209 (11.0%)** | **1,100 (58.1%)** | **489 (25.8%)** | **89 (4.7%)** | **6 (0.3%)** |

- Every InvalidIR result is `ir.unreachable_block`. The 58 and 31 Unsupported results of `libc` and
  the AArch64 binary carry `lift.no_blocks`.
- The crashes are `0x35d90`, `0x364b0`, `0x348f0` and `0x236f0` in `libsqlite3.so.0`, and
  `0x13d220` and `0x13dcb0` in `libc.so.6`. All six are SIGFPE from `lift_rotate` (`rol r9w, 8`
  and similar).
- 1,009 sampled functions carry "outgoing call arguments and return values follow no modelled
  ABI". 902 carry "control flow not fully structured; showing labeled blocks".
- Per-binary reason counts are in `sample.log`. The full-binary run in `audit.log` reports
  `Partial` 766, `InvalidIR` 229 and `Complete` 5 for the own unstripped CLI: 1,000 functions, not
  the 2,490 it holds. That is the silent cap (see the defects below).

## Defects the baseline found

1. **Crash in the lifter.** `rol` and `ror` of `r8w` to `r15w` divided by a width of 0 (the table
   had no 16-bit high registers). SIGFPE, exit 136 on `donkey-cli`. Fixed by Goal 1.
2. **Unreachable-block rejections.** A quarter of the sampled functions fail `verify_ir` with
   `ir.unreachable_block` and print nothing. Causes are being fixed (Goal 4).
3. **Silent 1,000-function cap.** `donkey-cli decompile <binary> --json` stops after 1,000
   functions with no message (Goal 2).
4. **Wrong register in a note.** On AArch64 the note "the returned register is not determined
   ...; rax is assumed" names `rax` (Goal 3). The audit log shows it 430 times on the AArch64
   binary.

## After

Measured on this machine, Release build, the same scoring as the baseline. Each row says which
commit it is, and what changed since the baseline. Numbers are never copied between populations:
where the population changed, the table says so.

### Population growth

The baseline sampled 1,893 functions from 12,531 `.text` functions of seven binaries. The
unwind-table seeds of G23-T1 and G23-T2 found more function starts (for example `ls` went from
94 to 186 starts, `bash` from 2,073 to 2,343, `python3.12` to 11,416), so a later run samples from
a larger population. Any comparison across that change must use the same addresses.

### Same-population measurement (`tools/audit/sample_list.py`)

The list was drawn once, from the function starts of the final commit (seed 7, 300 per binary,
186 for `ls`, all of its starts), and measured on each commit. Only system binaries are used, since
their files are identical at every commit (an own donkey-cli is a different file at each commit).
The seven binaries are `ls`, `openssl`, `bash`, `libsqlite3.so.0`, `libc.so.6`, `git`, `python3.12`.

| Commit | Complete | Partial | Unsupported | InvalidIR | "no modelled ABI" note | "not fully structured" note |
|---|---|---|---|---|---|---|
| `ed22df5` (before G21) | 155 | 1,369 | 262 | 0 | 1,278 | 1,164 |
| `c26a9d3` (G21, call arguments) | 167 | 1,357 | 262 | 0 | 1,269 | 1,164 |
| `665c9e4` (final: G24 block bound, extent) | 180 | 1,606 | 0 | 0 | 1,497 | 1,317 |

Sampled: 1,786 functions in each row, all found at every commit. Totals are summed from the
per-binary rows of `tools/audit/results/measure_ed22df5.log`, `measure_c26a9d3.log` and
`measure_665c9e4.log`; the address list is `tools/audit/results/list_final.json`.

- The G21 change alone (`ed22df5` to `c26a9d3`) moves 9 functions off the "no modelled ABI" note
  and 12 to Complete. The call-argument work resolves few calls in this sample, because most
  callees are not Complete integer-only functions of the same image.
- `ed22df5` predates the block-bound fix (commit `48db0fe`); its 262 Unsupported functions are
  the `git` and `python3.12` functions that the bound cut off. The final row therefore includes
  that fix, which accounts for most of the difference in the "no modelled ABI" note: those
  functions now have blocks and print with the note.
- The "not fully structured" note rose from 1,164 to 1,317. The rise is the functions that gained
  blocks in the final commit; most of them print labelled. This is the Goal 8 gap (section below).

### Correction to commit `c26a9d3`

Its commit message says that `c_call_loop` at `-O2` and `-O3` is Partial and that two of the ten
call corpus functions are not Complete. That is wrong. The last corpus report of that commit has
all six call-heavy functions (`c_call_add2`, `c_call_six`, `c_call_unused`, `c_call_loop`,
`c_call_wide`, `c_call_chain`) Complete and verified at `-O0`, `-O2`, `-O3` and `-O3-x86-64-v2`,
48 vectors each. The other remaining Partial corpus rows are pre-existing SIMD statements (`movdqu`,
`movdqa`, `movd`) at `-O3`. History is not rewritten, so this correction is recorded here.

### Block bound and the AArch64 build (item A)

The cross-built AArch64 donkey-cli has 3,587 functions. Before commit `48db0fe`, 745 of them were
Unsupported with `lift.no_blocks`: the control-flow graph stopped at a fixed bound of 200,000 blocks.
The bound is now one block per decoded instruction, with 200,000 as the floor. After it: 0
Unsupported, Complete 310, Partial 3,277, CFG status Complete with 267,667 blocks.

Analysis time and peak memory of the 8.3 MB stripped x86-64 donkey-cli (`functions --json`):
2.15 s and 645 MiB peak RSS (measured after the fix; the Goal 5 measurement was 1.81 s).

### Structuring (item C)

The "not fully structured" share is 1,317 of 1,786 (73.7%) on the fixed list at `665c9e4`, against a
bar of 52% (1,317 is above it). The most frequent defeating shape is irreducible control flow: a
loop entered at more than one block, which the structurer rejects in `find_loops`. On `ls` after the
fall-through fix, 115 of the 120 labelled functions fail there; the others fail at `region_closed`
or in emission. The fix for the dominant shape is node splitting (duplicating loop-body blocks while
keeping the index layout and fall-throughs consistent). That is not implemented. A tail-duplication
attempt for shared return blocks was measured and removed: it changed no function in `ls`.
