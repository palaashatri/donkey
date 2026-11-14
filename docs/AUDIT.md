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
5. **Statements of a branching block omitted from pseudocode (found after goal 8, step 1).**
   The structured emitter printed a block's terminator-test `if` without first printing the
   block's own statements, so statements that run before a conditional branch were missing
   from the output. The shipped text on `main` could omit them. Introduced in `1915c3c`
   ("structure reducible control flow into if/else and loops", on `main`). Fixed in
   `7cfddc2` on `claude/funny-meitner-cpc7oc`; regression test
   `Ir.StatementsInTheBranchingBlockArePrintedBeforeTheIf` (fails without the fix, with the
   `rsi` assignment missing from the output). The IR oracle did not catch it because it
   executes the IR, not the printed text. Guard for this class: see goal 8, step 0.

## After

Measured on this machine, Release build, the same scoring as the baseline. Each row says which
commit it is, and what changed since the baseline. Numbers are never copied between populations:
where the population changed, the table says so.

### Population growth

Population sizes (`.text` function starts, as `donkey-cli functions` reports them):

| Binary | Baseline (`sample.py`, `1a92abf`) | Final (`665c9e4`, fixed list) |
|---|---|---|
| `ls` | 94 | 186 |
| `openssl` | 299 | 535 |
| `bash` | 2,073 | 2,343 |
| `libsqlite3.so.0` | 2,128 | 2,773 |
| `libc.so.6` | 3,026 | 3,786 |
| `git` | not sampled | 4,473 |
| `python3.12` | not sampled | 11,416 |

The baseline sampled 1,893 functions (300 per binary, the own binaries included; 12,531 `.text`
starts across seven binaries). The final list samples 1,986 from the seven system binaries
(300 each, all 186 of `ls`). The unwind-table seeds of G23-T1 and G23-T2 found more function
starts, so a later run samples from a larger population. Any comparison across that change must
use the same addresses.

### Same-population measurement (`tools/audit/sample_list.py`)

The list was drawn once, from the function starts of the final commit (seed 7, 300 per binary,
186 for `ls`, all of its starts), and measured on each commit. Only system binaries are used, since
their files are identical at every commit (an own donkey-cli is a different file at each commit).
The seven binaries are `ls`, `openssl`, `bash`, `libsqlite3.so.0`, `libc.so.6`, `git`, `python3.12`.

| Commit | Complete | Partial | Unsupported | InvalidIR | "no modelled ABI" note | "not fully structured" note |
|---|---|---|---|---|---|---|
| `ed22df5` (before G21) | 155 | 1,569 | 262 | 0 | 1,278 | 1,164 |
| `c26a9d3` (G21, call arguments) | 167 | 1,557 | 262 | 0 | 1,269 | 1,164 |
| `665c9e4` (final: G24 block bound, extent) | 180 | 1,806 | 0 | 0 | 1,497 | 1,317 |

Sampled: 1,986 functions in each row, all found at every commit. Totals are summed from the
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

The "not fully structured" share is 1,317 of 1,986 (66.3%) on the fixed list at `665c9e4`, against a
bar of 52% (1,317 is above it). The most frequent defeating shape is irreducible control flow: a
loop entered at more than one block, which the structurer rejects in `find_loops`. On `ls` after the
fall-through fix, 115 of the 120 labelled functions fail there; the others fail at `region_closed`
or in emission. The fix for the dominant shape is node splitting (duplicating loop-body blocks while
keeping the index layout and fall-throughs consistent). That is not implemented. A tail-duplication
attempt for shared return blocks was measured and removed: it changed no function in `ls`.

### Goal 8: structuring, measured on the fixed 1,986-function list

Progress (the state is in the commits; this list is the order of the work):
1. Done: post-dominators with a virtual exit (`immediate_post_dominators`), and the fallback
   structurer (`Structurer::run_fallback`), used only when the layout-based structurer and the
   reverse-postorder copy both reject a function. Measured below (step 1).
2. Done: trampoline entry rule removed from `reverse_postorder_copy` (no output changed; see below).
3. Done: bounded duplication of small return blocks in the fallback (at most 8 statements per copied
   block, at most 64 duplicated statements per function). Measured below (step 5): the bar is met.
4. Done: node splitting for irreducible functions under per-node (16 statements) and per-function
   (64 statements) bounds. It makes 37 functions reducible but gains no structured function; see
   the step 2 section.
5. Next: full verification on the final commit, and the doc updates (G04, PARITY row 7, README, AGENTS).

Bar: at most 1,032 of 1,986 labelled. Current: 996 (50.2%), met.


Classification (`classify_structure`, `ir.h`): a function is **structured** (printed without labels),
**irreducible** (an iterative depth-first search from the entry finds a retreating edge whose target
does not dominate its source), **reducible but rejected** (reducible, and the structurer rejects the
shape: the reason is the last attempt's), or **other** (empty, invalid or unreachable blocks). The
measurement is `tools/audit/sample_list.py measure` on `tools/audit/results/list_final.json`.

| Commit | Structured | Irreducible | Reducible but rejected | Labelled (note) | Share |
|---|---|---|---|---|---|
| `665c9e4` (before the structuring work) | 669 | 143 | 1,174 | 1,317 | 66.3% |
| `9b49613` (dominance loops, reverse-postorder copy, break rules) | 715 | 143 | 1,128 | 1,271 | 64.0% |
| step 1: fallback structurer and post-dominators | 915 | 143 | 928 | 1,071 | 53.9% |
| step 5: return-block copies in the fallback (bounded) | 990 | 143 | 853 | 996 | 50.2% |
| step 2: node splitting of irreducible functions | 990 | 106 | 890 | 996 | 50.2% |

The bar is at most 52% of the list (at most 1,032 functions labelled). Step 1 brings it to 1,071
(53.9%), still not met.

What each rule changed:
- Loops are natural loops (a back edge is an edge whose target dominates its source), and
  irreducibility is checked first in `run()`. The rejection `back edge by index not dominated by its
  target` (1,032 functions) was a reducible join block below its predecessor taken for a loop. It is
  gone; the functions moved to later checks and none became structured by this rule alone.
- A reverse-postorder copy of the function (printing only), tried after the layout as given fails.
  The entry is first, a conditional branch whose fall-through is no longer next gets an explicit
  branch block, and a trampoline is not copied. 669 to 715 structured.
- A conditional branch to the innermost loop's exit prints as `if (cond) break;` (a rejection inside a
  switch), and an `if` inside a loop may contain its break edge. No count change on the list; covered
  by `Ir.ConditionalBranchToTheLoopExitPrintsAsBreak`.
- Tried and removed: a loop-contiguous layout (each natural loop's body as one run). It structured no
  additional function, so it was not kept.

Remaining rejections (last attempt, 1,128 reducible functions): region not closed 596, loop exit not
determined 169, loop leaves through several blocks 168, if without join 100, loop body not contiguous
63, loop latch not a conditional 16, loop latch not an exit 13, switch case falls into the next 2, loop
header with a test 1. In the failing regions the edges are: a block in a region branching to a block
before it with no enclosing loop, and a join block with a predecessor outside its region. Those need
region construction that does not depend on index ranges. Irreducible (143 functions) needs node
splitting with a bound on the duplicated code; neither is implemented.

#### Step 1: fallback structurer (measured on the same 1,986 functions)

The fallback is used only after the layout-based structurer and the reverse-postorder copy both
reject a function. It builds regions from the trees: an `if` joins at the branch block's immediate
post-dominator; a loop is the natural loop of its back edges (a back edge is one whose target
dominates its source), its follow block is the exit that the most body blocks reach without leaving
by a non-return exit, ties going to the earlier reverse-postorder block; an arm that is the innermost
loop's header or follow prints as `continue;` or `break;`; a return block the loop leaves prints in
place. Every block must be emitted exactly once, or the attempt is rejected, so no statement is
dropped (the printed-statement guard, `DecompilerCorpus.EveryKeptStatementIsPrinted`, runs on the
corpus).

| Structured | Irreducible | Reducible but rejected | Labelled | Share |
|---|---|---|---|---|
| 915 | 143 | 928 | 1,071 | 53.9% |

Rejections by the fallback (last attempt), 928 functions:

| Shape | Functions |
|---|---|
| a block is reached twice (a return block reached by two edges, or a join reached twice) | 446 |
| a branch leaves its region (a jump to a block outside the region's blocks) | 378 |
| an if joins outside its region | 91 |
| a loop leaves to a block that is not its follow | 8 |
| a terminator the fallback does not structure (switch) | 5 |

Per binary: ls 84 structured of 186; openssl 124 of 300; bash 154 of 300; libsqlite3 166 of 300;
libc 169 of 300; git 86 of 300; python3.12 132 of 300.

Rules and their tests (each fails when its rule is disabled, checked by hand):
- `Ir.PostDominatorsOfADiamondJoinAtTheMerge`, `Ir.EveryReturnFeedsTheVirtualExit`,
  `Ir.ATailCallFeedsTheVirtualExit`, `Ir.PostDominatorsOfAWhileLoopLeaveTheHeaderToItsExit`
  (the virtual exit: the two exit tests fail when returns do not feed it).
- `Ir.FallbackPrintsALoopExitToTheFollowAsBreak` (break; fails when the break edge is disabled).
- `Ir.FallbackPrintsALoopExitToAReturnBlockInPlace` (return in place; fails when a loop's
  unconditional exit to a return block is rejected).
- `Ir.FallbackJoinsAnIfAtItsPostDominator` (the if join; fails when a branch without a join is
  rejected). The layout-based structurer rejects this loop, so the test needs the fallback.
- `Ir.FallsBackToLabelsForIrreducibleControlFlow` was corrected: its cycle had one entry, so the
  graph was reducible and the fallback structured it. It now has two entries to the cycle.

#### Trampoline entry rule (removed)

The trampoline-entry rule in `reverse_postorder_copy` (skip a block-0 trampoline and enter at its
target) fired on 29 of the 1,986 sampled functions (instrumented locally, not committed). Printed
output with the rule and without it was identical on all 29 (a byte comparison of the decompile
output, 412,943 bytes each), so the rule was removed. The two trampoline tests are kept as output
regressions and do not discriminate: `Ir.SyntheticEntryTrampolineDoesNotPrintAsGoto` and
`Ir.SyntheticEntryTrampolineInAnIfWithTwoReturnsDoesNotPrintAsGoto` (the second is the shape of
libc `sub_191770`). The original layout already structures these shapes.

#### Step 5: bounded copies of return blocks (measured on the same 1,986 functions)

A return block (a block with no successors, ending in `return`; a tail call is one) reached a second
time in the fallback is printed again as a copy, if it has at most 8 statements and the copies in
the function so far stay within 64 duplicated statements. A copy keeps the source addresses of the
original. Past either bound the attempt is rejected and the function stays labelled.

| Structured | Irreducible | Reducible but rejected | Labelled | Share |
|---|---|---|---|---|
| 990 | 143 | 853 | 996 | 50.2% |

Rejections by the fallback (last attempt), 853 functions: a block is reached twice (not a return
block) 342; a branch leaves its region 288; the return duplication bound is reached 128; an if joins
outside its region 82; a loop leaves to a block that is not its follow 8; a switch 5.

Tests (each fails when its rule is disabled, checked by hand): `Ir.FallbackCopiesASmallReturnBlockReachedTwice`
(fails with the copy budget at zero), `Ir.FallbackDoesNotCopyAReturnBlockOverEightStatements`
(the per-block bound), `Ir.FallbackStopsCopyingAtTheFunctionBudget` (fails with the budget at 1000).

#### Step 2: node splitting (measured on the same 1,986 functions)

For an irreducible function, the splitter finds a retreating edge whose target does not dominate its
source, and copies that target once per incoming edge (the copies keep the source addresses). It
repeats until no retreating edge is irreducible, then lays the blocks out again with explicit
branches, and the structurer and the fallback run on the result. Bounds: a split duplicates at most
16 statements, and a function at most 64 in all. Past a bound, or for a shape it does not model, the
function stays irreducible and the verdict names the region.

| Structured | Irreducible | Reducible but rejected | Labelled | Share |
|---|---|---|---|---|
| 990 | 106 | 890 | 996 | 50.2% |

Against step 5: 37 functions are now reducible (the irreducible count fell from 143 to 106), and
none of them is structured. The split leaves a loop header with two entries from outside (the copy
of the target is an entry), and the structurer and the fallback model a single entry. Structuring
them needs the loop body copied per entry, which the per-node bound does not allow for most loops.

Remaining shapes, with one example address each (from the `ls` sample; the other binaries have the
same shapes):

| Shape | Example | Why it resists |
|---|---|---|
| node-splitting bound reached (16 per split, 64 per function) | `ls` 0x4da0 (irreducible region at 0x60f0) | splitting duplicates the whole target block; a loop with a large body exceeds the bound |
| a terminator the splitter does not model (switch) | `ls` 0x11f70 | the splitter's successor model has branches and conditional branches only; a switch has case edges |
| reducible after the split, the loop header has two entries | the test `Ir.SplitsAnIrreducibleFunctionIntoAReducibleOne` (no sampled address checked for this shape) | a single-entry loop is needed; copying the loop per entry is beyond the bound |
| a block is reached twice (not a return) | `ls` 0x7c50 | a join reached from two arms with no common join needs node copies beyond return blocks |
| a branch leaves its region | `ls` 0x6ea0 | a jump into a block that belongs to another region; the regions are built from the dominator trees and do not cover it |
| an if joins outside its region | `ls` 0x8090 | the if's join is the post-dominator of an arm that reaches the exit separately |
| the return duplication bound is reached | `ls` 0x8190 | more copies of return blocks than the 64-statement budget |

Tests: `Ir.SplitsAnIrreducibleFunctionIntoAReducibleOne` (the verdict is ReducibleRejected rather
than Irreducible; fails with splitting disabled) and `Ir.NodeSplittingKeepsItsPerNodeBound` (the
verdict is Irreducible and names the bound; fails with the per-node bound removed).

#### Verification (code at `f2e194a`; this section is the only change after it)

| Tree | Compiler and preset | Result |
|---|---|---|
| `build/headless-linux` | GCC 13.3, headless | 789 of 789 pass (includes the corpus oracle, `DecompilerCorpus.EveryKeptStatementIsPrinted`, and the pass-preservation tests) |
| `build/clang-headless` | Clang, headless | 789 of 789 pass |
| `build/release-headless` | Release, headless | 790 of 790 pass |
| `build/dev-linux` | desktop shell, UI smoke tests under `xvfb-run -a -s "-screen 0 1600x1000x24"` | 816 of 816 pass |
| `build/cross-a64` | AArch64 under `qemu-aarch64 -L /usr/aarch64-linux-gnu` (the tree's ctest launcher) | 242 tests; 241 pass; 1 skipped (`DecompilerCorpus.FrameSlotsTakeTheNamesOfTheDebugInformation`, a platform skip that predates goal 8) |

Pinned clang-format (`cf2018`) passes over every changed file (`src/ir/structure.cpp`,
`src/ir/ir.cpp`, `src/ir/ir_internal.h`, `tests/unit/ir_test.cpp`,
`tests/unit/decompiler_corpus_test.cpp`).

Not run here: the FreeBSD, macOS and Windows presets, and the package targets.

### W1: goto structuring (G04-T5)

Branch `agent/ir/G04-T5-goto-structuring`, measured on the fixed list (`tools/audit/results/list_final.json`,
1,986 functions) with the Release build of the branch head (`c101de2`) and the baseline build from
`5162f62` (the plan commit, no code change; the same list). The measurement is
`sample_list.py measure`, extended with the goto and refusal counts.

| | Before | After |
|---|---|---|
| Printed as labelled blocks (whole function) | 996 (50.2%) | **0** |
| Structured, no goto | 990 | 989 |
| Structured with gotos | 0 | 997 |
| Gotos, total | 0 | 16,476 |
| Gotos, largest in one function | 0 | 394 (`git`) |
| Candidate structures refused by the control-flow check | not checked | 0 |
| Complete / InvalidIR / Unsupported | 180 / 0 / 0 | 180 / 0 / 0 |

Per binary (after; before in brackets is the labelled count):

| Binary (sampled) | Labelled | No goto | With gotos | Gotos | Largest |
|---|---|---|---|---|---|
| ls (186) | 0 (96) | 90 | 96 | 1,649 | 239 |
| openssl (300) | 0 (169) | 130 | 170 | 3,385 | 292 |
| bash (300) | 0 (130) | 170 | 130 | 2,031 | 235 |
| libsqlite3 (300) | 0 (124) | 177 | 123 | 1,754 | 126 |
| libc (300) | 0 (122) | 177 | 123 | 1,423 | 101 |
| git (300) | 0 (199) | 101 | 199 | 3,751 | 394 |
| python3.12 (300) | 0 (156) | 144 | 156 | 2,483 | 392 |

**Goto-free functions dropped by 1 (990 to 989), and this is a correctness fix, not a regression.**
Per function, two functions left the goto-free set and one joined it (`libsqlite3`). The two that left
(`openssl` `0xa9b70`, `libc` `0x97ec0`) printed a switch whose join lies outside the region of the
enclosing `if`. The layout-based structurer accepted that by walking on to the next block, which printed
the case blocks a second time: `return rax;` appeared 22 times in `0x97ec0` and `rax = (u64)(0xbacc6);` 103
times in `0xa9b70` (their outputs had 230 and 539 lines; now 139 and 203). The switch rule now rejects
that shape (`switch join outside its region`), and the goto structurer prints the two functions with
gotos (one in `0xa9b70`, two in `0x97ec0`). Net goto-free count: 990 before, 989 after.

Where the gotos are. Counted on `openssl` (all its functions, both runs of the goto structurer, so each
decision counted twice; shares are what matter):

| Target of the goto | Share | Note |
|---|---|---|
| a block already printed earlier in the function | 60% | 59% of these blocks have at most 4 statements: short-circuit conditions (`a && b` joins a block printed in the first arm) and switch arms that share a block |
| a block the region does not dominate | 28% | a join reached from an arm, not the arm's own join |
| the stop of an arm, not printable there | 12% | an `if` whose join is already printed or is a loop's follow |
| a loop header from outside its loop | 3% | multi-entry loops (irreducible) |
| return blocks (any target above) | 5% | copying returns would remove little |

Copying small blocks into each arm that reaches them would remove the first group (not measured; it is
the candidate for the owner decision below, because it grows the output). It is not done.

Control-flow check. Every candidate structure (the layout-based ones, their reverse-postorder copy,
the fallback, the split function, and the goto structurer) is rebuilt from its tags and compared with the
IR edge by edge; a candidate that fails is refused and the next one is tried. Across the 1,986 functions:
0 refusals. The check found two bugs of its own kind during the work: the switch join rule (above), and a
goto emitted for a break whose join was already printed (`libc` `sub_e7870`, `sub_ea0b0`, `confstr`: refused
until the fix, now `goto_structured` with 0 refusals). The corpus test
`DecompilerCorpus.EveryPrintedFunctionPassesTheControlFlowCheck` runs the same check on every corpus function.

Rules and tests (each rule switched off in the emitter fails its test; checked by hand, failures shown in
the commit messages): `Ir.RuleSequencePrintsAFallThroughWithoutGoto`, `Ir.RuleIfElsePrintsADiamondAsIfElse`,
`Ir.IfWithoutElsePrintsItsComplementedCondition`, `Ir.RuleLoopPrintsANaturalLoopAsWhileOne`,
`Ir.RuleWhileTestPrintsAPureHeaderAsItsCondition`, `Ir.RuleBreakPrintsALoopExitAsBreak`,
`Ir.RuleContinuePrintsABackEdgeInTheBodyAsContinue`, `Ir.RuleSwitchPrintsEachArmFromItsTarget`, plus
`Ir.GotoLeavesALoopByAnExitThatIsNotItsFollow`, `Ir.IrreducibleControlFlowIsPrintedWithAGotoIntoTheCycle`
and `Ir.SwitchInALoopWhoseArmLeavesTheLoopIsAGotoNotABreak` (the switch-join rule: with the old rule
switched on, its arm prints `break;` and the check refuses it).
The check's own tests: `Ir.ControlFlowCheck*` (a condition that goes the wrong way, in the tags only and
in the tags and text together; a break to the wrong block; a block that is not printed).

What the check does not cover: statement text (`DecompilerCorpus.EveryKeptStatementIsPrinted` does, for
kept statements); the rendering of conditions and operands (the check renders conditions with the printer's
own function, so a wrong rendering is not caught); and the choice of which side is the then-arm beyond
the tags (the text of each control line is checked against its tag).

Timing: whole-binary `decompile --json`, one process at a time, two runs of each binary, baseline and
branch alternating (wall time, seconds):

| Binary | Baseline | Branch | Difference |
|---|---|---|---|
| openssl | 6.25, 7.41 | 7.61, 8.43 | +22%, +14% |
| git | 246.9, 248.2 | 248.9, 261.0 | +1%, +5% |

Both are under the 25% bar. The `openssl` runs vary by about 15% on this machine between repeats of the
same binary, so the small figure is the one to read. Structuring runs once per candidate, and the CLI
also classifies each function (a second run of the structurers), so most of the added cost is the check.

Decisions for the owner (not made here): (1) whether to copy small blocks (up to 4 statements) into each
arm that reaches them, which should remove much of the first goto group at a cost in output size; (2) whether
compound conditions (`a && b`) are recovered as one `if` with a combined condition, which needs a
multi-block condition in the tags and a check of its rendering; (3) whether 997 functions with gotos is
acceptable as the decompiler's state for irreducible and shared-join control flow until (1) or (2) is
decided.
