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

6. **Resource use of the fallback structurer (introduced on this branch, fixed on this branch).**
   The fallback nested every `if` whose arm returns inside the rest of its region's `else`, so an
   input of N chained early-return tests recursed N levels deep and indented each line by 2N spaces:
   memory was quadratic and the recursion unbounded. On a 512 KiB thread (the macOS default for
   secondary threads) N = 10,000 segfaulted; at N = 5,000 the branch used 438 MiB against main's 41
   MiB. Fixed by (a) an `if` whose taken arm cannot fall out, when both arms leave by return, closes
   and the fall-through continues at the same level (a chain stays flat), (b) a nesting bound of 128
   (`kMaxStructureNesting`, `ir_internal.h`, used by the fallback and by the layout structurer's
   `emit_range`): a deeper candidate is rejected with "nesting deeper than 128 levels" and the next
   stage or the labelled form prints it, and (c) each structurer attempt is scoped, so its
   dominator and post-dominator sets (quadratic in the block count) are freed before the next attempt
   builds its own. Tests: `Ir.EarlyReturnChainPrintsFlatWhenShort`,
   `Ir.EarlyReturnChainOf5000FormatsOnASmallStack` (512 KiB thread; it segfaults before the fix),
   `Ir.NestingThatCannotBeFlatIsRejectedNotNested`, and
   `Ir.NestedChainDeeperThanTheBoundPrintsLabelledOnASmallStack` (1,000 genuinely nested tests on a 512
   KiB thread: it segfaults before the bound, and prints labelled after it).

   Follow-up (`6af21ee`). As first written, the flat form also fired when the fall-through was an
   edge rather than a block to print next: in a loop body whose `if` returns on one side and goes
   back to the loop header on the other (openssl `sub_a9c60`), the walk reached the header a second
   time and the function was rejected with "a block is reached twice" instead of printing
   `continue;`. Nine functions of the fixed list became labelled (openssl 2, libsqlite3 1, libc 1,
   git 5; on the whole binaries, 71). The flat form now applies only when the fall-through is not
   the region's stop, not a block already printed, and not the innermost loop's header or follow;
   otherwise the nested form prints it as before. Test:
   `Ir.LoopBodyWithAnEarlyReturnFallsBackToContinueNotFlat` (the openssl shape; fails with the
   guard removed). Checked on every function of openssl, libsqlite3, libc and git (13,472
   functions, `decompile --json`): the structure class of each one is the same at `6af21ee` as at
   `cedb9db` (7,496 structured before and after; none lost, none gained), so the fixed-list counts
   are those of step 2 of goal 8 (990 structured, 996 labelled).

Stress table (`stress N stack_KiB` through `rss.py`, which caps the address space at 1.5 GiB; N
checks followed by the irreducible tail of `Ir.IrreducibleControlFlowPrintsGotoNotLabelledBlocks`,
2N+4 blocks). Peak RSS and wall time:

| N | main `1a92abf` | branch before (`cedb9db`) | branch after (`6af21ee`), 512 KiB stack |
|---|---|---|---|
| 2,500 | 16 MiB, 0.1 s | 152 MiB, 0.4 s | 31 MiB, 0.2 s |
| 5,000 | 41 MiB, 0.2 s | 438 MiB, 1.2 s | 77 MiB, 0.8 s |
| 10,000 | 126 MiB, 0.7 s | bad_alloc, abort | 209 MiB, 3.0 s |
| 10,000 on 512 KiB | ok | segfault | ok (the row above) |

All runs are Release builds of the IR library linked into the stress driver, one at a time on an
otherwise idle machine. After the fix the ratio to main is 1.9 at 2,500, 1.9 at 5,000 and 1.7 at
10,000, all within 2x, and no run aborts or segfaults. Every run prints the function labelled (the
tail is irreducible), with a maximum indentation of 2 spaces. The genuinely nested chain (`nest.cpp`:
block 2k tests and branches to 2k+2, block 2k+1 jumps to the return block; 512 KiB stack) prints
labelled: 13 MiB and 0.1 s at D = 1,000, and 334 MiB and 5.5 s at D = 10,000 (20,001 blocks). Main
segfaults on that shape at D = 10,000 on a 512 KiB stack.

Not fixed here, and also on main: the dominator sets are bit sets, quadratic in the block count.
At D = 50,000 (100,001 blocks) main and this branch both end in `std::bad_alloc` under a 1.5 GiB
address-space cap, and the CFG bound allows 200,000 blocks. Replacing the sets with an immediate
dominator tree and interval queries is the next task for this defect class.


## After

Measured on this machine, Release build, the same scoring as the baseline. Each row says which
commit it is, and what changed since the baseline. Numbers are never copied between populations:
where the population changed, the table says so.

### Function starts at `6af21ee`

Same scoring as the baseline table (`.cold` fragments ignored), Release build. `donkey-cli functions
--json` on each binary.

| Binary | Ground truth | Baseline recall / precision | `6af21ee` recall / precision |
|---|---|---|---|
| own `donkey-cli`, stripped, vs symbols | 2,077 symbols (this build) | 85.8 / 100.0 (1,973 symbols) | 99.9 / 99.9 |
| `/usr/bin/ls` | 185 FDEs | 50.3 / 98.9 | 100.0 / 99.5 |
| `/usr/bin/openssl` | 534 FDEs | 55.8 / 99.7 | 100.0 / 99.8 |
| `/usr/bin/bash` | 2,342 FDEs | 88.5 / 100.0 | 100.0 / 100.0 |
| `libsqlite3.so.0` | 2,772 FDEs | 76.7 / 100.0 | 100.0 / 100.0 |
| `libc.so.6` | 3,785 FDEs | 79.9 / 100.0 | 100.0 / 100.0 |
| `/usr/bin/git` | 4,472 FDEs | 68.9 / 100.0 | 100.0 / 100.0 |
| `/usr/bin/python3.12` | 11,415 FDEs | 33.0 / 100.0 | 100.0 / 100.0 |

The rows scored against `.eh_frame` are no longer independent: since G23-T1, Donkey seeds function
starts from the same FDEs, so 100% recall there shows that the seeds are read, not that discovery
finds functions. The independent check is the stripped own binary scored against the symbols of
its unstripped copy: 99.9% recall and 99.9% precision. Donkey also lists 549 `.cold` fragments of
that binary as functions of their own (each has its own FDE); they are ignored in the scores, as
in the baseline. A binary without unwind tables (G24) is not measured here.

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

Bar: at most 1,032 of 1,986 labelled. 996 (50.2%) after step 2, met; 985 (49.6%) after the review rounds (below, "Second and third review rounds").


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

#### Verification at `6af21ee` (the head of the branch before this section)

| Tree | Compiler and preset | Result |
|---|---|---|
| `build/headless-linux` | GCC 13.3, headless | 800 of 800 pass; 0 build warnings |
| `build/clang-headless` | Clang, headless | 800 of 800 pass; 0 build warnings |
| `build/release-headless` | Release, headless | 801 of 801 pass |
| `build/dev-linux` | desktop shell, UI smoke tests under `xvfb-run -a -s "-screen 0 1600x1000x24"` | 827 of 827 pass (3 platform skips: process isolation unavailable, a refused attach, an unsupported host) |
| `build/cross-a64` | AArch64 under `qemu-aarch64` (the tree's ctest launcher), whole suite | 769 of 795 pass; the 26 that fail need what qemu-user does not give: 18 native-debugger tests launch an AArch64 child under ptrace (the x86-64 kernel cannot exec it, exit status 126), and 8 CLI and Python script tests run the AArch64 `donkey-cli` directly rather than through the launcher (no binfmt handler, so `/bin/sh` reads the ELF file). Earlier rounds ran the decompiler subset only (DecompilerCorpus, Ir, Cfg), which passes. |

The CI format command (`find include src apps tests -type f \( -name '*.h' -o -name '*.cpp' \) |
xargs clang-format --dry-run --Werror`, pinned 20.1.8) is clean over the whole tree.

Not run here: the FreeBSD, macOS and Windows presets, and the package targets.

#### Review fixes and the re-measurement (after goal 8)

Four findings from the review of this branch were fixed, each in its own commit:

1. A callee that reads a stack argument was resolved with its register arguments only, and its
   caller was Complete with the seventh argument missing (`gcc -O1 -fno-inline`, `caller` printed
   `rax = sub_1129(rdi, rsi, rdx, rcx, r8, r9);`). `known_callee` now refuses such a callee: a
   dataflow over the callee's IR tracks each register as an offset from the entry rsp, and any access,
   lea or call argument at offset 8 or more, or any stack address it cannot follow, refuses the
   callee. Tests: `Ir.CallerOfAFunctionThatReadsAStackArgumentIsPartial` (bytes) and
   `cli.decompile_stack_argument_caller_is_partial` (fixture `tests/fixtures/calls/stack_argument-x86_64`,
   with its provenance). Both fail without the check.
2. An indirect tail jump (`jmp rax`) was lifted as a call to 0 (`ls` 0x6d60 printed
   `((void (*)(void))0x0)();`). It is now a call through its operand, as an indirect call is. Test:
   `Ir.IndirectTailJumpCallsItsOperand` (bytes `ff e0`), which fails on the old code. `ls` 0x6d60 now
   prints `((void (*)(void))rax)();`.
3. `tests/fixtures/link/libtailcall.so` has its recorded build in `tests/fixtures/link/PROVENANCE.md`:
   GCC 13.3.0, `gcc -O2 -shared -fPIC -o libtailcall.so tail.c` from a copy named `tail.c`; rebuilt
   byte-identical. Seeds committed for `fuzz_eh_frame` (`tests/fuzz/corpus/eh_frame`) and `fuzz_pdata`
   (`tests/fuzz/corpus/pdata`). Each target ran 60 s from a scratch copy of its corpus, exit 0:
   `fuzz_eh_frame` 3,692,837 runs; `fuzz_pdata` 25,531 runs.
4. The documents now describe this work as part of `main` once it merges (README, AGENTS, PARITY,
   SUPPORT_MATRIX, the G04 ledger entry, and DESIGN §17.2).

Re-measurement on the same 1,986 functions, after the fixes (`tools/audit/sample_list.py measure`):

| Structured | Irreducible | Reducible but rejected | Labelled | Share | Complete | InvalidIR | Unsupported |
|---|---|---|---|---|---|---|---|
| 990 | 106 | 890 | 996 | 50.2% | 180 (9.1%) | 0 | 0 |

Against the measurement before the fixes (step 2), every binary is unchanged except `python3.12`,
whose call-note count moved from 235 to 236 (the stack-argument refusal). No function changed its
verdict. The Complete share is 180 of 1,986 (9.1%); an earlier draft of PARITY row 6 said 10.1%, which
was wrong and is corrected.

#### Second and third review rounds, and the re-measurement

The second review round (`7e1c108`, `09d585e`, `6f4a2da`, `8493c88`) and the third (`d0b91c2` to `28cb808`) fixed
findings in the lifter, the evaluator, the unwind readers, the CFG walk, the structurer, the guards and
the audit tools; each has a test that fails without its fix (the PR's review threads list them). The
fixes that change what the measurement counts:

1. **A conditional jump to another function's start** (`09d585e`). The CFG walk followed it into the
   other function, so the caller took in that function's body. It now stops there; the lifter ends
   that path with an exit block that calls the target and returns (resolved like any direct call,
   else Partial with the note "conditional jump leaves the function; treated as a tail call").
   Tests: `Ir.AConditionalJumpToAKnownFunctionIsACallInAnExitBlock`,
   `Cfg.AConditionalJumpToAnotherFunctionDoesNotTakeInItsBody`. The same commit stopped the
   distinct-instruction budget from refusing an instruction that an earlier walk had counted
   (`Cfg.AnInstructionCountedByAnotherWalkIsFollowedAfterTheBudget`). Between `7e1c108` and
   `09d585e`, 16 functions of `python3.12` changed and none of the other six binaries: 12 went from
   rejected to structured, 1 from structured to rejected (`sub_6ca9f0`), and 3 from Partial to
   Complete. 14 of the 16 print the new exit-block call (item 1), among them `sub_6fff30`, now
   Complete. The other two (`sub_4cd5e8`, `sub_510f5f`) are one-block `xor eax, eax; ret` functions
   that were Partial with no note; which of the commit's two changes moved them was not separated.
2. **A resolved call writes all of `rax`** (`d0b91c2`). The call wrote `rax` at the callee's
   inferred return width. That width comes from the callee's last write in block order, so it can be
   narrower than what a path leaves in `rax` (`mov eax, 0x100; mov al, 1` returns 0x101 with a width of
   1), and the caller kept stale bits above it. After a call the caller's `rax` is the callee's `rax`,
   all 64 bits, and the IR now says so. Test: `Ir.AResolvedCallDefinesTheCalleesWholeRax` (the
   caller returned 2 instead of 1). On the fixed list it changed no count.
3. **Measurement inputs** (`9e98468`). `sample_list.py` hashes a private copy of each binary and
   samples or decompiles that copy, so the recorded hash names exactly the bytes measured. The seven
   binaries are files of installed Ubuntu packages, unchanged since before the list was drawn
   (`5d39ed2`, 2026-11-14): coreutils 9.4-3ubuntu6.3 (`ls`), openssl 3.0.13-0ubuntu3.16, bash
   5.2.21-2ubuntu4, libsqlite3-0 3.45.1-1ubuntu2.8, libc6 2.39-0ubuntu8.9, git 1:2.43.0-1ubuntu7.4,
   python3.12-minimal 3.12.3-1ubuntu0.17. `dpkg --verify` reports none of their files changed, and
   the last package operation on any of them was on 2026-10-22. No hash was recorded when the list was
   drawn; the hashes in `list_final.json` were recorded afterwards, from these files.

Re-measurement on the same 1,986 functions at `28cb808` (`tools/audit/sample_list.py measure`):

| Structured | Irreducible | Reducible but rejected | Labelled | Share | Complete | InvalidIR | Unsupported |
|---|---|---|---|---|---|---|---|
| 1,001 | 106 | 879 | 985 | 49.6% | 183 (9.2%) | 0 | 0 |

Per binary (Complete, labelled): ls 14, 96; openssl 17, 169; bash 28, 130; libsqlite3 45, 124; libc 39,
122; git 15, 199; python3.12 25, 145. 1,491 functions carry the call note (python3.12 234, from 236).
The counts at `09d585e` were the same, binary for binary; the change from the first round's table
(990 structured, 180 Complete) is all in `python3.12`, from `09d585e` (item 1).
### W1: goto structuring (G04-T5)

Branch `agent/ir/G04-T5-goto-structuring`, measured on the fixed list (`tools/audit/results/list_final.json`,
1,986 functions) with the Release build of the branch at `d5e9350` (after it merged
`claude/funny-meitner-cpc7oc` up to `8322ece`), and again at `443a2da` (after it merged phase A up to
`5309774`, which adds the stack-argument fixes of `e2c078c`): the two measurements are the same,
binary for binary. The baseline is phase A at `e2c078c`, measured the same way.
The measurement is `sample_list.py measure`, extended with the goto and refusal counts. (The first
measurement, at `14b94a4` against `5162f62`, had 996 labelled before and 989 goto-free, 997 with gotos
and 16,364 gotos after; the review fixes of phase A changed the baseline, see "Second and third review
rounds".)

| | Before (phase A, `e2c078c`) | After (W1, `443a2da`) |
|---|---|---|
| Printed as labelled blocks (whole function) | 985 (49.6%) | **0** |
| Structured, no goto | 1,001 | 1,000 |
| Structured with gotos | 0 | 986 |
| Gotos, total | 0 | 16,232 |
| Gotos, largest in one function | 0 | 409 (`git`) |
| Candidate structures refused by the control-flow check | not checked | 0 |
| Complete / InvalidIR / Unsupported | 183 / 0 / 0 | 183 / 0 / 0 |

Per binary (after; before in brackets is the labelled count):

| Binary (sampled) | Labelled | No goto | With gotos | Gotos | Largest |
|---|---|---|---|---|---|
| ls (186) | 0 (96) | 90 | 96 | 1,648 | 240 |
| openssl (300) | 0 (169) | 130 | 170 | 3,326 | 291 |
| bash (300) | 0 (130) | 170 | 130 | 1,997 | 230 |
| libsqlite3 (300) | 0 (124) | 177 | 123 | 1,734 | 125 |
| libc (300) | 0 (122) | 177 | 123 | 1,362 | 102 |
| git (300) | 0 (199) | 101 | 199 | 3,749 | 409 |
| python3.12 (300) | 0 (145) | 155 | 145 | 2,416 | 392 |

**Goto-free functions: 1,001 before, 1,000 after, and the drop is a correctness fix, not a regression.**
Per function, two functions left the goto-free set and one joined it (`libsqlite3` `0xa5c40`, which the
fallback rejected with "an if joins outside its region"). The two that left (`openssl` `0xa9b70`, `libc`
`0x97ec0`) print a switch whose join lies outside the region of the enclosing `if`. The layout-based
structurer accepts that by walking on to the next block, which prints the case blocks a second time: at
`e2c078c`, `return rax;` appears 22 times in `0x97ec0` and `rax = (u64)(0xbacc6);` 103 times in
`0xa9b70` (outputs of 230 and 539 lines). The switch rule now rejects that shape (`switch join outside
its region`), and the goto structurer prints the two functions with one goto each (126 and 184 lines;
the statement appears 9 times and once). These are the same three functions as at `14b94a4`.

Where the gotos are. Counted on `openssl` at `14b94a4` (all its functions, both runs of the goto
structurer, so each decision counted twice; shares are what matter):

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

Timing (branch head `14b94a4`): whole-binary `decompile --json`, one process at a time on an idle
machine, baseline and branch alternating (wall time, seconds):

| Binary | Baseline | Branch | Difference |
|---|---|---|---|
| openssl, four pairs | 5.64, 5.93, 5.69, 5.90 | 7.91, 6.38, 6.54, 6.21 | +40%, +8%, +15%, +5% (median +11%) |
| git, two pairs | 223.6, 222.3 | 229.2, 230.2 | +2.5%, +3.6% |

Both are under the 25% bar. The openssl repeats vary by about 15% between runs of the same binary, so
the first pair (+40%) is treated as noise, and the median is the figure to read. The earlier timing of
`c101de2` (openssl +22%/+14%, git +1%/+5%) is superseded by these numbers. Structuring runs once per candidate, and the
CLI also classifies each function (a second run of the structurers), so most of the added cost is the check.

### W1: stack and nesting (blocker fixes, branch head `14b94a4`)

A stress driver (`w1audit/stress`, not committed) builds N checks `if (rax == 0) return i;` followed by the
irreducible tail of `Ir.IrreducibleControlFlowPrintsGotoNotLabelledBlocks`, and formats the function on a
thread with a given stack size. The memory of each run is the peak RSS (`rss.py`, address space capped at 1.5 GiB),
one run at a time. `main` is `1a92abf` (the reference binary has no goto structurer).

| N | Stack | main: RSS, time, output | branch: RSS, time, output | ratio (RSS) |
|---|---|---|---|---|
| 2,500 | 64 MiB | 16 MiB, 0.1 s, labelled, 275 KB | 31 MiB, 0.1 s, structured, 142 KB | 1.9 |
| 2,500 | 512 KiB | 16 MiB, 0.1 s | 31 MiB, 0.1 s | 1.9 |
| 5,000 | 64 MiB | 41 MiB, 0.2 s, labelled, 557 KB | 70 MiB, 0.3 s, structured, 286 KB | 1.7 |
| 5,000 | 512 KiB | 41 MiB, 0.2 s | 70 MiB, 0.3 s | 1.7 |
| 10,000 | 64 MiB | 126 MiB, 0.7 s, labelled, 1.1 MB | 184 MiB, 0.8 s, structured, 576 KB | 1.5 |
| 10,000 | 512 KiB | 126 MiB, 0.7 s | 184 MiB, 1.0 s | 1.5 |

Every run completes on both stacks: no abort and no segfault. Memory is within 2x of main at every N.
Before the fixes, the same driver overflowed the 512 KiB stack at N=1,000 and hit `std::bad_alloc`
at N=10,000 with 175 MB of output and indentation of 10,004 columns at N=5,000 (the old quadratic output).

What changed:
- An arm that jumps closes its `if`, and the other arm continues at the same level in the caller's loop.
  A chain of checks is walked iteratively, not by one recursion per check, and it prints flat (`Ir.ThreeCheckChainPrintsFlatWithoutElse`).
- The post-dominators are computed with the iterative dominator algorithm on the reversed graph, not with
  bit sets. The old immediate-post-dominator scan was quadratic in the block count, and it ran on
  every candidate that reached the goto structurer.
- Empty markers print no indentation, and no printed line is only spaces (`Ir.NoPrintedLineIsOnlyWhitespace`).
- Nesting bound `kMaxStructureNesting = 128`. The emitter, the legacy structurer and each recursive routine
  of the control-flow check refuse a deeper nesting with a reason, and the labelled form prints.
  The bound is 128, not the 256 first proposed: a nested `if`/`else` chain of depth 200 runs on a
  512 KiB stack, depth 250 overflows it (about 2 KB of stack per level), so 256 would overflow the stack
  it is meant to protect. Depths 128, 200 and 300 now print labelled without a crash.
- Tests: `Ir.LongCheckChainFormatsOnASmallStackWithBoundedNesting` (5,000 checks on a 512 KiB pthread,
  indentation within 2 x bound + 16), `Ir.ThreeCheckChainPrintsFlatWithoutElse`, `Ir.NoPrintedLineIsOnlyWhitespace`,
  `Ir.ControlFlowCheckRefusesNestingDeeperThanTheBound`. Each was run against the previous code: the 5,000 check
  chain segfaults on the 512 KiB stack, the three-check chain prints `} else {`, the blank-line test finds
  whitespace-only lines, and the nesting test gets no refusal.

Measurement on the fixed list at `14b94a4` (before the merge of phase A's review rounds): labelled 0,
structured without goto 989, with gotos 997, 16,364 gotos in all, largest 409 (`git`), 0 candidates
refused, Complete 180, InvalidIR 0. At `d5e9350` and `443a2da`, after the merges, the numbers are those of the
table at the top of this section.

Matrix at `14b94a4`: GCC headless 809/809; Clang headless 809/809 with no warnings; Release 810/810;
desktop UI under Xvfb 836/836; pinned clang-format 20.1.8 over include, src, apps and tests: clean.

#### W1: merging phase A's review rounds (`2a613ff`, `d5e9350`)

Phase A's review fixes touched the same structurer. The merge needed three changes beyond the conflicts:

1. **The loop follow.** The goto structurer chose a loop's follow by a search from every body block for
   every exit, the cubic pattern the review found in the fallback. Phase A's test
   `Ir.ALoopWithManyReturnExitsChoosesItsFollowInBoundedTime` (2,000 exits) ran for more than eleven
   minutes on the merged tree before it was stopped. Both structurers now call one helper,
   `choose_loop_follow` (`ir_internal.h`), which labels each body block once with the non-return exits it
   reaches: the test takes 0.37 s. `Ir.LoopFollowChoiceMatchesTheSearchPerExit` compares the helper with
   the old search on 20,000 random graphs and bodies (two mutations of the helper, a reversed tie rule and
   a worklist that does not propagate, fail it at rounds 15 and 60).
2. **Phase A's flat early-return `if`** in the fallback printed its lines without the control-flow tags
   W1 adds, so the check refused every fallback candidate that used it, and the goto structurer printed
   those functions instead (`Ir.FallbackPrintsALoopExitToTheFollowAsBreak` and
   `Ir.FallbackCopiesASmallReturnBlockReachedTwice` failed). The flat form is tagged as an `if` without
   an else.
3. **An unreachable cycle** (`Ir.ACycleTheEntryDoesNotReachIsUnreachable`) is classified
   `GotoStructured` with the reason "unreachable block" on this branch (the goto structurer places such
   blocks after the reachable code); the verifier refuses such IR, so it is never printed.

The nesting bound is W1's recursion counter, which also bounds the indentation, with phase A's reason
text ("nesting deeper than 128 levels").

4. **Stack per nesting level.** Phase A's `Ir.NestedChainDeeperThanTheBoundPrintsLabelledOnASmallStack`
   (1,000 nested tests on a 512 KiB thread) crashed in the Clang Debug build of the merged tree: the
   layout structurer's `emit_range` frame was 4,104 bytes there (`-fstack-usage`), and 128 levels need
   525 KB. Its lines are now built by small helpers whose frames are gone before it recurses: 792
   bytes. The output is unchanged (libc's whole `decompile --json`, 63 MB, is byte-identical before and
   after), and the test passes under GCC and Clang.

#### W1: first review round on PR #59 (`cf4e6f5`, `6948cef`)

The control-flow check left four things unchecked. Each fix has a test that fails without it:

1. **Where the printed function starts, and where each test is.** Code that printed block 1 (a return)
   first and block 0 after it, jumping back, passed: every block's own edges were right. A switch with
   only a default arm, wrapped around the code before block 0 or between two blocks, passed too: its one
   arm reaches the right block. The first operation must now be the entry block's code, and every
   condition and switch must come right after the code of the block it tests
   (`Ir.ControlFlowCheckRefusesCodeThatDoesNotStartAtTheEntry`, `Ir.ControlFlowCheckRefusesATestThatNoBlockEndsIn`).
2. **The value each switch arm is entered for.** Only the set of arm targets was compared, so swapped
   case values passed. Each arm now carries its value, and every value is compared: each IR case (the
   last case with that value, as the evaluator takes it), each printed case the IR does not have (it
   must reach the IR's default), and the default (`Ir.ControlFlowCheckRefusesASwitchWhoseCaseValuesAreSwapped`).
3. **The switch selector.** Any `switch (...) {` passed; the text is now compared with the selector
   rendered from the dispatch block's operand (`Ir.ControlFlowCheckRefusesASwitchOnAnotherOperand`).
4. **Goto labels.** A goto was resolved from its tag, not from the label it prints. It now goes to the
   line that defines that label, the label must be on the tagged block, and a label printed twice is
   refused (`Ir.ControlFlowCheckFollowsTheLabelAGotoPrints`, `Ir.ControlFlowCheckRefusesALabelPrintedTwice`).

The label check found a bug in the goto structurer: a loop header that is not a pure test and is a
goto target printed its label twice, on the `while (1)` and on its marker, which is not valid C. The
label is now on the marker only (`Ir.ALoopHeaderThatAGotoNamesIsLabelledOnce`). Before the fix, 144 of the 1,986 sampled functions
printed a label twice (`ls` 15, `openssl` 22, `bash` 18, `libsqlite3` 24, `libc` 19, `git` 36,
`python3.12` 10). The goto
structurer also printed no test for a conditional branch whose two targets are the same block, which
the check refuses; it now prints an empty `if` (`Ir.ABranchWhoseTwoTargetsAreTheNextBlockKeepsItsTest`).
`sample_list.py` counted a structured function as labelled when a string literal quoted the note; the
class decides now, and without a class only the whole note line counts. A graph that nests deeper than
`kMaxStructureNesting` prints as labelled blocks, which `AGENTS.md`, `DESIGN.md` §17.2 and the ledger now
say.

Re-measurement on the fixed list at `6948cef`, and again with the test-placement rule: every count of
every binary is the same as before this round (0 labelled, 1,000 without goto, 986 with gotos, 16,232 gotos, largest 409, 0 candidates refused,
Complete 183, InvalidIR 0). The printed text of each sampled function was compared before and after:
it changed for exactly the 144 functions with a doubled label, none prints a label twice now, and no
sampled function prints the new empty `if`.

Decisions for the owner (not made here): (1) whether to copy small blocks (up to 4 statements) into each
arm that reaches them, which should remove much of the first goto group at a cost in output size; (2) whether
compound conditions (`a && b`) are recovered as one `if` with a combined condition, which needs a
multi-block condition in the tags and a check of its rendering; (3) whether 986 functions with gotos is
acceptable as the decompiler's state for irreducible and shared-join control flow until (1) or (2) is
decided.

### W2: call summaries (G21-T2, nested callees)

A direct call resolved only when its callee lifted Complete with its own calls left unresolved, so in
practice only calls to leaves resolved, and each call site lifted its callee twice more. A callee's own
calls now resolve the same way, bottom-up, through a `CallSummaryCache` that the command line and the
corpus share across the lifts of one image:

- A summary is the callee's System V parameters, its integer result, the registers it may change
  (with those its own resolved callees change) and its height: 1 for a leaf, else one more than its
  tallest resolved callee.
- A call resolves only to a callee of height 8 or less: the evaluator runs calls 8 levels deep
  (`kMaxCallDepth`), so it can run every call the lifter resolves.
- A call back into a function being lifted (recursion, direct or mutual) is not resolved.
- A summary is computed with a budget, one less at each level. A callee whose calls would go deeper
  than its budget is cut there, and the cut is kept with that budget: a later query with that budget
  or less is answered at once, and one with more budget computes it again. Keeping a cut without its
  budget would make a result depend on which function was lifted first
  (`Ir.ACutCalleeIsResolvedWhenALaterCallReachesItNearTheTop`, `Ir.CallSummariesDoNotDependOnLiftOrder`).

Tests, each failing on `main`: `Ir.ANonLeafCalleeIsResolvedWhenItsOwnCallsAre`,
`Ir.RegistersANestedCalleeWritesAreClobberedForTheCaller`,
`Ir.CallChainsDeeperThanTheEvaluatorRunsStayUnresolved`, and the corpus function `c_call_nested` (a
two-level chain), Partial on `main` at -O0, -O2 and -O3 and now Complete and verified against the
compiled code at all three. `Ir.ARecursiveCalleeStaysUnresolved` guards recursion.

Measured on the fixed list of 1,986 functions (before: `main` at `e26abbf`):

| Binary | Complete | call note |
|---|---|---|
| `ls` (186) | 14 → 14 | 118 → 118 |
| `openssl` (300) | 17 → 17 | 248 → 248 |
| `bash` (300) | 28 → 28 | 226 → 226 |
| `libsqlite3` (300) | 45 → 45 | 211 → 211 |
| `libc` (300) | 39 → 39 | 185 → 185 |
| `git` (300) | 15 → 15 | 269 → 269 |
| `python3.12` (300) | 25 → 26 | 234 → 232 |
| Total | 183 → 184 | 1,491 → 1,489 |

Labelled 0, functions with gotos 986 and refused candidates 0 are unchanged. Over the whole of `libc`,
3 functions go from Partial to Complete and none the other way. The gain is small because a callee that
makes a call usually also calls an import or calls through a register: it stays Partial, and so do its
callers. Imports (G22) and indirect calls (G21-T6) are what keeps the call note on most functions.

Time and memory of `donkey-cli decompile --json` on every function (Release build):

| Binary | `main` | this change |
|---|---|---|
| `bash` | 91.8 s, 247 MB | 28.8 s, 247 MB |
| `libc.so.6` | 161.9 s, 348 MB | 41.2 s, 348 MB |
| `ls` | 6.3 s, 32 MB | 2.6 s, 32 MB |

The speed-up comes from summarising each callee once per image instead of lifting it again at each
call site.


### Segment-relative memory (fs/gs) was lifted as absolute

The x86 decoder dropped Capstone's `mem.segment`, so an `fs:`- or `gs:`-relative operand looked like
an access to a fixed address. The stack-protector load `mov %fs:0x28,%rax` printed as
`rax = *(u64 *)(0x28);`, a data reference to address 0x28 was recorded, and thread-local accesses
(`errno`, the locale) were lifted as loads and stores of fixed addresses. `sigemptyset` in libc, for
example, printed `errno = EINVAL` (`movl $0x16, %fs:(%rax)`) as `*(u32 *)(rax) = 0x16;` and was
Complete.

Fix: `MemoryOperand::segment` keeps `fs` or `gs`. Such an operand gets no data reference, the
jump-table emulator gives it no address, and the lifter makes any instruction with one (`lea`
excepted: it ignores segments) Unsupported with the note "fs- or gs-relative memory (thread-local
storage) is not modelled". Tests: `Decode.X86FsRelativeOperandKeepsItsSegment`,
`Ir.FsRelativeLoadIsNotLiftedAsAnAbsoluteAddress`, `Ir.StackCanaryCheckStaysPartial`.

Measured on the fixed list of 1,986 functions (before: `main` at `ca53fcc`):

| Binary | Complete |
|---|---|
| `ls` (186) | 14 → 14 |
| `openssl` (300) | 17 → 17 |
| `bash` (300) | 28 → 28 |
| `libsqlite3` (300) | 45 → 45 |
| `libc` (300) | 39 → 34 |
| `git` (300) | 15 → 15 |
| `python3.12` (300) | 26 → 24 |
| Total | 184 → 177 |

The 7 functions that lost Complete were Complete with a wrong meaning: `sigemptyset`, `__sysctl`,
`__ns_name_unpack`, `iswupper` and `sub_144cc0` in libc, `sub_434942` and `sub_4311b6` in python3.12.
No function changed the other way. Modelling thread-local storage (an opaque thread block that the
evaluator reads and writes) would bring the canary checks and `errno` writes back; it is not done.
