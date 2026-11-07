# Support matrix

What Donkey does per platform and instruction set, and how it was
measured. A row is filled only from a test that ran. Results from
machines the author could not run are left for CI and marked as such.

## Platforms

| Platform | Packages | Desktop app | CLI | Native debugger |
|---|---|---|---|---|
| Linux x86_64 | .deb .rpm .tar.gz | yes | yes | yes (ptrace) |
| Linux arm64 | .deb .rpm .tar.gz | yes | yes | yes (ptrace) |
| macOS arm64 (11+) | .dmg .zip | yes | yes | no |
| Windows x86_64 | setup .exe, .zip | yes | yes | yes (Win32 debug API) |
| Windows arm64 | setup .exe, .zip | yes | yes | no |
| FreeBSD amd64 / aarch64 | .pkg .tar.gz | yes (X11) | yes | no |

Package installation, running and removal are checked by
`.github/workflows/package.yml`: Ubuntu 22.04/24.04, Debian 12, Fedora 41 and
Arch Linux (x86_64 only) for Linux; NSIS silent install/uninstall on
Windows; DMG mount and `lipo`/`codesign` checks on macOS; `pkg add`/`pkg
delete` on FreeBSD. Where a platform has no native debugger, the debugger
panel and `donkey-cli debug` say so; nothing is simulated.

## Formats

| Format | Read | Symbols | DWARF |
|---|---|---|---|
| ELF 32/64, LE/BE | headers, segments, sections | .symtab, .dynsym (ARM mapping symbols skipped) | DWARF 2-5, 32/64-bit; zlib- and zstd-compressed sections read (`inflate` and `zstd_decompress`, checked against zlib and the zstd library); split DWARF reported Unsupported; separate debug files found by build-id or debuglink |
| PE32 / PE32+ | headers, sections (long names via COFF string table) | exports, imports, COFF symbols | MinGW-style DWARF in PE sections. PDB files are read separately (PDB row). |
| Mach-O 32/64, universal | load commands (LC_UUID is read), segments, slices | symtab | `__DWARF` sections when present. A `.dSYM` bundle beside the executable is found by its UUID, and `donkey-cli debuginfo --debug-file` checks a named file the same way. Tested with `ld64.lld` and `llvm-dsymutil` output on Linux (`cli.debuginfo_dsym`, `SeparateDebug.DsymFindsTheBundleWhoseUuidMatches`); not yet checked against Apple's `dsymutil` on macOS |
| ELF relocatable (`ET_REL`, `.o`) | laid out and linked as one image: x86-64 and AArch64 common relocations, GOT forms, COMMON symbols, x86-64 local-exec, initial-exec, global-dynamic and local-dynamic TLS, and AArch64 local-exec, initial-exec and TLSDESC (the dynamic sequences are relaxed to the static offsets as `ld` relaxes them, when the variable is defined in the object); AArch64 `-mtls-dialect=trad` DTPREL forms and the TP-relative load/store forms are reported, not applied | — | — |
| PDB 7.00 (`pdb.h`) | procedures and code sizes, global data, struct/class/union/enum names and sizes, the instance fields of complete structs with their offsets, pointers, arrays, const/volatile and procedures with their parameters, sections, modules, PDB GUID and age. Mapped into the type store (`types_from_pdb`) except enumerators and any struct with a base class, virtual table or method, which are reported and left out. Not line information | — | — |
| ELF core (`ET_CORE`) | threads with x86-64 registers, process name, file mappings (`donkey-cli core`); memory is the PT_LOAD segments | — | — |
| Windows minidump (`MDMP`) | architecture, exception, threads with x86-64 registers, modules with UTF-16 names, memory ranges read by address (`donkey-cli core`, `read_minidump_memory`). Checked against a generated file that follows Microsoft's documented layout; not yet against a dump written by Windows. Other architectures: threads without registers, reported partial | — | — |
| Raw | with explicit `--arch --base --entry` | — | — |

## C++ symbol names

| Scheme | Demangler | Checked against | Not covered (reported Unsupported, never guessed) |
|---|---|---|---|
| Itanium (`_Z`) | `demangle_itanium` (G10-T1, partial) | 502 of 512 `c++filt` corpus names match; 10 are Unsupported | expression template arguments, generic lambdas |
| MSVC (`?`, x64 `__cdecl`) | `demangle_msvc` (G10-T2, partial) | 87 of 95 `llvm-undname` corpus names match exactly; 8 are Unsupported | templates, arrays, string literals, vftables, dynamic initialisers, function and member pointers, 32-bit forms and other calling conventions |

`donkey-cli info` shows the demangled form of Itanium and MSVC exports (the `demangled` JSON field, and the name in brackets in the human output); the raw name is always kept. The desktop app and the symbol list do not show demangled names yet (G10-T4).

| Itanium RTTI and vtables (ELF) | Reader | Checked against | Not covered |
|---|---|---|---|
| x86-64 and AArch64, PIE and non-PIE | `read_itanium_rtti` (G10-T3, partial) | `gdb` on the x86-64 non-PIE fixture: vtable slots, typeinfo bases and offsets-to-top match; the PIE build gives the same graph. AArch64 builds of the same source (`aarch64-linux-gnu-g++`, PIE and non-PIE) give the same graph and name the pure-virtual slot through its PLT stub | Only the 16-byte PLT entry form is decoded for AArch64 (a BTI-prefixed entry stays unnamed and reports `rtti.plt_unnamed`); AArch64 is not run in CI; MSVC RTTI (Complete Object Locators) is not read; no call-site resolution in the decompiler |

## Instruction sets

| ISA | Decode (Capstone 5) | CFG, xrefs | Lifter / decompiler | Jump tables | Debugger |
|---|---|---|---|---|---|
| x86-64 | yes | yes | integer subset and scalar SSE (`ss`/`sd`): see the corpora below | yes, absolute and PC-relative tables, including `sub`-based bounds checks | Linux, Windows |
| x86-32 | yes | yes | smaller subset (cdecl stack arguments are not recovered) | yes | no |
| AArch64 | yes | yes, with ADRP folding | integer subset and scalar floating point (`s` and `d` registers): see the corpora below | yes for the GCC and Clang forms; other shapes are reported as unresolved indirect branches | Linux |
| 32-bit ARM (A32 only) | yes, little-endian; matches llvm-objdump on the test image (55 instructions). Thumb is not decoded or detected, so Thumb code is read as A32 and gives wrong results | not measured | Unsupported (`lift.unsupported_architecture`) | no | no |
| RISC-V 64 (RV64GC) | yes, little-endian; matches llvm-objdump on the test image (56 instructions, compressed included) | not measured | Unsupported (`lift.unsupported_architecture`) | no | no |
| MIPS32 (little- and big-endian) | yes; matches llvm-objdump on both byte orders of the test image (23 instructions each). Branch delay slots are not modelled, so the CFG may drop a delay slot that follows an unconditional branch. microMIPS and MIPS16 are not detected and are read as MIPS32. 64-bit MIPS is Unknown | Partial: analysis reports `analysis.mips_delay_slots` because delay slots are not modelled | Unsupported (`lift.unsupported_architecture`) | no | no |
| PowerPC32 (big- and little-endian) | yes; matches llvm-objdump on both byte orders of the test image (25 instructions each). VLE (variable-length) code is not detected and is read as 32-bit PowerPC. 64-bit PowerPC is Unknown | not measured | Unsupported (`lift.unsupported_architecture`) | no | no |

## Decompiler corpus

Loop structuring (G04-T3, partial): a loop whose body is one block that repeats
itself is printed as `do { ... } while (...)`, and a branch to the next block is a
fall-through. A function with an early return therefore prints an if/else around the
loop instead of labelled blocks with `goto`. Not done: the `for (init; cond; step)`
form (a bottom-tested loop cannot be rewritten into it without a proof from the entry
guard), `break`, `continue`, and the integer comparison simplification. Shapes the
structurer does not recognise keep the labelled-block form.

`tests/corpus/corpus.c` has 59 integer functions: arithmetic, branches,
loops, arrays, structs, dense and sparse switches, stack arguments, narrow
types, carry-propagating 128-bit arithmetic (`adc`, `sbb`), double-width
multiply and divide (`mul`, `imul`, `div`, `idiv`), and bit operations
(population count, guarded bit scans, byte swap, bit test and bit set, reset
and complement, `movbe`). The test suite builds it at -O0, -O2 and -O3 with
the host's C compiler, and on x86-64 hosts also at -O3 with
`-march=x86-64-v2` (which adds POPCNT). `DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode` lifts
every function from the built library and runs the IR in an interpreter on
48 input vectors. It calls the compiled function itself with the same inputs
and compares return values and memory written through pointers.

A function the decompiler reports **Complete** that computes anything
different fails the test. **Partial** results are run too and recorded. The
full outcome table is `tests/decompiler-corpus-report.json` in the build
tree.

`tests/corpus/jump_table.c` is a separate library, so the counts above stay as
they are. It has one function, `jt_dispatch16`, a 16-case switch built at -O2
whose cases compute from the second argument (a case that returns a constant
becomes a lookup, not a jump). `DecompilerCorpus.JumpTableFixtureAgreesWithTheCompiledCode`
requires it to lift Complete and agree with the compiled code on all 48 vectors.
On GCC it is built without hot/cold partitioning, see the known limitations.

`tests/corpus/corpus_fp.c` is a third library, on x86-64 and AArch64 hosts: 26 scalar
floating-point functions, each `double f(double, double, double, double)`, built
at -O0 with `-fno-math-errno -ffp-contract=off` so that `sqrt` is one instruction.
Its arguments arrive in xmm0 to xmm3, which the IR reads as parameters. It covers
arithmetic, comparisons that select a value, `int`/`double` and `float`/`double`
conversions, single-precision arithmetic, loops over a local array, and branches.
`DecompilerCorpus.FloatResultsAgreeWithTheCompiledCode` compares every Complete
result with the compiled code on 48 vectors. NaN equals NaN; otherwise the bits
must match, so the sign of a zero is checked. Partial functions are not compared.
Results at -O0 on x86-64, GCC 13.3: 6 of 26 Complete, none wrong. The other 20 are Partial. Every scalar SSE arithmetic operation and every integer-to-float conversion depends on the MXCSR rounding mode. The caller may set a mode other than round to nearest, and this lifter does not model MXCSR, so each function that rounds is Partial with that assumption written in its notes (review of #39). Before this rule the count was 18 of 26: three functions copied a register with `movapd`, whose upper lanes are not modelled, and five wrote both `rax` and `xmm0` on a path to the return, which the return rule now keeps Partial. Every Partial function is still compared with the compiled code on all 48 vectors. Clang 18.1, measured on the same corpus after the rule: 5 of 26 Complete, none wrong (before the rule: 23 of 26). The corpus test requires at least 5 with either compiler.

On AArch64, GCC 13.3 at -O0 gives 20 of 26 Complete, none wrong, run under
qemu-aarch64 against the native AArch64 code (48 vectors each). The six Partial functions
(`fp_truncate_int`, `fp_scale_by_int`, `fp_sum_array`, `fp_dot3`, `fp_loop_reduce`,
`fp_int_quotient`) write both `x0` and `v0` on a path to the return, the same ambiguity
rule as on x86-64. Before that rule the count was 26 of 26. CI runs the same test on
`ubuntu-24.04-arm` and `macos-15`; Apple Clang is not yet measured.

Each cell counts functions reported **Complete** whose IR, run in the
interpreter, agreed with the compiled code on all 48 vectors. CI prints the
counts in each job's "Decompiler corpus results" step. Partial causes are
listed where the per-function report was read.

| Compiler, target | Where measured | -O0 | -O2 | -O3 | Partial causes |
|---|---|---|---|---|---|
| GCC 13.3, x86-64 Linux | CI ubuntu-24.04 (before G02-T1, 39 functions) | 39/39 | 38/39 | 32/39 | SIMD vectorisation |
| GCC 13.3, x86-64 Linux | locally, after G02-T1 (42 functions) | 42/42 | 41/42 | 35/42 | SIMD vectorisation |
| GCC 13.3, x86-64 Linux | locally, after G02-T2 (53 functions) | 53/53 | 52/53 | 46/53 | SIMD vectorisation |
| GCC 13.3, x86-64 Linux | locally, after G02-T3 (59 functions) | 57/59 | 56/59 | 50/59 | SIMD vectorisation, calls to `__popcountdi2` (no `-mpopcnt`), `bsr` |
| GCC 13.3, x86-64 Linux, `-march=x86-64-v2` | locally, after G02-T3 (59 functions) | not built | not built | 51/59 | SIMD vectorisation, `bsr`; `c_switch_sparse` Partial (cause not itemised); `c_popcount` Complete |
| GCC 13.3, x86-64 Linux | locally, after G02-T4 (59 functions) | 57/59 | 57/59 | 51/59 | the causes above, not re-itemised; one more function is Complete at O2 and O3 (cross-block flags) |
| GCC 13.3, x86-64 Linux, `-march=x86-64-v2` | locally, after G02-T4 (59 functions) | not built | not built | 52/59 | the causes above, not re-itemised; one more function is Complete (cross-block flags) |
| Clang 18.1, x86-64 Linux | locally (before G02-T1, 39 functions) | 39/39 | 33/39 | 33/39 | SIMD, `adc` |
| Clang 18.1, x86-64 Linux | locally, after G02-T1 (42 functions) | 42/42 | 37/42 | 37/42 | SIMD vectorisation |
| Clang 18.1, x86-64 Linux | locally, after G02-T2 (53 functions) | 53/53 | 48/53 | 48/53 | SIMD vectorisation |
| Clang 18.1, x86-64 Linux | locally, after G02-T3 (59 functions) | 58/59 | 53/59 | 53/59 | SIMD vectorisation, `bsr` |
| Clang 18.1, x86-64 Linux, `-march=x86-64-v2` | locally, after G02-T3 (59 functions) | not built | not built | 52/59 | SIMD vectorisation, `bsr`, `shld` (`c_rotl5`, not lifted) |
| MinGW-w64 GCC 14.2, x64 Windows | CI windows-2022 | 39/39 | 36/39 | 30/39 | not itemised |
| GCC 13.3, AArch64 Linux | CI ubuntu-24.04-arm | 39/39 | 36/39 | 30/39 | SIMD, `ccmp` |
| GCC 13.3, AArch64 Linux | locally, after G02-T1 (42 functions), under qemu-aarch64 | 40/42 | 36/42 | 30/42 | SIMD, `ccmp`, `adc`/`sbc`/`cmn` (not lifted yet) |
| GCC 13.3, AArch64 Linux | locally, after G02-T2 (53 functions), under qemu-aarch64 | 40/53 | 36/53 | 30/53 | SIMD, `ccmp`, `adc`/`sbc`/`cmn`, `umulh`/`smulh`, `udiv`/`sdiv` (not lifted yet) |
| GCC 13.3, AArch64 Linux | locally, after G03-T2 (59 functions), under qemu-aarch64 | 52/59 | 48/59 | 42/59 | SIMD, `ccmp`/`ccmn` (G03-T1), `cmn`/`adc`/`sbc` (G03-T4; `sdiv`/`srem` need `cmn`), `fmov`/`ldr d` (popcount) |
| GCC 13.3, AArch64 Linux | locally, after G03-T1 (59 functions), under qemu-aarch64 | 52/59 | 54/59 | 48/59 | SIMD (`movi`, `dup`, `fmov`, `ldr d`), `cmn`/`adc`/`sbc` (G03-T4; `sdiv`/`srem` need `cmn`), `c_switch_sparse` Partial (cause not itemised) |
| GCC 13.3, AArch64 Linux | locally, after G03-T4 (59 functions), under qemu-aarch64 | 58/59 | 57/59 | 51/59 | SIMD (`ldr d`, `fmov`, `movi`, `dup`); `c_switch_sparse` Partial at O2 and O3 (agrees; cause not itemised) |
| GCC 13.3, AArch64 Linux | locally, after G03-T3 (59 functions), under qemu-aarch64 | 58/59 | 57/59 | 51/59 | the same as after G03-T4: SIMD (`ldr d`, `fmov`, `movi`, `dup`); `c_switch_sparse` Partial at O2 and O3 (agrees; cause not itemised) |
| GCC 13.3, AArch64 Linux | locally, after G03-T4 with `adcs`/`sbcs` and cross-block flags (59 functions), under qemu-aarch64 | 58/59 | 58/59 | 52/59 | SIMD and FP only (`ldr d`, `fmov`, `movi`, `dup`); `c_switch_sparse` is Complete and verified at O0, O2 and O3 |
| Clang 18.1, AArch64 Linux | locally, after G03-T3 (59 functions), under qemu-aarch64 | 56/59 | 52/59 | 52/59 | SIMD and FP register moves (`fmov`, `movi`, `mov v`), `umull` (not lifted) |
| Clang 18.1, AArch64 Linux | locally, after G03-T2 widening multiply (59 functions), under qemu-aarch64 | 56/59 | 53/59 | 53/59 | SIMD and FP register moves (`fmov`, `movi`, `mov v`) only |
| Clang 18.1, AArch64 Linux | locally, after G03-T4 with `adcs`/`sbcs` and cross-block flags (59 functions), under qemu-aarch64 | 56/59 | 53/59 | 53/59 | the same as after G02-T2: SIMD and FP register moves (`fmov`, `movi`, `mov v`); `c_switch_sparse` is Complete on both |
| Apple Clang 17, arm64 macOS | CI macos-15 | 39/39 | 32/39 | 32/39 | not itemised |
| Clang 18.1, AArch64 Linux | locally, under qemu-aarch64 | 39/39 | 32/39 | 32/39 | SIMD, `ccmp` |
| llvm-mingw Clang 23, arm64 Windows | CI windows-11-arm (package job) | 38/39 | 32/39 | 32/39 | not itemised |

Floating-point results that round (AArch64 `fadd`, `fsub`, `fmul`, `fdiv`, `fsqrt`, `fmadd`, `fmsub`, `scvtf`, `ucvtf` and narrowing `fcvt`) depend on the FPCR rounding mode, which the caller may set. Those functions are Partial, with the assumption written in their notes. A row above is current only if it was measured after that rule. The rows with a CI or local measurement before the rule are kept as measured; CI re-measures on every run, and the local rows are not re-measured here.

On every row, no Complete result disagrees with the compiled code.

The passes that run after lifting (signature inference and pointer-structure
recovery) are checked separately. `DecompilerCorpus.EveryPassPreservesSemantics`
interprets the IR before and after each pass on all 48 vectors, for every
function at every level, and requires identical results. These passes only
annotate the function, so the table above does not change.

### Fixed by this corpus

Each of these was reported **Complete** and computed the wrong value:

- three-operand `imul` lost its immediate
- `js`/`jns`/`jo`/`jno` were unmapped
- AArch64 `sxtb` read the whole register, and extended operands lost
  their extension

Since fixing them, the lifter also models `neg`, `not`, sign-widening
(`cdqe` and friends), rotates, `cmov`/`setcc`, and exact flags after
arithmetic on x86. On AArch64 it tracks NZCV within a block: a branch or
conditional select is exact when the block's last flag writer is `cmp`,
`tst`, `subs` or `ands`, and Partial otherwise. It also models the `csel`
family, register-offset addressing, `ldpsw`, `ror`, `ubfiz`/`sbfiz`/
`ubfx`/`sbfx` and `mvn`. It also lifts `udiv`/`sdiv` with the architecture's
results (division by zero gives 0, and `INT_MIN / -1` gives `INT_MIN`, with no
fault), `umulh`/`smulh`, `clz`, `cls`, `rbit`, `rev`/`rev16`/`rev32`, `extr`,
`bfi` and `bfxil`, `umull`, `smull`, `umaddl`, `smaddl`, `umsubl`, `smsubl`, `umnegl`
and `smnegl` (each 32-bit source is extended to 64 bits first), `ccmp`/`ccmn`, `cmn`
and `adds`, `adc`/`sbc` and `adcs`/`sbcs` when the flags
before them are exact (a second carry reader in a block needs its own flag
writer, since the carry out of `adc`/`sbc` is not modelled). On
x86 it also lifts `popcnt`, `tzcnt`, `lzcnt`,
`bswap`, `bt`, `bts`, `btr`, `btc` with a register destination, and `movbe`
with a register and a memory operand.

Jump tables are recovered on x86-64 and AArch64 from the bounds check and the
table bytes, and the decompiler shows a `switch`. On AArch64 the bounds check
is a `cmp` directly before a `b.cond`, and the path must follow its in-range
side. Two forms are recognised: GCC's (`b.ls` into the table, byte offsets read
with `ldrb` and applied with `add ... sxtb #2`) and Clang's (`b.hi` falling
into the table, `uxtb ... lsl #2`). Each entry must be a code address that
starts an instruction; one bad entry leaves the whole table unresolved. The
switch selects on a copy of the compared register taken right after the
compare, because GCC's table code overwrites `x0`.

### Known unsupported classes

- Floating point and SIMD: scalar `ss`/`sd` arithmetic, moves, conversions and
  comparisons are lifted on x86-64 (G01-T2) and the scalar `s`/`d` forms on AArch64
  (G01-T3), including the fused `fmadd`/`fmsub`. Anything else is Partial: packed
  and vector forms, `movaps`/`movapd` (their upper lanes are not modelled), x87,
  `fcvtzu` (the IR has no unsigned float-to-integer conversion), and the negated
  fused forms `fnmadd`/`fnmsub`. Only the low lane of an XMM register or the scalar
  view of a SIMD&FP register is modelled. The IR's IEEE operations are tested against
  native execution (G01-T1).
- Calls: a function that calls is Partial. Its call is rendered, and the
  callee's effects on registers and memory are not modelled.
- `bsf`/`bsr` with a zero source: the destination is undefined there, and ZF is
  not modelled. They are lifted, and a function that uses them is Partial with a
  note. A guarded use such as `c_clz64_guarded` stays Partial until flags cross
  blocks (G02-T4).
- Memory forms of `bt`, `bts`, `btr` and `btc`: the bit can lie outside the
  operand, so they are Unsupported.
- Flags read across basic blocks, except into a fall-through block with one
  predecessor: there the cmp or test that set them is repeated (G02-T4 on x86-64,
  G03-T4 on AArch64). Any other flag writer is not repeated, so a branch on its
  flags in another block stays Partial. An AArch64 `ccmp`/`ccmn` whose flags before
  are not exact is Partial.
- AArch64 jump tables outside the GCC and Clang forms above; 32-bit ARM.
- Functions with a cold block below their entry (GCC's -O2 hot/cold split can
  place the default path there on x86-64). The lifter keeps blocks in address
  order and the verifier starts from the first one, so the IR is rejected
  (`ir.unreachable_block`) and the function is never shown as Complete.
- Varargs and struct passing by value.

## Debugger

| Capability | Linux x86-64 | Linux AArch64 | Windows x64 | Other |
|---|---|---|---|---|
| Software breakpoints, stepping, memory and registers | yes (ptrace) | yes (ptrace) | yes (Win32 debug API) | Unsupported |
| Hardware watchpoints (`set_watchpoint`, library API) | yes: up to four write or read-or-write watches of 1, 2, 4 or 8 bytes (DR0-DR3, DR7), set while stopped | not implemented (DBGWVR) | not implemented | Unsupported |
| Hardware watchpoints in the CLI (`donkey-cli debug launch --watch`) | yes (`cli.debug_native_watch_json`) | not implemented | not implemented | Unsupported |
| Hardware watchpoints in the GUI | not yet | not yet | not yet | not yet |

## Automation

| Surface | Status | Notes |
|---|---|---|
| `donkey-cli serve` (JSON-RPC 2.0, `donkey.rpc.v1`, stdin and stdout) | Implemented (G11-T1) | Read methods `hello`, `open`, `info`, `functions`, `strings`, `xrefs`, `disasm`, `callgraph`, `decompile`, and `annotations.list` (with `--project`), and the write methods `rename`, `comment` and `type.apply` (with `--project` and `--allow-write`) are tested (`cli.serve_session`, `cli.serve_project`) and fuzzed (`fuzz_rpc`). See `docs/RPC.md` |
| `donkey-cli batch <script.json>` | Implemented | Runs a JSON array of the same requests in one session (`cli.batch_script`) |
| Python client (`bindings/python`, optional) | Partial | Typed wrappers for the implemented methods, tested against the built tool (`python.rpc_client`) |

## UI

Covered by the scripted UI tests (`docs/UI_TESTING.md`) on every platform
whose package job runs them: keyboard-only navigation, IME commit and
composition, focus changes, display-scale changes, display removal (where
the window manager allows an off-screen window), graphics device loss and
recreation, layout persistence, and a 1,000,000-row virtualised table. On
FreeBSD aarch64, whose CI VM is emulated, timing limits are not enforced and
the two timing-only scripts (1,000,000-row table, input latency under load)
are not run.
Screen readers are not supported: Dear ImGui exposes no accessibility tree.
