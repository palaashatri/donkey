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
| ELF 32/64, LE/BE | headers, segments, sections | .symtab, .dynsym (ARM mapping symbols skipped) | DWARF 2-5, 32/64-bit; compressed sections and split DWARF reported Unsupported |
| PE32 / PE32+ | headers, sections (long names via COFF string table) | exports, imports, COFF symbols | MinGW-style DWARF in PE sections. PDB is not read. |
| Mach-O 32/64, universal | load commands, segments, slices | symtab | `__DWARF` sections when present. Apple keeps DWARF in .dSYM bundles, which are not read. |
| Raw | with explicit `--arch --base --entry` | — | — |

## C++ symbol names

| Scheme | Demangler | Checked against | Not covered (reported Unsupported, never guessed) |
|---|---|---|---|
| Itanium (`_Z`) | `demangle_itanium` (G10-T1, partial) | 502 of 512 `c++filt` corpus names match; 10 are Unsupported | expression template arguments, generic lambdas |
| MSVC (`?`, x64 `__cdecl`) | `demangle_msvc` (G10-T2, partial) | 87 of 95 `llvm-undname` corpus names match exactly; 8 are Unsupported | templates, arrays, string literals, vftables, dynamic initialisers, function and member pointers, 32-bit forms and other calling conventions |

`donkey-cli info` shows the demangled form of Itanium and MSVC exports (the `demangled` JSON field, and the name in brackets in the human output); the raw name is always kept. The desktop app and the symbol list do not show demangled names yet (G10-T4).

| Itanium RTTI and vtables (ELF) | Reader | Checked against | Not covered |
|---|---|---|---|
| x86-64, PIE and non-PIE | `read_itanium_rtti` (G10-T3, partial) | `gdb` on the non-PIE fixture: vtable slots, typeinfo bases and offsets-to-top match; the PIE build gives the same graph | AArch64 PLT stubs are not named (the reader reports `rtti.plt_unnamed`); AArch64 is checked one-off, not in CI; MSVC RTTI (Complete Object Locators) is not read; no call-site resolution in the decompiler |

## Instruction sets

| ISA | Decode (Capstone 5) | CFG, xrefs | Lifter / decompiler | Jump tables | Debugger |
|---|---|---|---|---|---|
| x86-64 | yes | yes | integer subset: see the corpus below | yes, absolute and PC-relative tables, including `sub`-based bounds checks | Linux, Windows |
| x86-32 | yes | yes | smaller subset (cdecl stack arguments are not recovered) | yes | no |
| AArch64 | yes | yes, with ADRP folding | integer subset: see the corpus below | no: reported as unresolved indirect branches | Linux |
| 32-bit ARM, RISC-V | decode or none | partial | Unsupported (reported, never guessed) | no | no |

## Decompiler corpus

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
| Apple Clang 17, arm64 macOS | CI macos-15 | 39/39 | 32/39 | 32/39 | not itemised |
| Clang 18.1, AArch64 Linux | locally, under qemu-aarch64 | 39/39 | 32/39 | 32/39 | SIMD, `ccmp` |
| llvm-mingw Clang 23, arm64 Windows | CI windows-11-arm (package job) | 38/39 | 32/39 | 32/39 | not itemised |

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
`ubfx`/`sbfx` and `mvn`. On x86 it also lifts `popcnt`, `tzcnt`, `lzcnt`,
`bswap`, `bt`, `bts`, `btr`, `btc` with a register destination, and `movbe`
with a register and a memory operand.

### Known unsupported classes

- Floating point and SIMD: vectorised loops are Partial.
- Calls: a function that calls is Partial. Its call is rendered, and the
  callee's effects on registers and memory are not modelled.
- `bsf`/`bsr` with a zero source: the destination is undefined there, and ZF is
  not modelled. They are lifted, and a function that uses them is Partial with a
  note. A guarded use such as `c_clz64_guarded` stays Partial until flags cross
  blocks (G02-T4).
- Memory forms of `bt`, `bts`, `btr` and `btc`: the bit can lie outside the
  operand, so they are Unsupported.
- x86 flags read across basic blocks, except into a fall-through block that has
  no other predecessor, where the compare that set them is repeated (G02-T4).
  Flags are not carried across blocks on AArch64, so an AArch64 `ccmp`/`ccmn`
  whose flags before are not exact is Partial.
- AArch64 jump tables; 32-bit ARM.
- Varargs and struct passing by value.

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
