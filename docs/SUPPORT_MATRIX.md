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

## Instruction sets

| ISA | Decode (Capstone 5) | CFG, xrefs | Lifter / decompiler | Jump tables | Debugger |
|---|---|---|---|---|---|
| x86-64 | yes | yes | integer subset: see the corpus below | yes, absolute and PC-relative tables, including `sub`-based bounds checks | Linux, Windows |
| x86-32 | yes | yes | smaller subset (cdecl stack arguments are not recovered) | yes | no |
| AArch64 | yes | yes, with ADRP folding | integer subset: see the corpus below | no: reported as unresolved indirect branches | Linux |
| 32-bit ARM, RISC-V | decode or none | partial | Unsupported (reported, never guessed) | no | no |

## Decompiler corpus

`tests/corpus/corpus.c` has 39 integer functions: arithmetic, branches,
loops, arrays, structs, dense and sparse switches, stack arguments and
narrow types. The test suite builds it at -O0, -O2 and -O3 with the host's C
compiler. `DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode` lifts
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
| GCC 13.3, x86-64 Linux | CI ubuntu-24.04 | 39/39 | 38/39 | 32/39 | SIMD vectorisation |
| Clang 18.1, x86-64 Linux | locally | 39/39 | 33/39 | 33/39 | SIMD, `adc` |
| MinGW-w64 GCC 14.2, x64 Windows | CI windows-2022 | 39/39 | 36/39 | 30/39 | not itemised |
| GCC 13.3, AArch64 Linux | CI ubuntu-24.04-arm | 39/39 | 36/39 | 30/39 | SIMD, `ccmp` |
| Apple Clang 17, arm64 macOS | CI macos-15 | 39/39 | 32/39 | 32/39 | not itemised |
| Clang 18.1, AArch64 Linux | locally, under qemu-aarch64 | 39/39 | 32/39 | 32/39 | SIMD, `ccmp` |
| llvm-mingw Clang, arm64 Windows | CI windows-11-arm (package job) | pending | pending | pending | |

On every row, no Complete result disagrees with the compiled code.

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
`ubfx`/`sbfx` and `mvn`.

### Known unsupported classes

- Floating point and SIMD: vectorised loops are Partial.
- Calls' effects on registers and memory: functions that call are
  rendered, but the oracle does not evaluate them.
- `adc`/`sbb`, double-width `mul`/`imul`/`div`.
- Flags read across basic blocks; AArch64 `ccmp`/`ccmn`.
- AArch64 jump tables; 32-bit ARM.
- Varargs and struct passing by value.

## UI

Covered by the scripted UI tests (`docs/UI_TESTING.md`) on every platform
whose package job runs them: keyboard-only navigation, IME commit and
composition, focus changes, display-scale changes, display removal (where
the window manager allows an off-screen window), graphics device loss and
recreation, layout persistence, and a 1,000,000-row virtualised table.
Screen readers are not supported: Dear ImGui exposes no accessibility tree.
