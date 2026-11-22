# Support matrix

What Donkey does per platform and instruction set, and how it was
measured. A row is filled only from a test that ran. Results from
machines the author could not run are left for CI and marked as such.

## Platforms

## Goals 1 to 10 (branch `claude/funny-meitner-cpc7oc`, merged into `main` with this change)

What these tests prove, beyond the state of `main` at `1a92abf`.

- Unwind seeds: ELF `.eh_frame` FDEs (`EhFrame.*`, 13 tests, the fixture matches `readelf`) and PE
  x64 `.pdata` entries (`Pdata.*`, 4 tests, the fixture matches `llvm-readobj`). Both fuzzed
  (`fuzz_eh_frame`, `fuzz_pdata`, 60 s each, clean; `tests/fuzz/corpus/eh_frame` and
  `tests/fuzz/corpus/pdata`). Chained `.pdata` entries are skipped and not covered by a fixture.
- Mach-O `LC_FUNCTION_STARTS` (G23-T3): the linker's table of function starts seeds functions in a
  stripped image, marked `from_function_starts` (`FunctionStarts.*`, 5 tests, both stripped fixtures
  match `llvm-objdump --macho --function-starts`; `Analysis.MachOFunctionStartsSeedAStrippedBinary`,
  `cli.functions_marks_function_starts`). Fuzzed (`fuzz_function_starts`, 60 s, 10.4 million runs,
  clean; `tests/fuzz/corpus/function_starts`).
- Mach-O compact unwind, `__TEXT,__unwind_info` version 1 (G23-T3): regular and compressed
  second-level pages are read, and each entry's function seeds a function in a stripped image,
  marked `from_unwind` (`UnwindInfo.*`, 9 tests). Both stripped fixtures, linked without
  `LC_FUNCTION_STARTS`, match `llvm-objdump --macho --unwind-info` entry by entry and encoding by
  encoding. On the `LC_FUNCTION_STARTS` fixtures every entry is one of the table's starts.
  `Analysis.MachOUnwindInfoSeedsAStrippedBinary` and `cli.functions_marks_unwind_info` cover the
  analysis. Fuzzed (`fuzz_unwind_info`, 60 s, 12.7 million runs, clean;
  `tests/fuzz/corpus/unwind_info`). The linker folds adjacent functions with one encoding into one
  entry, so compact unwind names a subset of the starts. The encodings are kept and not
  interpreted; an entry with UNWIND_IS_NOT_FUNCTION_START (a range inside a function) is not a
  start. The personality array is bounds-checked and not read; the index's LSDA offsets are not
  read or checked.
- ELF initialisation and termination functions (G24): `DT_INIT`, `DT_FINI`, the entries of
  `DT_INIT_ARRAY`, `DT_FINI_ARRAY` and `DT_PREINIT_ARRAY` (and of the matching sections), and the
  starts of `.init` and `.fini` seed functions, marked `from_init_fini`. An array entry takes its
  `R_*_RELATIVE` addend when a relocation covers it, and an entry with a symbolic relocation is
  skipped. An entry seeds a function only when it is neither 0 nor -1 (the placeholders of
  `.ctors`-style arrays) and lies in executable code. An entry, relocation or tag that cannot be
  read leaves the analysis Partial (`analysis.init_fini_incomplete`) (`InitFini.*`,
  `Analysis.ElfInitAndFiniFunctionsAreSeeded`, `Analysis.AnUnnamedConstructorIsSeededFromInitArray`).
  Tested on 64-bit ELF (x86-64 and AArch64) and on a synthetic 32-bit image; 32-bit ELF programs
  (i386 `R_386_RELATIVE`, ARM `R_ARM_RELATIVE`) are not tested on real binaries. On the stripped R1 builds,
  the missed starts fell from 109 to 71:
  - every start of the glibc AArch64 builds is found;
  - each glibc x86-64 build still misses `register_tm_clones`, which `frame_dummy` reaches by a tail
    jump;
  - static musl still misses 65 assembly functions.
  The 3 extra starts of static musl are `_start`, `_init` and `_fini`. musl's assembly gives them
  NOTYPE symbols, which the FUNC-only ground truth does not count.
- Control flow: a function ends where its code jumps to, or falls through into, another function's
  start (not a call to the next instruction); jumps to named PLT import stubs are tail calls
  (`Cfg.*`), recorded as `TailCall` edges (`Cfg.JumpToAnotherFunctionIsATailCall`; a jump into
  code no function starts at stays a `Jump`). The CFG block bound is one block per decoded instruction, with a floor of 200,000
  (`Cfg.BlockBoundFollowsTheDecodedInstructionCount`). An indirect tail jump (`jmp rax`) is a call
  through its operand (`Ir.IndirectTailJumpCallsItsOperand`).
- Import stubs and thunks named (G24-T4): ELF stubs in `.plt` and `.plt.sec` (x86-64 and AArch64,
  BTI entries included) and in x86-64 `.plt.got` are functions named `<import>@plt`; the PLT0 header
  is not named. A `-fno-plt` call through a GLOB_DAT slot and a PE call through an IAT slot are
  named by the import, and a MinGW `jmp *slot` thunk is an import stub named by its import. The
  pseudocode prints such a call by the import's own name when that name is a C identifier
  (`abort();`, valid C); a name that is not (`foo.bar`) prints as before. The function list, call
  graph and xrefs use `abort@plt`. A stub for a function the image defines itself (`free@plt` in
  libc; the relocation's own dynamic symbol is defined) is named the same way but is not an
  import. A function that is only a jump to another function is a thunk named `j_<target>`.
  Tested on committed fixtures built from `tests/fixtures/stubs/stubs.c` (`Analysis.*Stub*`,
  `Analysis.*Thunk*`, `Analysis.GotCallIsNamedByItsImport`, `Analysis.PeIatCallIsNamedByItsImport`,
  `PltStubs.PltGotEntryIsNamedByItsGlobDatSlot`, `cli.*import_stubs*`,
  `cli.decompile_prints_import_calls_by_name`). Not done: AArch64 `.plt.got` entries, Mach-O stubs (no `__stubs` reader), PE
  delay-load imports, and imports by ordinal print as `ordinal_<n>`.
- No-return calls (G24-T3): a call to a name on the fixed list (`abort`, `exit`, `__stack_chk_fail`,
  `__assert_fail`, `longjmp`, `__cxa_throw`, `_Unwind_Resume`, `ExitProcess`, and the rest in
  `src/analysis/no_return.cpp`; not `error`) ends its path when the import is bound to a runtime library:
  on ELF by finding the libraries the dynamic loader would load, in its order (`ElfLoadScope`: ld.so.preload,
  DT_NEEDED breadth first, RPATH/RUNPATH/ld.so.conf/default directories, under `--sysroot`, plus `--library-path`)
  and binding each reference (its symbol version read by a bounded reader, `fuzz_elf_versions`) by glibc's lookup
  rules, and on PE by the import's DLL. An ELF shared library's references bind first in the global scope of
  the program that loads it, so its calls are marked only with that program (`--program`); without it they
  stay unmarked. Its local scope follows glibc's dlopen: a need the program already loaded is that object,
  the executable's DT_RPATH is searched, and DT_SYMBOLIC puts the library first (each checked against glibc's
  loader, `ElfLoadScope.ALibrarys*`, `ElfLoadScope.ASymbolicLibraryLooksItselfUpFirst`). `link` analyses
  each input with its executable as that program; its own import bindings and call reports come from the
  inputs it is given, and it prints no no-return marks. A library that cannot be found before the binding leaves the call
  unmarked (`analysis.no_return_unverified`, and the analysis is Partial). `functions --json` gives each mark
  its reason (`no_return_reason`); an ELF import mark names the bound library and the file it was found in,
  a PE import mark names its DLL. The ELF search models glibc's (`/etc/ld.so.cache`, inherited DT_RPATH,
  hardware-capability subdirectories) and does not read `LD_PRELOAD` or `LD_LIBRARY_PATH`; where it cannot know
  which file the loader takes, the call is not marked. A program whose interpreter is musl's loader
  (`ld-musl-x86_64.so.1`) is walked by musl's rules: its C library names (`libc.so`,
  `libc.musl-x86_64.so.1`, ...) are the loader itself, and other names are searched without the cache, in
  `/etc/ld-musl-x86_64.path` or `/lib`, `/usr/local/lib`, `/usr/lib`; a versioned reference under musl is not
  modelled (`ElfLoadScope.MuslGivesTheCLibraryNamesToItsLoader`, `ElfLoadScope.MuslWithoutItsLoaderBindsNothing`,
  `NoReturn.AMuslProgramsAbortBindsToTheLoader`; checked on Alpine 3.18's musl 1.2.4 sysroot, not on a musl
  system's own loader). Tested against the real loader's binding
  (`Analysis.AVersionedImportBoundToAnEarlierUnversionedDefinitionIsNotMarked`,
  `ElfLoadScope.FindsLibrariesInTheLoadersOrderAndBindsByGlibcRules`). Same-image functions whose
  every path ends in such a call, `ud2` or `hlt` are marked by propagation (8 rounds at most). The CFG gives
  the call no fall-through edge; the IR ends the block with an unreachable return that prints nothing; the
  evaluator stops at the call with `ir.eval_no_return`; a function with no returning path stays Partial.
  Tested: `ElfVersions.*`, `Analysis.*NoReturn*`, `Analysis.PropagationUsesOnlyProvenMarks`,
  `Cfg.NoReturnCallEndsTheBlock`, `Cfg.BytesReachedByAnotherPathStayInTheFunction`, `Ir.NoReturn*`,
  `Ir.ANoReturnBlockIsStructured`, `Ir.AFunctionWithNoReturningPathStaysPartial`,
  `cli.decompile_prints_no_return_call_without_return`, `cli.functions_list_no_return_evidence`. Not
  done: a same-image function is never marked by its name (libc's own `abort`); interposition
  (`LD_PRELOAD`) is assumed absent and recorded as such; AArch64 GOT calls are not bound.
- Calls (G21): a direct call to a same-image integer callee is resolved to its inferred arguments
  and result (x86-64 System V; Win64 (PE) calls with arguments stay Partial) when the callee lifts Complete,
  with its own calls resolved the same way up to 8 levels deep (G21-T2: call summaries computed bottom-up
  and cached per image; a recursive callee stays unresolved; corpus `c_call_nested`, a two-level chain,
  is verified at -O0, -O2 and -O3). A callee that reads a stack argument is not resolved,
  so its caller is Partial (`Ir.CallerOfAFunctionThatReadsAStackArgumentIsPartial`,
  `cli.decompile_stack_argument_caller_is_partial`). The clobber check and the callee write set are
  tested (`Ir.CallCarries*`, `Ir.CallerSaved*`, `Ir.DirectCallTo*`). Six call-heavy corpus functions
  (`c_call_*`) are Complete and verified at -O0, -O2, -O3 and -O3-x86-64-v2 (48 vectors each). The
  CLI test `cli.decompile_prints_call_arguments` shows a call with its arguments.
- C library calls (G21-T7): on x86-64 and AArch64, a call of an import shown to bind to the C library (the
  G24-T3 load scope on ELF, with `--program` for a shared library; a C runtime DLL on PE) to
  `strlen`, `strnlen`, `memchr`, `strchr`, `strrchr`, `strspn`, `strcspn`, `memcpy`, `memmove` or
  `memset` carries the function's prototype, and the interpreter runs an executable model of it.
  Every model is compared with the host C library on random inputs
  (`LibcModels.AgreeWithTheHostCLibrary`). Under GCC 13.3 on Linux x86-64, all 44 `c_lib_*`
  corpus results are Complete and verified (48 vectors each), `c_lib_memcpy_sum`'s zeroing `xor`
  after the call included. On AArch64 the arguments are in `x0`-`x2` (an `int` in `w0`-`w2`) and the
  result in `x0`, and the call clobbers every caller-saved register and `x30`; under GCC 13.3 on Linux
  AArch64 (`qemu-aarch64`), all 33 `c_lib_*` results (-O0, -O2, -O3) are Complete and verified.
  Not tested on Windows, macOS (Mach-O imports are not bound) or FreeBSD hosts.
- Calls that do not return (G21-T5): on x86-64 and AArch64, a call or tail call of an import bound to its
  runtime library as no-return (G24-T3) whose C prototype is fixed (`abort`, `__stack_chk_fail`,
  `__chk_fail`, `__cxa_rethrow`, `__cxa_bad_cast`, `__cxa_bad_typeid`, `std::terminate`, `exit`, `_exit`,
  `_Exit`, `quick_exit`, `__fortify_fail`, `__assert_fail`) carries the prototype's arguments and no
  result, ends its path, and no longer keeps its caller Partial. The paths that return are compared as
  before; a function with none stays Partial. Unit-tested from bytes on both architectures
  (`Ir.ACallOfStackChkFailEndsThePathAndLeavesTheCallerComplete`, `Ir.ACallOfExitCarriesItsStatus`,
  `Ir.ANoReturnCallWithoutAPrototypeStaysPartial`, `Ir.ANoReturnMarkGivenByTheCallerHasNoPrototype`).
  No corpus function calls one yet, so none is executed through such a call.
- Structuring (goal 8): a statement-printing bug in the conditional emitter is fixed (defect 5 in
  `docs/AUDIT.md`; the printed-statement guard is `DecompilerCorpus.EveryKeptStatementIsPrinted`).
  Post-dominators, a dominator-tree fallback structurer, bounded copies of return blocks and node
  splitting of irreducible functions (`Ir.*Fallback*`, `Ir.*PostDominator*`, `Ir.*Split*`).
- Measured on a fixed list of 1,986 system-binary functions (`tools/audit/`, `docs/AUDIT.md`): 0
  InvalidIR and 0 Unsupported, 177 Complete (8.9%; 184 before the fs/gs fix, 7 of them wrong); before G04-T5, 985 labelled (49.6%, under the 52% bar).
- Structuring (G04-T5): on the same 1,986 functions no function is printed as labelled
  blocks (985 before G04-T5). 1,073 print without a goto and 913 with gotos (13,758 in all, 15,712
  on `main` before W1b copied small blocks in place of gotos and printed two tests as one `&&` or `||`
  condition; the largest function has 385). Every printed
  structure is checked edge by edge against the IR before it is shown (no candidate was refused on the
  sample). The gotos are the open part: most go to a block that is already printed (shared joins and
  short-circuit conditions; `docs/AUDIT.md`, W1 and W1b).
- Not done: calls of imports beyond the ten C library models (Partial); calls to other images;
  Windows x64 calls with arguments; .xdata and ARM64
  unwind; structured output without gotos for the 913 functions that G04-T5 prints with gotos.

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
| Mach-O 32/64, universal | load commands (LC_UUID is read), segments, slices | symtab | `__DWARF` sections when present. A `.dSYM` bundle beside the executable is found by its UUID, and `donkey-cli debuginfo --debug-file` checks a named file the same way. Tested with `ld64.lld` and `llvm-dsymutil` output on Linux (`cli.debuginfo_dsym`, `SeparateDebug.DsymFindsTheBundleWhoseUuidMatches`); checked against Apple's `dsymutil` on macOS CI (`cli.debuginfo_json`) |
| ELF relocatable (`ET_REL`, `.o`) | laid out and linked as one image: x86-64 and AArch64 common relocations, GOT forms, COMMON symbols, x86-64 local-exec, initial-exec, global-dynamic and local-dynamic TLS, and AArch64 local-exec, initial-exec and TLSDESC (the dynamic sequences are relaxed to the static offsets as `ld` relaxes them, when the variable is defined in the object); AArch64 `-mtls-dialect=trad` DTPREL forms and the TP-relative load/store forms are reported, not applied | — | — |
| PDB 7.00 (`pdb.h`) | procedures and code sizes, global data, struct/class/union/enum names and sizes, the instance fields of complete structs with their offsets, pointers, arrays, const/volatile and procedures with their parameters, sections, modules, PDB GUID and age. Mapped into the type store (`types_from_pdb`) except enumerators and any struct with a base class, virtual table or method, which are reported and left out. Not line information | — | — |
| ELF core (`ET_CORE`) | threads with x86-64 registers, process name, file mappings (`donkey-cli core`); memory is the PT_LOAD segments | — | — |
| Windows minidump (`MDMP`) | architecture, exception, threads with x86-64 registers, modules with UTF-16 names, memory ranges read by address (`donkey-cli core`, `read_minidump_memory`). Checked against a generated file that follows Microsoft's documented layout; not yet against a dump written by Windows. Other architectures: threads without registers, reported partial | — | — |
| Raw | with explicit `--arch --base --entry` | — | — |

## Several images (`donkey-cli link`, `project link`)

| Feature | Done | Not done | Evidence |
|---|---|---|---|
| ELF import binding | Each import is bound to the first linked image, in link order, that exports its name and is a library the importer names (DT_NEEDED against DT_SONAME or file name). Unbound imports are counted and listed | PE and Mach-O bindings beyond the DLL name; ordinal imports; forwarded exports | `Link.*`, `cli.link_binds_imports_to_needed_libraries`, `cli.project_link_*` |
| ELF calls across images | Calls and jumps through a PLT stub (x86-64 and AArch64, including BTI stubs) and on x86-64 a call that reads a GOT slot directly (`call *slot(%rip)`, as `-fno-plt` code makes) are bound to the export. A function the image defines itself is never listed as an import | Calls through a register loaded from a GOT slot first; imports used as data pointers; AArch64 GOT calls; PE IAT and Mach-O stub calls | `LinkCalls.*`, `PltStubs*`, `GotSlots.*`, `cli.link_reports_calls_through_plt_stubs`, `cli.link_reports_calls_through_got_slots` |

The project does not store the cross-image results: `project link` recomputes them from the saved
files, and refuses a file whose SHA-256 has changed.

## C++ symbol names

| Scheme | Demangler | Checked against | Not covered (reported Unsupported, never guessed) |
|---|---|---|---|
| Itanium (`_Z`) | `demangle_itanium` (G10-T1, partial) | 502 of 512 `c++filt` corpus names match; 10 are Unsupported | expression template arguments, generic lambdas |
| MSVC (`?`, x64 `__cdecl`) | `demangle_msvc` (G10-T2, partial) | 87 of 95 `llvm-undname` corpus names match exactly; 8 are Unsupported | templates, arrays, string literals, vftables, dynamic initialisers, function and member pointers, 32-bit forms and other calling conventions |

`donkey-cli info` shows the demangled form of Itanium and MSVC exports (the `demangled` JSON field, and the name in brackets in the human output); the raw name is always kept. The desktop app shows the readable form of a function's symbol in the Functions list, the call graph, the disassembly call-target column, the decompiler header and the debugger's stack frames, with the raw symbol as a tooltip (`ui.script_readable_names`, on the hierarchy fixture). The decompiler's pseudocode body keeps the symbols as C identifiers. Its Classes window lists the Itanium classes of an ELF image with their direct bases, vtable address and slot count (`ui.script_classes`); other images show why they have no RTTI. MSVC RTTI is not read (G10-T4 partial).

| MSVC RTTI and vtables (x64 PE) | `read_msvc_rtti` (G10-T3, partial) | The x64 fixture `tests/fixtures/rtti/msvc/hierarchy.exe` (clang 18 for the MSVC target, linked with LLD; see its PROVENANCE.md). The class names, the direct bases (a three-level chain, so an indirect base is not listed), the vtable groups and the slot counts are checked against the source (`RttiMsvc.*`). The COL-to-vtable reference is checked against the file bytes | 32-bit MSVC; virtual base classes (the vbtable); class names that are templates or use special characters (reported, not shown); the names of the slots (no PDB symbols); call sites through a vtable |

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
| MIPS32 (little- and big-endian) | yes; matches llvm-objdump on both byte orders of the test image (23 instructions each). The CFG keeps each branch's, call's and return's delay slot in its block, and the fall-through starts after it (`DecodeIsa.MipsDelaySlotsStayWithTheirBranchesInTheGraph`). Branch-likely forms (`beql` and kin) run their slot only when taken, which is not modelled: the graph is Partial with `analysis.mips_branch_likely`. microMIPS and MIPS16 images (their e_flags) are refused as Unknown with `elf.mips_isa_extension`; they are not read as MIPS32. 64-bit MIPS is decoded in its 64-bit mode and matches llvm-objdump on the test image (27 instructions, the padding excluded) | yes for the test image, with no unmodelled branch form; not checked against another disassembler's CFG | Unsupported (`lift.unsupported_architecture`) | no | no |
| PowerPC32 (big- and little-endian) | yes; matches llvm-objdump on both byte orders of the test image (25 instructions each). VLE (variable-length) code is not detected and is read as 32-bit PowerPC. 64-bit PowerPC is decoded in its 64-bit mode and matches llvm-objdump on the test image (31 instructions) | not measured | Unsupported (`lift.unsupported_architecture`) | no | no |

## Real programs (R1, G20)

R1 is the reference corpus of real programs (`tools/r1/README.md`): zlib 1.3.1, Lua 5.4.7 and SQLite 3.46.1,
built by `tools/r1/build.cmake` on Ubuntu 24.04 with GCC 13.3 and the distribution defaults. There are 13
builds, at -O0 and -O2, for x86-64 and AArch64, plus a static `lua` linked with musl 1.2.4; each is also kept
as a stripped copy. Every function was decompiled, not a sample, with `tools/r1/decompile.cmake`
(`donkey-cli decompile --json --no-pseudocode`), and counted with `donkey-r1 measure` (G20-T2). The decompiler
was that of `main` at `3530b46` (after the init and fini seeds of G24 and the Mach-O header fix); the change that
adds the measurement adds JSON fields only. The AArch64 counts and the table below are measured again with AArch64
call resolution (G21-T1/T2 for AAPCS64), then with the C library models on AArch64 (G21-T7 for AAPCS64); the
x86-64 counts and the starts did not change. The AArch64 builds are decompiled with `--sysroot
/usr/aarch64-linux-gnu`, the glibc they were linked against (Ubuntu's `libc6-arm64-cross`, named in
`tools/r1/r1.json`), so their imports bind as that system's loader would bind them (G24-T3).

These are counted results, not verified ones: a Complete function here has not been executed. The execution
comparison on R1 is G20-T4.

No run stopped at an analysis limit (`measure` refuses such an output, which may miss functions). The analysis
of every `libz.so` build is Partial for one reason, `analysis.no_return_unverified`: which library an import binds
to, and so whether it returns, cannot be shown for a shared library without the program that loads it (G24-T3).
Before the AArch64 builds were given their sysroot, their analysis was Partial for the same reason. That diagnostic leaves
function discovery whole. `measure` marks a binary whose analysis gave any other diagnostic (an unreadable
`.eh_frame`, `.pdata`, start table or init array, for example) as one whose starts may be missing; no R1 binary
is marked.

The counts are ratcheted (G20-T3). `tools/r1/baseline.json` records, for each binary, Complete, Unsupported,
InvalidIR, errors and the missed starts of the stripped copies. The `r1` CI job measures R1 again on every push
and pull request. It fails when any of these gets worse than the base commit's baseline (`R1Ratchet.*`, and
`tools/r1/ci-check.sh` on both of its paths, run locally).

Unstripped builds, totals:

- x86-64: 1,273 of 8,406 functions are Complete (15.1%). It was 1,269 before calls of no-return imports
  stopped keeping their callers Partial (G21-T5).
- AArch64: 1,182 of 7,450 functions are Complete (15.9%). It was 839 (11.3%) before AArch64 calls to
  same-image callees resolved (G21-T1/T2 for AAPCS64, measured on `main` at `c655bdf` with that change),
  1,086 (14.6%) before the C library models applied on AArch64 (G21-T7 for AAPCS64), and 1,130 (15.2%)
  before G21-T5.
- No function is Unsupported or InvalidIR, and no run failed.
- Every Partial function of an unstripped build names at least one reason. One Partial function of the stripped
  static musl build names none.

Stripped builds, against the function symbols of their unstripped twins (`STT_FUNC` and `STT_GNU_IFUNC`):

- 14,816 of 14,887 starts are found.
- The 71 missed starts:
  - each glibc x86-64 build misses `register_tm_clones`, which `frame_dummy` reaches by a tail jump (6 builds);
  - the glibc AArch64 builds miss none;
  - static musl misses 65 assembly functions that have no unwind entry.
- 966 further starts found are import stubs (`.plt`, `.plt.sec`, `.plt.got`), which have no symbol.
- 3 extra starts are found, all in static musl: `_start`, `_init` and `_fini`, whose symbols musl's assembly
  makes `NOTYPE`, so the `FUNC`-only ground truth does not count them.

| Binary | Functions | Complete | Partial | Unsupported or InvalidIR | Partial, no reason | Starts found (stripped) |
|---|---|---|---|---|---|---|
| `libz-x86_64-glibc-O0.so` | 207 | 58 | 149 | 0 | 0 |  |
| `libz-x86_64-glibc-O0.so.stripped` | 206 | 58 | 148 | 0 | 0 | 157 of 158 (1 missed; 49 stubs, 0 extra) |
| `libz-x86_64-glibc-O2.so` | 185 | 40 | 145 | 0 | 0 |  |
| `libz-x86_64-glibc-O2.so.stripped` | 184 | 40 | 144 | 0 | 0 | 135 of 136 (1 missed; 49 stubs, 0 extra) |
| `libz-aarch64-glibc-O0.so` | 208 | 58 | 150 | 0 | 0 |  |
| `libz-aarch64-glibc-O0.so.stripped` | 208 | 58 | 150 | 0 | 0 | 159 of 159 (0 missed; 49 stubs, 0 extra) |
| `libz-aarch64-glibc-O2.so` | 186 | 31 | 155 | 0 | 0 |  |
| `libz-aarch64-glibc-O2.so.stripped` | 186 | 31 | 155 | 0 | 0 | 137 of 137 (0 missed; 49 stubs, 0 extra) |
| `lua-x86_64-glibc-O0` | 1178 | 174 | 1004 | 0 | 0 |  |
| `lua-x86_64-glibc-O0.stripped` | 1177 | 174 | 1003 | 0 | 0 | 1086 of 1087 (1 missed; 91 stubs, 0 extra) |
| `lua-x86_64-glibc-O2` | 794 | 77 | 717 | 0 | 0 |  |
| `lua-x86_64-glibc-O2.stripped` | 793 | 77 | 716 | 0 | 0 | 703 of 704 (1 missed; 90 stubs, 0 extra) |
| `lua-aarch64-glibc-O0` | 1180 | 191 | 989 | 0 | 0 |  |
| `lua-aarch64-glibc-O0.stripped` | 1180 | 191 | 989 | 0 | 0 | 1088 of 1088 (0 missed; 92 stubs, 0 extra) |
| `lua-aarch64-glibc-O2` | 790 | 60 | 730 | 0 | 0 |  |
| `lua-aarch64-glibc-O2.stripped` | 790 | 60 | 730 | 0 | 0 | 699 of 699 (0 missed; 91 stubs, 0 extra) |
| `lua-static-musl-x86_64-musl-O2` | 988 | 125 | 863 | 0 | 0 |  |
| `lua-static-musl-x86_64-musl-O2.stripped` | 923 | 113 | 810 | 0 | 1 | 920 of 985 (65 missed; 0 stubs, 3 extra) |
| `sqlite3-x86_64-glibc-O0` | 3067 | 587 | 2480 | 0 | 0 |  |
| `sqlite3-x86_64-glibc-O0.stripped` | 3066 | 587 | 2479 | 0 | 0 | 2974 of 2975 (1 missed; 92 stubs, 0 extra) |
| `sqlite3-x86_64-glibc-O2` | 1987 | 212 | 1775 | 0 | 0 |  |
| `sqlite3-x86_64-glibc-O2.stripped` | 1986 | 212 | 1774 | 0 | 0 | 1893 of 1894 (1 missed; 93 stubs, 0 extra) |
| `sqlite3-aarch64-glibc-O0` | 3097 | 649 | 2448 | 0 | 0 |  |
| `sqlite3-aarch64-glibc-O0.stripped` | 3097 | 649 | 2448 | 0 | 0 | 2987 of 2987 (0 missed; 110 stubs, 0 extra) |
| `sqlite3-aarch64-glibc-O2` | 1989 | 193 | 1796 | 0 | 0 |  |
| `sqlite3-aarch64-glibc-O2.stripped` | 1989 | 193 | 1796 | 0 | 0 | 1878 of 1878 (0 missed; 111 stubs, 0 extra) |

The 20 most frequent first reasons of Partial functions, over the unstripped builds. A reason is the first
note that is not one every function carries; when the lifter gave none, it is the first instruction that was
not lifted.

| Partial functions | First reason |
|---|---|
| 9382 | outgoing call arguments and return values follow no modelled ABI |
| 1883 | jump leaves the function; treated as a tail call |
| 1646 | fs- or gs-relative memory (thread-local storage) is not modelled |
| 147 | the returned register is not determined by the definitions that reach the return; rax is assumed |
| 103 | the returned register is not determined by the definitions that reach the return; x0 is assumed |
| 62 | floating-point results assume the MXCSR rounding mode is round to nearest; a caller may set another mode, which is not modelled |
| 33 | floating-point results assume the FPCR rounding mode is round to nearest; a caller may set another mode, which is not modelled |
| 20 | conditional branch depends on flags this lifter does not model |
| 19 | both x0 and v0 are written on a path to this return; which one carries the return value is not determined, so x0 is assumed |
| 19 | conditional branch depends on flags not set by a modelled cmp/tst/subs/ands in the same block |
| 15 | no path returns: every path ends in a call that does not return, so nothing is compared |
| 15 | unsupported instruction 'syscall' |
| 12 | both rax and xmm0 are written on a path to this return; which one carries the return value is not determined, so rax is assumed |
| 11 | unsupported instruction 'ldurb' |
| 7 | conditional select depends on flags not set by a modelled cmp/tst/subs/ands in the same block |
| 4 | a return does not see the entry x30, so it may not return to the caller |
| 2 | bsf and bsr with a zero source leave the destination undefined; that case is not modelled |
| 2 | integer and floating-point parameters are both present; their order in the source is not recoverable from the registers, so the signature is Partial |
| 2 | unsupported instruction 'ldurh' |
| 2 | unsupported instruction 'movdqa' |

### Call census (G21)

`decompile --json` lists each call it left without arguments and a result, with the kind of its target, and
`donkey-r1 measure` counts them (`R1.CountsUnresolvedCalls`, `cli.decompile_json_lists_unresolved_calls`,
`cli.decompile_json_lists_aarch64_calls`, `cli.decompile_json_lists_aarch64_tail_calls`,
`Ir.UnresolvedTailCallsAreInTheCallCensus`). A tail call (a jump to another function, conditional or not)
is a call site too; the jump of an import stub through its own slot is not. The kinds:

- `import`: a direct call of an import stub with no C library model or library prototype (a stub of a
  function the image defines itself, such as libc's `free@plt`, is `same_image`);
- `import_slot`: a call through an import's GOT or IAT slot;
- `same_image`: a direct call of a function of the image whose call summary did not resolve (it is Partial,
  reads a stack argument, is on a cycle, or is deeper than eight levels);
- `indirect`: a call through a register or memory that is no import slot;
- `unknown_target`: a direct call of an address that is no function;
- on AArch64, `aarch64_import` for an unresolved call of an import stub with no C library model, and `aarch64_other` for any other unresolved call (a same-image callee whose summary did not
  resolve, for the reasons above, or a call through a register).

A Partial function counts as Partial only because of calls when every specific reason it gives comes from an
unresolved call: the call note, a tail call's note, or the clobber check's read of a register after a call that
does not define it. Measured with AArch64 calls resolved (G21-T1/T2 for AAPCS64) and the C library models on AArch64 (G21-T7 for
AAPCS64), with the AArch64 sysroot. Before AArch64 calls resolved, on the same bytes and without the sysroot,
4,452 functions were Partial only because of calls, 2,471 of them AArch64; with them, 4,310.

Unresolved calls by kind of target (unstripped binaries):

| Calls | Kind of target |
|---|---|
| 31616 | same_image |
| 31614 | aarch64_other |
| 1787 | aarch64_import |
| 1765 | indirect |
| 1686 | import |
| 4 | import_slot |
| 1 | unknown_target |

4727 Partial functions have an unresolved call as their only reason. By the kinds of target they call:

| Functions | Kinds of target |
|---|---|
| 2394 | aarch64_other |
| 1584 | same_image |
| 276 | aarch64_import+aarch64_other |
| 122 | import+same_image |
| 116 | indirect+same_image |
| 81 | aarch64_import |
| 68 | import |
| 59 | indirect |
| 19 | import+indirect |
| 8 | import+indirect+same_image |

The 20 imports those functions call most (a function counted once per import):

| Functions | Import |
|---|---|
| 74 | `strcmp` |
| 67 | `memcmp` |
| 64 | `__errno_location` |
| 52 | `__ctype_b_loc` |
| 47 | `memcpy` |
| 38 | `free` |
| 24 | `fflush` |
| 23 | `malloc` |
| 22 | `fopen64` |
| 20 | `memset` |
| 20 | `strerror` |
| 17 | `fwrite` |
| 16 | `fclose` |
| 16 | `fread` |
| 16 | `getenv` |
| 15 | `realloc` |
| 12 | `fprintf` |
| 12 | `strncmp` |
| 11 | `__fprintf_chk` |
| 11 | `lseek64` |

With the AArch64 sysroot, the no-return imports of the AArch64 builds bind (G24-T3): their blocks end at the
call, which turns 483 more functions into ones Partial only because of calls (4,793), and Complete is unchanged.
The C library models on AArch64 then make 44 more functions Complete and leave 4,780. Calls of no-return
imports with a fixed prototype (`__stack_chk_fail`, `abort`, `exit`, `__assert_fail` and the like, G21-T5) no
longer keep their callers Partial: 56 more functions are Complete, and 4,727 are left. 2,751 are AArch64: 2,394
call only functions of the image whose summaries do not resolve, because a callee is Partial for a reason of its
own, and 357 call an import. 1,976 are x86-64: 1,584 call only a same-image callee that does not resolve, and
the rest call an unresolved import or through a register.

## Decompiler corpus

Loop structuring (G04-T3, partial): a loop whose body is one block that repeats
itself is printed as `do { ... } while (...)`, and a branch to the next block is a
fall-through. A function with an early return therefore prints an if/else around the
loop instead of labelled blocks with `goto`. Not done: the `for (init; cond; step)`
form (a bottom-tested loop cannot be rewritten into it without a proof from the entry
guard). `break` and `continue` are done. Shapes the structurer does not recognise are
printed with `goto` for the edges that have no structured form (G04-T5), with a note
that counts them; a structured function with no goto has no note. The printed control
flow of every corpus function is checked against the IR (`DecompilerCorpus.EveryPrintedFunctionPassesTheControlFlowCheck`).

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
Results at -O0 on x86-64, GCC 13.3: 6 of 26 Complete, none wrong. The other 20 are Partial. Every scalar SSE arithmetic operation and every integer-to-float conversion depends on the MXCSR rounding mode. The caller may set a mode other than round to nearest, and this lifter does not model MXCSR, so each function that rounds is Partial with that assumption written in its notes (review of #39). Before this rule the count was 18 of 26: three functions copied a register with `movapd`, and five wrote both `rax` and `xmm0` on a path to the return, which the return rule now keeps Partial. Every Partial function is still compared with the compiled code on all 48 vectors.
Clang 18.1 at -O0 (the FreeBSD job builds the corpus with clang): 6 of 26 Complete, none wrong, checked by the same test on the clang-built corpus. The count reaches 6 because the lifter models both 64-bit lanes of an XMM register (`xmm0` and `xmm0_hi`) for `movaps`/`movapd`, the packed logical operations (`andps`/`andpd`/`andnps`/`andnpd`/`orps`/`orpd`/`xorps`/`xorpd`/`pxor`), the zeroing idioms and the memory loads; it lowers `cmpltsd` as a masked select with the flags it does not keep; and it carries `ucomisd`/`comisd` with a memory operand across a block boundary when nothing after the compare touches memory.

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
| GCC 13.3, AArch64 Linux | locally, on `main` at `c655bdf` (77 functions: the integer corpus with the call and C library sections), under qemu-aarch64 | 58/77 | 56/77 | 51/77 | every `c_call_*` and `c_lib_*` function (calls are not resolved on AArch64), SIMD (`cnt`, `movi`, `dup`) |
| GCC 13.3, AArch64 Linux | locally, after G21-T1/T2 for AAPCS64 (77 functions), under qemu-aarch64 | 65/77 | 62/77 | 57/77 | every `c_lib_*` function (no C library model applies on AArch64 yet), SIMD (`cnt`, `movi`, `dup`); every `c_call_*` function is Complete and verified at every level |
| GCC 13.3, AArch64 Linux | locally, after G21-T7 for AAPCS64 (77 functions), under qemu-aarch64 | 76/77 | 73/77 | 68/77 | SIMD (`cnt`, `movi`, `dup`); `c_store_pair`, `c_fill` and `c_point_move` Partial at -O2 (agree); every `c_call_*` and `c_lib_*` function is Complete and verified at every level |
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
and `adds`, `adc`/`sbc` and `adcs`/`sbcs` when the flags before them are exact (`adc`/`sbc`
without S do not write NZCV, so several of them in a block read the same carry; the carry out
of `adcs`/`sbcs` is modelled as their NZCV). On
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
  and vector forms, `movaps`/`movapd` and the packed logical operations (both lanes are modelled), other packed forms, x87,
  `fcvtzu` (the IR has no unsigned float-to-integer conversion), and the negated
  fused forms `fnmadd`/`fnmsub`. An XMM register is modelled as two 64-bit lanes (`xmm0` and
  `xmm0_hi`): scalar instructions write the low lane, and `movaps`/`movapd`, the packed logical
  operations, the zeroing idioms and the memory loads write both lanes. The scalar view of a
  SIMD&FP register is modelled on AArch64. The IR's IEEE operations are tested against
  native execution (G01-T1).
- Calls: a function that calls is Partial. Its call is rendered, and the
  callee's effects on registers and memory are not modelled.
- `bsf`/`bsr`: the result is undefined for a zero source, so they are
  Unsupported until a zero-flag state exists.
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
| Conditional hardware watchpoints (`set_conditional_watchpoint`, `--watch-if`) | yes: a hit stops only where `<operand> <op> <value>` holds, evaluated after the access; a passed-over hit is not counted (`NativeDebug.ConditionalWatchpoint*`, `cli.debug_native_watch_if_json`). Not done: more than one comparison, a condition on a register of another thread | not implemented | not implemented | Unsupported |
| Conditional software breakpoints (`set_conditional_breakpoint`, `--break-if`) | yes (`NativeDebug.Conditional*`) | yes (`NativeDebug.Conditional*` ran on `ubuntu-24.04-arm` in CI, run 42468469673) | not implemented | Unsupported |
| Hardware watchpoints in the GUI | not yet | not yet | not yet | not yet |

## Library function signatures (G09)

| Capability | Status | Evidence |
|---|---|---|
| Generate a set from x86-64 ELF relocatable objects and static archives (`donkey-cli sig make`) | Done for functions with a size, global, weak and local. Shared objects, PE import libraries and AArch64 are not read | `SignatureGen.*`, `cli.sig_make_*`, `fuzz_sig_object` |
| Match a set against a binary (`identify_functions`, `identify_at_starts`) | Library API only: no CLI command matches a set yet. Byte-identical aliases are reported ambiguous and named nothing | `Signatures.*`, `SignatureGen.AMatchInTheLinkedProgram*` |
| Shipped signature sets | musl 1.2.4 (`signatures/musl-1.2.4.json`, MIT). On a static musl program, 34 of 67 known functions are named, 28 are ambiguous aliases, 5 are not matched, and none is named wrongly | `Signatures.IdentifyMuslFunctionsInAStaticBinary` |

## Automation

| Surface | Status | Notes |
|---|---|---|
| `donkey-cli serve` (JSON-RPC 2.0, `donkey.rpc.v1`, stdin and stdout) | Implemented (G11-T1) | Read methods `hello`, `open`, `info`, `functions`, `strings`, `xrefs`, `disasm`, `callgraph`, `decompile`, and `annotations.list` (with `--project`), and the write methods `rename`, `comment` and `type.apply` (with `--project` and `--allow-write`) are tested (`cli.serve_session`, `cli.serve_project`) and fuzzed (`fuzz_rpc`). See `docs/RPC.md` |
| `donkey-cli batch <script.json>` | Implemented | Runs a JSON array of the same requests in one session (`cli.batch_script`) |
| `donkey-cli project local-name` / `local-names` and `decompile --project` (local names, G12-T3) | Partial | Names a parameter (`arg:<index>`) or a frame slot (`frame:<base>:<offset>`) in a project, lists them, and shows them in the decompiler output (`cli.local_names`). A slot the decompiler did not recover gets a local from its accesses. The desktop decompiler shows names set through the session API (undoable); there is no GUI gesture that sets them yet. Not done: register locals, local types, the definition address in the key, `serve` methods and the GUI rename gesture |
| Python client (`bindings/python`, optional) | Partial | Typed wrappers for the implemented methods, tested against the built tool (`python.rpc_client`) |

## UI

Command palette (Ctrl/Cmd+Shift+P, G17-T1): the commands the menus run and a Show command per view, filtered by the words typed; a disabled command is listed but does not run. Checked by `ui.script_command_palette`.

Search window (G17-T2): byte patterns with `??` wildcards, an immediate number (decimal or 0x hex) and an ECMAScript regular expression over each instruction's "mnemonic operands" text. Searches run in the background, keep the newest result, cap the hits at 10,000 and can be cancelled. An immediate search reads every number in the operand text, so a displacement or an address can match as well. Checked by `search.*` (core) and `ui.script_search`.

Symbols window (G17-T3): every symbol of the image with its kind, binding and size, the readable name of each (raw name as the tooltip), and a case-insensitive word filter. Checked by `ui.script_symbols`.

Xref Graph window (G17-T4): the call neighbourhood of the selected function, callers on the left and callees on the right, one column per call depth (1 or 2), at most 64 functions. Built from the analysis's direct calls only: indirect calls are not drawn. Clicking a node navigates to it. Checked by `ui.script_xref_graph` against the CLI's call graph. Not yet: the theme editor and synchronised views (G17).

Covered by the scripted UI tests (`docs/UI_TESTING.md`) on every platform
whose package job runs them: keyboard-only navigation, IME commit and
composition, focus changes, display-scale changes, display removal (where
the window manager allows an off-screen window), graphics device loss and
recreation, layout persistence, and a 1,000,000-row virtualised table. On
FreeBSD aarch64, whose CI VM is emulated, timing limits are not enforced and
the two timing-only scripts (1,000,000-row table, input latency under load)
are not run.
Screen readers are not supported: Dear ImGui exposes no accessibility tree.

Data ranges (G12-T2, partial): `A` defines a NUL-terminated byte string, `W` a NUL-terminated
UTF-16LE string (both as data of their bytes, terminator included), and `Shift+D` an array. The
Data window lists and previews them. Covered by the scripted tests `data` and `utf16`. Not done:
the listing draws no data rows, and the decompiler does not print string literals.

## Type libraries (G22)

| What | Status | Evidence | Not done |
|---|---|---|---|
| Format and reader (T1) | Done | `TypeLib.*`, `fuzz_typelib` | |
| Generator (T2) | Done for musl | `TypeLibMake.*`, `cli.typelib_show_musl`; `tools/typelib/make-musl.sh` regenerates `typelibs/musl-1.2.4-x86_64-linux.dtl` byte for byte with `CREATED=2026-11-18`, `musl-dev` 1.2.4-2 and GCC 13.3.0 (checked on Ubuntu 24.04 x86-64 on 2026-11-20 by regenerating and comparing with the committed file using `cmp`) | FreeBSD and MinGW-w64 libraries; `.winmd`; function pointers (40 of the 223 musl declarations listed as skipped are refused for a parenthesised declarator, `pthread_create` among them; the others include variables, function definitions, names declared again, `__builtin_va_list` users, `_Complex` types, arrays without a size and what depends on them; the library lists every skipped declaration with its reason) |
| Applying a library to code (T3) | Done for import stubs of ELF x86-64 programs whose imports bind to a file the library provides (musl programs), and of PE x64 images (tested with a Win64 test library) | `TypeLib.AppliesALibraryPrototypeToAnImportedName` (a musl-linked fixture), `TypeLib.AppliesAWin64LibraryToPeImportThunks` (the MinGW fixture's msvcrt thunks), `TypeLib.ALibraryDoesNotApplyToAnotherCLibrary`, `TypeLib.AnUnshownProviderAppliesNothing`, `TypeLib.AUserPrototypeWinsOverTheLibraryInBothOrders`, `TypeLib.ALoadStoresItsTypesAndRecordTogether`, `TypeLibApply.*`, `cli.project_type_library_*`, `cli.decompile_notes_a_library_prototype`; on six Alpine 3.18 programs (musl 1.2.4) 727 of 2,428 stubs get a musl prototype, and on the seven glibc audit binaries none does (their imports bind to `libc.so.6`) | calls take a prototype's arguments only in the T4 subset below (x86-64 System V, through a stub, integer and pointer arguments); GOT/IAT calls without a stub; ordinal imports not seen on a fixture; Mach-O refused (its stubs are not bound); a library for glibc; no desktop UI |
| Typed arguments at calls (T4) | Partial: x86-64 System V calls through an import stub that a library prototype applies to, up to six integer, enum and pointer arguments and the result | `TypeLibApply.RegisterPrototypeFollowsTypedefs`, `Ir.APrototypeWithoutASourceIsNotUsed`, `Ir.LibraryPrototypeSuppliesTheArgumentsOfAnImportCall`, `Ir.VariadicPrototypeLeavesTheCallPartial`, `Ir.UnreadArgumentRegisterWriteIsReportedAsAPossibleMismatch`, `Ir.ArgumentRegisterWithinThePrototypeIsNotAMismatch`, `Ir.CallerReadOfAnArgumentRegisterIsNotAnExtraArgument`, `Ir.APeCallTakesNoLibraryPrototype`, `Ir.APrototypeWithANonIntegerParameterIsNotUsed`, `Ir.VerifierAcceptsLibraryArgumentsAndRefusesUnsourcedOnes`, `cli.decompile_prints_library_call_arguments` (the musl program); 14,656 calls in 3,795 of 13,407 functions of six Alpine 3.18 (musl 1.2.4) programs, with 80 possible-mismatch notes | the caller stays Partial (an import is not executed); a call with an executable C library model (G21-T7) is run instead; GOT calls without a stub, AArch64, Windows x64, floating-point, struct and stack arguments (a seventh integer parameter); a variadic call's extra arguments |
