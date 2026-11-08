# MSVC demangler corpus (G10-T2)

These fixtures test `demangle_msvc` (`src/binary/demangle_msvc.cpp`).

| File | What it is | Origin |
|---|---|---|
| `names.cpp` | C++ sources covering namespaces, classes, constructors and destructors, operators, storage classes, cv-qualified members, references, pointers and builtin types | Written for this repository; no standard library headers |
| `make_pairs.sh` | Regenerates the two files below from `names.cpp` | Written for this repository |
| `msvc-pairs.txt` | Mangled symbol, tab, expected text, for every symbol in the object | Generated: `llvm-undname` output (line 2) for each symbol `clang++ --target=x86_64-pc-windows-msvc` emitted |
| `msvc-unsupported.txt` | Symbols the demangler must reject as `demangle.unsupported` | Listed by hand from the names the grammar does not cover |

Tools that produced the expected text: Ubuntu clang 18.1.3 (`clang++`, target
`x86_64-pc-windows-msvc`, `-fno-exceptions -fno-rtti`) and `llvm-undname` from LLVM 18.1.3
(Ubuntu package `llvm-18`). LLVM is Apache-2.0 with the LLVM exception; it is used here as a
test oracle only, and no LLVM demangler code is vendored or copied.

The expected text is `llvm-undname`'s spelling (for example `public: static int __cdecl
ns::Box::count(void)`), which is what the demangler prints. The names are the object's
symbols, not MSVC-produced binaries: MSVC itself was not used.

To regenerate: `sh tests/fixtures/msvc/make_pairs.sh` (needs clang and llvm-nm/llvm-undname).
