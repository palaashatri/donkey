# Mach-O and .dSYM fixture (G07-T2)

`dbg.c` is written for this repository: an `add` function and a `main` that calls it.

- `dbg`: a 64-bit Mach-O executable, x86-64, with its DWARF removed, as `dsymutil` leaves it. Built
  with `clang --target=x86_64-apple-macos13 -g -O0 -c dbg.c -o dbg.o` (clang 18.1.3) and
  `ld64.lld-18 -arch x86_64 -platform_version macos 13.0.0 13.0.0 -e _main -o dbg dbg.o`
  (LLD 18.1.3). It has no libSystem, so it is not runnable on macOS; it exists to be read.
- `dbg.dSYM/Contents/Resources/DWARF/dbg`: the DWARF of `dbg`, made by
  `dsymutil -o dbg.dSYM dbg` (LLVM 18.1.3). It is a Mach-O file with the same LC_UUID as `dbg`,
  `4C4C4427-5555-3144-A16F-211E69EACDE5`. The bundle's Info.plist and relocation files are not
  committed; the reader does not use them.

This was produced on Linux with the LLVM tools, so it has not been checked against Apple's
`dsymutil` or a macOS host. The reader's tests run on every platform; the macOS CI should add a
case that builds the same source with Apple clang and `dsymutil`.
