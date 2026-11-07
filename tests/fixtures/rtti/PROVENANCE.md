# RTTI and vtable fixture (G10-T3)

`hierarchy.cpp` is written for this repository. It is built by `tests/CMakeLists.txt` as two
executables with the same source: `donkey_test_hierarchy` (PIE, `-fPIE -pie`) and
`donkey_test_hierarchy_nopie` (`-fno-pie -no-pie`). Both keep their symbols.

The expected names, slots and addresses in `tests/unit/rtti_test.cpp` were read with `gdb`
on the non-PIE build (`x/Na` of each `_ZTV`, `_ZTI` and `_ZTS` symbol, and `info symbol`).
Tools: GCC 13.3 (Ubuntu 24.04, x86-64), GDB 15.

Checked beyond CI, one-off, with the same reader on an AArch64 build of the same source
(`aarch64-linux-gnu-g++` 13, PIE and non-PIE): the PIE graph matches the x86-64 graph exactly,
including `__cxa_pure_virtual`. The AArch64 non-PIE build reports `rtti.plt_unnamed` (partial)
for its pure-virtual slot, because AArch64 PLT stubs are not decoded yet (G10-T3 follow-up).
AArch64 is not run in CI.

Fuzzing: `fuzz/fuzz_rtti.cpp` ran 105,055 inputs in 91 seconds under ASan/UBSan, seeded with
the fixture binaries, with no finding.

Compiler differences: Clang 18 (the `clang-headless` build) fills the two destructor slots of
the abstract `Shape` with `Shape::~Shape()`, where GCC leaves them null. The test accepts either
for those two slots; the rest of the hierarchy is identical, and the whole suite passes with
both compilers.

`hierarchy-aarch64-nopie` and `hierarchy-aarch64-pie` are the AArch64 builds of the same source:
`aarch64-linux-gnu-g++` (GCC 13.3.0) with `-O0 -g0 -fno-stack-protector`, `-fno-pie -no-pie` and
`-fPIE -pie` respectively. They keep their symbols. The graph and slot names are the same
expectations as the x86-64 builds; the pure-virtual slot is named `__cxa_pure_virtual` through
the PLT stub `adrp x16; ldr x17, [x16, #0x30]; add x16, x16, #0x30; br x17`, whose JUMP_SLOT
relocation `aarch64-linux-gnu-readelf -r` shows.

