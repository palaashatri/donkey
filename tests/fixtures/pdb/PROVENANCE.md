# PDB fixture (G06)

`sample.c` is written for this repository: a struct, a global, a static function and an
entry point, freestanding.

- Object: `clang --target=x86_64-pc-windows-msvc -g -gcodeview -O0 -fno-stack-protector
  -ffreestanding -c sample.c` (Ubuntu clang 18.1.3), run in this directory. The object's
  module path is recorded as `/home/user/donkey/tests/fixtures/pdb/sample.obj` (clang writes
  the absolute path into the debug information).
- Image and PDB: `lld-link /debug:full /entry:sample_entry /subsystem:console /nodefaultlib
  /out:sample.exe sample.obj` (LLD 18.1.3). The PDB is `sample.pdb`. Its GUID differs from
  build to build; the test reads the value from this file.

The oracles are `llvm-pdbutil` 18.1.3 (`dump -summary`, `-modules`, `-symbols`, `-globals`,
`-publics`, `-types`) on `sample.pdb`, and `llvm-objdump -d` on `sample.exe`.

Where they disagree, the executable is the ground truth. `llvm-pdbutil -symbols` prints
`addr = 0001:0080` for `scale`, but the record bytes hold offset 0x50, and the call from
`sample_entry` (`callq 0x140001050`) and the function's code at that address confirm RVA 0x1050
(the function starts on a 16-byte boundary after `sample_entry`'s 75 bytes). The test expects
0x1050.

The other values the tests check: `sample_entry` at RVA 0x1000, 75 bytes, type 0x1001;
`shared_total` (in `.data`, RVA 0x3000) of type 0x74 (int); `point` as a forward reference
(0x1002) and its definition (0x1004, size 12); the sections `.text` 0x1000, `.rdata` 0x2000,
`.data` 0x3000; and the two modules, the object and `* Linker *`.
