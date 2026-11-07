# PDB enum fixture (G06-T3)

`enum.c` is written for this repository: an enum with three enumerators (red 0, green 5, blue 6),
a struct whose first field has that enum type, and two functions.

- Object: `clang --target=x86_64-pc-windows-msvc -g -gcodeview -O0 -fno-stack-protector
  -ffreestanding -c enum.c -o enum.obj` (Ubuntu clang 18.1.3).
- Image and PDB: `lld-link /debug:full /entry:paint_entry /subsystem:console /nodefaultlib
  /out:enum.exe enum.obj` (LLD 18.1.3). `enum.pdb` is the PDB the tests read.

The oracle is `llvm-pdbutil dump -types enum.pdb` (LLVM 18.1.3): the enum is 0x1005 with field list
0x1004 (three LF_ENUMERATE records) and underlying type int; the struct `paint` is 0x1007, 8 bytes,
with the enum at offset 0 and an int at offset 4.
