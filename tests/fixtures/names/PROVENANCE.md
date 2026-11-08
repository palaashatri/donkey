# Local-name fixture (G12-T3)

`add_three.c` is written for this repository. `add_three` is built from it with:

```
clang -O0 -g -fno-pie -no-pie -o add_three add_three.c   # clang 18.1.3, x86-64 Linux
```

`add_three` is a non-PIE x86-64 ELF with DWARF. Its `add_three` function starts at `0x401120` and
keeps `total` in a frame slot at `rbp-8` because its address is taken. The decompiler does not
recover locals, so the name `frame:rbp:-8` is applied as a new local.

Used by `cmake/checks/check_local_names.cmake` (the `cli.local_names` CTest).
