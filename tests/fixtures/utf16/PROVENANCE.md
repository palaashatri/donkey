# UTF-16 string fixture (G12-T2)

`utf16.c` is written for this repository. It has no libc and holds two arrays of UTF-16 code
units in `.rodata`: `greeting` ("Donkey", ASCII) and `mixed` ("café 中"). Each array ends
with a zero code unit.

`utf16` is built from it with:

```
clang -O0 -std=c11 -nostdlib -static -fuse-ld=lld -Wl,-e,_start -o utf16 utf16.c   # clang 18.1.3, x86-64 Linux
```

With clang 18 and lld 18 the `.rodata` section holds `greeting` at `0x2001a8` (14 bytes) and `mixed`
at `0x2001b6` (14 bytes), each as little-endian UTF-16. `llvm-objdump -s -j .rodata utf16` shows the
bytes.

Used by `Session.DefineString16DefinesTheTerminatedBytesAndRefusesOthers` and by the UI script
`tests/ui/utf16.donkeyui`.
