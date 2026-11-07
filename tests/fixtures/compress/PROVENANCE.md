# Compressed-stream fixtures (G07)

Written for this repository, with Python 3's `zlib` (the zlib library the Python build links,
zlib 1.3) as the oracle.

- `sample.txt`: 60000 bytes of words and punctuation from a fixed seed (`random.Random`
  with seed 20260502), built by a short Python script: 20 words, separators, and occasional
  random bytes.
- `dynamic.z`: `zlib.compress(sample.txt, 9)`. The first block is type 2 (dynamic Huffman).
- `stored.z`: `zlib.compress(sample.txt, 0)`. The first block is type 0 (stored).
- `fixed.txt` and `fixed.z`: `b"hello hello hello, fixed codes"`, compressed at level 6. The
  block is type 1 (fixed Huffman).

The tests are in `tests/unit/inflate_test.cpp`.

## Compressed DWARF (G07)

- `dwarf-sample.c`: written for this repository, a struct, an enum, a static function and a
  global-free entry point, so the DWARF has types, functions and locals.
- `dwarf-plain.elf`: `gcc -O0 -g -fno-stack-protector -fno-pie -no-pie -c dwarf-sample.c`
  (GCC 13.3), linked with `ld -static -nostdlib -e sample_entry`.
- `dwarf-zlib.elf`: `objcopy --compress-debug-sections=zlib dwarf-plain.elf` (binutils 2.42).
  The `.debug_*` sections carry the `C` flag (SHF_COMPRESSED) and an Elf64_Chdr of type zlib.
- The plain file is the oracle for the compressed file's functions, types and variables.

## Separate debug files (G07)

- `dwarf-buildid.elf`: `dwarf-sample.c` linked with `-Wl,--build-id=sha1` (the build id is
  50ecf7656faf58fb7c4dc466e4d17a79ff0d318d, read with `readelf -n`).
- `debug/.build-id/50/ecf7656faf58fb7c4dc466e4d17a79ff0d318d.debug`:
  `objcopy --only-keep-debug dwarf-buildid.elf` (binutils 2.42), in the tree that the
  build-id route searches.
- `stripped-buildid.elf`: `objcopy --strip-debug dwarf-buildid.elf` (keeps the build id, no
  DWARF).
- `dwarf-plain.debug`: `objcopy --only-keep-debug dwarf-plain.elf`. `stripped-debuglink.elf`
  is `objcopy --strip-debug dwarf-plain.elf` plus `--add-gnu-debuglink=dwarf-plain.debug`,
  so its link names this file and the CRC-32 is the one objcopy computed.
- `bogus/`: a binary with the same debuglink, and a `dwarf-plain.debug` that is a different
  file (a copy of `dwarf-zlib.elf`), so its CRC does not match and the link must be refused.
