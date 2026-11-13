# musl identification fixture (G09-T3)

`sig_musl.c` was written for this repository (MIT, like the rest of the repository). It uses a spread
of musl's C library (`qsort`, `malloc`, `strtol`, `strchr`, `strstr`, `memcpy`, `write`, ...), so the
static link pulls in the library functions the test identifies.

Built on Ubuntu 24.04 with `musl-tools` 1.2.4-2 (musl 1.2.4), GCC 13.3.0 as the front end:

    musl-gcc -static -O2 -fno-stack-protector -o sig_musl_unstripped sig_musl.c
    strip -o sig_musl sig_musl_unstripped
    nm -S --defined-only sig_musl_unstripped | keep the lines whose type is t or T, and write
      "0x<address> <size> <name>" in address order (a short Python filter; the lines are
      the ones with four fields)

- `sig_musl` (stripped, the file the test analyses; SHA-256
  `7daee9ff15c926708599fc9d237c789cd9e2511d41a67e0771e065615fa42950`).
- `symbols.txt`: the ground truth, one line per function symbol of the unstripped build:
  `0x<address> <size> <name>`. A function may have several names (an alias at the same address), and
  any of them is correct there. SHA-256 `6ae581d1ced5a074bcac70ba368f5aedc30add7e8649ac588e369a34d56eb78d`.

The test does not read `symbols.txt` to find functions: it finds them with the analysis of the stripped
file and compares its names with `symbols.txt` afterwards.
