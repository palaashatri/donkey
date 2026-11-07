# ELF core fixture (G15-T3)

`sleeper.core` is an ELF core file of the program in `sleeper.c`, written for this repository.

- Program: `gcc -O0 -g0 -fno-pie -no-pie -static sleeper.c -o sleeper`, started with an empty
  environment (`env -i`) and left in `pause()`. The empty environment keeps the core free of
  the environment of the session that made it: a core holds its process's memory, and the
  process environment is in that memory.
- Core: `gdb -batch -p <pid> -ex "generate-core-file sleeper.core" -ex detach`, GDB 15 on
  Ubuntu 24.04, x86-64. The process id was 8251 when the core was taken.
- The values the test checks were read from GDB on the same core file:
  `info threads` (one LWP, 8251), `info registers rip rsp rax` (rip 0x4112f4, rsp
  0x7ffc29d24f98, rax 0xfffffffffffffdfe), and `info proc mappings` (five file-backed
  mappings, the first 0x400000-0x401000 at offset 0; the offsets 0x1000, 0x7f000, 0xa4000 and
  0xa9000 match the NT_FILE page offsets). The PT_NOTE segment is at 0x54238, 0x6794 bytes.
- Size 371880 bytes. Checked before commit: no environment variables, tokens, email addresses
  or account identifiers appear in the file.
