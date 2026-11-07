# ISA fixtures (G13)

`isa.c` is written for this repository: a Fibonacci loop, a conditional, a sum loop, a call and a
spin loop, freestanding (no libc).

- `arm-a32.elf`: `clang --target=armv7a-none-eabi -O2 -ffreestanding -nostdlib -fuse-ld=lld
  -Wl,-e,_start isa.c` (clang 18.1.3, lld 18.1.3). A32, little-endian, not stripped.
- `riscv64.elf`: `clang --target=riscv64-unknown-elf -march=rv64gc -mabi=lp64d -O2 -ffreestanding
  -nostdlib -fuse-ld=lld -Wl,-e,_start isa.c` (clang 18.1.3, lld 18.1.3). RV64GC, so the
  compressed (RVC) instructions the compiler emits are present.
- `isa_branches.c` and `isa_branches_start.c` are written for this repository: a loop with a
  conditional branch, and an entry point that calls it and then spins. The call crosses translation
  units, so its relocation names a global symbol, which the MIPS static link requires.
- `mips32el.elf`: `clang --target=mipsel-linux-gnu -mno-abicalls -fno-pic -O1 -ffreestanding
  -nostdlib -static -fuse-ld=lld -Wl,-e,_start isa_branches.c isa_branches_start.c`. MIPS32,
  little-endian.
- `mips32be.elf`: the same with `--target=mips-linux-gnu`. MIPS32, big-endian.
- `ppc32.elf`: `clang --target=powerpc-linux-gnu -O1 -ffreestanding -nostdlib -static -fuse-ld=lld
  -Wl,-e,_start isa_branches.c isa_branches_start.c`. PowerPC32, big-endian.
- `ppc32le.elf`: the same with `--target=powerpcle-linux-gnu`. PowerPC32, little-endian.
- `mips64el.elf` (`--target=mips64el-linux-gnuabi64 -mabi=n64`) and `ppc64.elf`
  (`--target=powerpc64-linux-gnu`) exist only to test that 64-bit images are refused. They have no
  listing.
- `*.objdump-lengths.txt`: the oracle. Each line is an instruction address and its length in bytes,
  from `llvm-objdump -d` (LLVM 18.1.3), for every instruction in the image's `.text`, in order. Data
  words the listing prints as `.word` are not instructions and are not in the file.

The decoder (Capstone) and the listing agree on every instruction's address and length (55 of 55
for A32, 56 of 56 for RV64GC, 23 of 23 for each MIPS32 byte order, 25 of 25 for each PowerPC32
byte order). The differences the comparison showed were naming only: LLVM prints
`ret` where Capstone prints the `c.jr ra` it stands for.
