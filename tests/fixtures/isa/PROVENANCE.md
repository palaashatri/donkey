# ISA fixtures (G13)

`isa.c` is written for this repository: a Fibonacci loop, a conditional, a sum loop, a call and a
spin loop, freestanding (no libc).

- `arm-a32.elf`: `clang --target=armv7a-none-eabi -O2 -ffreestanding -nostdlib -fuse-ld=lld
  -Wl,-e,_start isa.c` (clang 18.1.3, lld 18.1.3). A32, little-endian, not stripped.
- `riscv64.elf`: `clang --target=riscv64-unknown-elf -march=rv64gc -mabi=lp64d -O2 -ffreestanding
  -nostdlib -fuse-ld=lld -Wl,-e,_start isa.c` (clang 18.1.3, lld 18.1.3). RV64GC, so the
  compressed (RVC) instructions the compiler emits are present.
- `*.objdump-lengths.txt`: the oracle. Each line is an instruction address and its length in bytes,
  from `llvm-objdump -d` (LLVM 18.1.3), for every instruction in the image's `.text`, in order. Data
  words the listing prints as `.word` are not instructions and are not in the file.

The decoder (Capstone) and the listing agree on every instruction's address and length (55 of 55
for A32, 56 of 56 for RV64GC). The differences the comparison showed were naming only: LLVM prints
`ret` where Capstone prints the `c.jr ra` it stands for.
