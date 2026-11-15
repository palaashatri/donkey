# Call fixtures

## `stack_argument-x86_64`

`stack_argument.c` is written for this repository: a callee with seven integer arguments (the
seventh on the stack) and a caller that passes six in registers and reads nothing from the stack.
It is built with GCC 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) on x86-64 Linux, with this command:

    gcc -O1 -fno-inline -o stack_argument-x86_64 stack_argument.c

Rebuilt from the same source and command on the same toolchain, the output is byte-identical
(SHA-256 `0aef1864c8e411632e6ec38d0a4cee57a482a40c6040d67eafd17b013c6a98f3`). It is used by
`cli.decompile_stack_argument_caller_is_partial`: `caller` must print as Partial with the call note,
never as Complete with a call that omits the seventh argument.

## `lea_stack_argument-x86_64`

`lea_stack_argument.s` is written for this repository (AT&T syntax, x86-64, no C library). `callee`
takes the address of its first stack argument with `lea 8(%rsp), %rax` and reads through it at entry
rsp + 16, an incoming argument; `caller` pushes one argument and calls it. Built with GNU as and ld
2.42 (GNU Binutils for Ubuntu 2.42) on x86-64 Linux:

    as --64 -o lea_stack_argument.o lea_stack_argument.s
    ld -e caller -o lea_stack_argument-x86_64 lea_stack_argument.o

SHA-256 `bd27debdbd1a340ccf89c14918670066980562deeea7e1597864525256fe02d4`. Used by
`cli.decompile_lea_stack_argument_caller_is_partial`: `caller` must be Partial with the call note.
