# A callee that reads an incoming stack argument through a register: lea 8(%rsp), %rax takes the
# address of the first stack argument (entry rsp + 8), and mov 32(%rax), %rax reads entry rsp + 16,
# which is an incoming argument, so the caller must not be resolved against this callee. Written
# for this repository.
    .text
    .globl callee
callee:
    sub $24, %rsp
    lea 8(%rsp), %rax
    mov 32(%rax), %rax
    add $24, %rsp
    ret

    .globl caller
caller:
    push $7
    call callee
    add $8, %rsp
    ret
