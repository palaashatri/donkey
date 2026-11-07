# Initial-exec thread-local accesses (G15-T1): each variable is reached through its GOT slot
# (R_X86_64_GOTTPOFF), which holds the thread-pointer offset. Written for this repository;
# the same variables and read_tls as tls.c.
	.section .tdata,"awT",@progbits
	.align 4
	.globl tls_counter
tls_counter:
	.long 7
	.globl tls_byte
tls_byte:
	.byte 3
	.section .tbss,"awT",@nobits
	.align 16
	.globl tls_pair
tls_pair:
	.zero 16
	.text
	.globl read_tls
	.type read_tls, @function
read_tls:
	movq tls_counter@gottpoff(%rip), %rax
	movl %fs:(%rax), %edx
	movq tls_pair@gottpoff(%rip), %rax
	movq %fs:8(%rax), %rax
	addl %edx, %eax
	movq tls_byte@gottpoff(%rip), %rcx
	movsbl %fs:(%rcx), %ecx
	addl %ecx, %eax
	ret
	.size read_tls, .-read_tls
