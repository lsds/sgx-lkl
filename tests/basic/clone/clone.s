.text
.global do_clone
.hidden do_clone
.type   do_clone,@function
do_clone:
	push %rax
	call lkl_syscall@PLT
	test %eax,%eax
	jnz 1f
	xor %ebp,%ebp
	pop %rdi
	pop %r9
	call *%r9
	// exit system call if this function returns
	subq $5*8, %rsp
	push %rax
	mov %rsp, %rsi
	mov $93, %rdi
	call lkl_syscall@PLT
	// Should be unreachable, trap if it is reached
	ud2
1:	pop %rdi
	ret

	.weak lkl_syscall
