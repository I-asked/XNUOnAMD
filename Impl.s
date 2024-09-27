#include <i386/asm.h>

.globl _my_user_trap
.globl _new_user_trap
.globl _new_user_trap_end
.globl _old_user_trap
.globl _old_user_trap_end
.globl _old_user_trap_ret

#define CCALL1(fn, arg1)		\
	movl	%esp, %edi		;\
	subl	$4, %esp		;\
	andl	$0xFFFFFFF0, %esp	;\
	movl	arg1, 0(%esp)		;\
	call	EXT(fn)			;\
	movl	%edi, %esp

.text
// inject into `user_trap`
_new_user_trap:
	movl	$wrap_my_user_trap,%ecx
	jmp		*%ecx
_new_user_trap_end:
// call `my_user_trap` and return on rv=0
wrap_my_user_trap:
	push	%ebx
	push	%edi
	movl	8+S_ARG0,%eax
	CCALL1	(my_user_trap,%eax)
	test	%eax,%eax
	popl	%edi
	popl	%ebx
	
	jnz		_old_user_trap
	ret
// old instructions go here (see kext entry)
_old_user_trap:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
// jump back to `user_trap`
_old_user_trap_end:
	movl	(_old_user_trap_ret),%ecx
	jmp		*%ecx
// address of the rest of the function
_old_user_trap_ret:
	.long	0xFFFFFFFF