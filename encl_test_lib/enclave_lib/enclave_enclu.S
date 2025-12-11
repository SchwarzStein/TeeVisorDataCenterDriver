#include "enclave_offsets.h"
#include "enclave_runtime.h"
#include <asm/errno.h>
/*
 * Input: RDI: struct enclave_run *run
 *  struct enclave_run
 *  {
 *      uint64_t function; // RAX, should be ERESUME or EENTER OFF
 *      uint64_t rdi;
 *      uint64_t rsi;
 *      uint64_t rdx;
 *      // uint64_t rcx; AEP used by the library
 *      uint64_t r8;
 *      uint64_t r9;
 *      struct tcs *tcs;
 *
 *      uint64_t signal_mask;
 *     void (*signal_handler)(int signum, siginfo_t *info, void *uc);
 *    // output rcx is aep
 *   int (*user_handler)(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r8, uint64_t r9);
 *};
 */

 /* This funtion uses r10, r11 for storing local variable*/
.global enclu_loop
enclu_loop:
    /* set up the stack frame*/
    push %rbp
	mov	%rsp, %rbp
	/* store */
    push %rbx
	/* push rdi to use later*/
	push %rdi

	mov %rdi, %r10
.Lenter_enclave:
    /* check if function is valid*/
    mov	ENCLAVE_RUN_FUNCTION(%r10), %rax
    /* EENTER <= function <= ERESUME */
	cmp	$EENTER, %rax
	jb	.Linvalid_input
	cmp	$ERESUME, %rax
	ja	.Linvalid_input

	mov ENCLAVE_RUN_RDI(%r10), %rdi
	mov ENCLAVE_RUN_RSI(%r10), %rsi
	mov ENCLAVE_RUN_RDX(%r10), %rdx
	mov ENCLAVE_RUN_R8(%r10), %r8
	mov ENCLAVE_RUN_R9(%r10), %r9

	mov ENCLAVE_RUN_TCS(%r10), %r11
	mov TCS_ADDR(%r11), %rbx
	mov $1, TCS_STATE(%r11)
	lea	.Laex_addr(%rip), %rcx

	/* If exit_reason is written by signal handler, go to user handler*/
.Laex_addr:
	mov 0(%rsp), %r10
	cmpq $0, ENCLAVE_RUN_EXIT_REASON(%r10)
	jne .Lhandle_exit
	enclu

.Lhandle_exit:
	mov 0(%rsp), %r10
	cmpq $0, ENCLAVE_RUN_USER_HANDLER(%r10)
	jne .Linvoke_userspace_handler

	xor	%eax, %eax

.Lout:
	pop %rdi
	pop	%rbx
	leave
	ret

.Linvalid_input:
	mov	$(-EINVAL), %eax
	jmp	.Lout

.Linvoke_userspace_handler:
	mov %r10, %rcx

	cld
	mov ENCLAVE_RUN_USER_HANDLER(%r10), %rax
	lfence
	call *%rax

	cmp	$0, %eax
	jle .Lout
	mov 0(%rsp), %r10
	jmp .Lenter_enclave
