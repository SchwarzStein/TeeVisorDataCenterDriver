#include "../enclave_lib/enclave_offsets.h"
#include "../enclave_lib/enclave_runtime.h"
#include "../enclave_lib/sgx_arch.h"

.text
.global enclave_entry
.type enclave_entry, @function
enclave_entry:
    # rcx contains the next addr
    movq %rcx, %gs:ENCLAVE_TLS_NEXT_RIP

    cmpq $0, %gs:ENCLAVE_TLS_OCALL_XSAVE
    jne .Lreturn_from_ocall
    # switch the stack
    movq %gs:ENCLAVE_TLS_TCS_STACK_ADDR, %rsp

    # clear the alignment check flag
    pushfq
    andq $(~RFLAGS_AC), (%rsp)
    popfq

    # host xsave state is not used when entering the enclave
    # thus here we do not save it before entering main
    # rdi: call id
    # rsi, rdx, r8, r9
    callq handle_ecall

    movq EEXIT_FAIL, %rdi
    # rdi: EXIT TYPE
    # rsi: exit param
.global __do_eexit
.type __do_eexit, @function
__do_eexit:
.Lstart_eexit:
    # user stack
    movq %gs:ENCLAVE_TLS_URSP, %rsp
    movq %gs:ENCLAVE_TLS_URBP, %rbp
    # set exit addr
    movq %gs:ENCLAVE_TLS_NEXT_RIP, %rbx

    xorq %rdx, %rdx
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15

    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    subq %r11, %r11 # use sub to set flags to a fixed value

    mov	$4, %rax
    
	enclu


# If there is an allocated ocall stack, save states to it
# The save area should have the same layout as SSA for simplicity
    # rdi: EXIT TYPE
    # rsi: exit param
.global __do_ocall
.type __do_ocall, @function
__do_ocall:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx

    movq %gs:ENCLAVE_TLS_OCALL_XSAVE, %rbx
    fxsave64 (%rbx)


    movq %gs:ENCLAVE_TLS_OCALL_GPR, %rbx

    movq $0, GPR_RAX(%rbx)
    movq %rcx, GPR_RCX(%rbx)
    movq %rdx, GPR_RDX(%rbx)
    movq 0(%rsp), %rax
    movq %rax, GPR_RBX(%rbx)
    leaq 16(%rbp), %rax
    movq %rax, GPR_RSP(%rbx)
    movq 0(%rbp), %rax
    movq %rax, GPR_RBP(%rbx)
    movq %rsi, GPR_RSI(%rbx)
    movq %rdi, GPR_RDI(%rbx)
    movq %r8, GPR_R8(%rbx)
    movq %r9, GPR_R9(%rbx)
    movq %r10, GPR_R10(%rbx)
    movq %r11, GPR_R11(%rbx)
    movq %r12, GPR_R12(%rbx)
    movq %r13, GPR_R13(%rbx)
    movq %r14, GPR_R14(%rbx)
    movq %r15, GPR_R15(%rbx)

    pushfq
    popq GPR_RFLAGS(%rbx)

    movq 8(%rbp), %rax
    movq %rax, GPR_RIP(%rbx)

    rdfsbase %rax
    movq %rax, GPR_FSBASE(%rbx)

    # gs base is used for tls, should not be changed
    # rdgsbase %rax
    # movq %rax, GPR_GSBASE(%rbx)

    jmp .Lstart_eexit
    
.Lreturn_from_ocall:
    movq %gs:ENCLAVE_TLS_OCALL_XSAVE, %rbx
    fxrstor64 (%rbx)
    movq %gs:ENCLAVE_TLS_OCALL_GPR, %rbx
    movq GPR_RSP(%rbx), %rsp
    movq GPR_RBP(%rbx), %rbp
    movq %rdi, GPR_RAX(%rbx)

    movq GPR_FSBASE(%rbx), %rax
    wrfsbase %rax


    movq GPR_RSI(%rbx), %rsi
    movq GPR_RDI(%rbx), %rdi
    movq GPR_RCX(%rbx), %rcx
    movq GPR_RDX(%rbx), %rdx
    movq GPR_R8(%rbx), %r8
    movq GPR_R9(%rbx), %r9
    movq GPR_R10(%rbx), %r10
    movq GPR_R11(%rbx), %r11
    movq GPR_R12(%rbx), %r12
    movq GPR_R13(%rbx), %r13
    movq GPR_R14(%rbx), %r14
    movq GPR_R15(%rbx), %r15



    movq GPR_RFLAGS(%rbx), %rax
    push %rax
    popfq
    mov GPR_RIP(%rbx), %rax
    push %rax

    movq GPR_RAX(%rbx), %rax
    movq GPR_RBX(%rbx), %rbx
    ret
    
    # rdi: clone_ptr
    # rsi: exit vaddr
    # rdx: metadata vaddr
.global __do_eclone
.type __do_eclone, @function
__do_eclone:
    push %rbx
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    movq %rsp, %gs:ENCLAVE_TLS_ECLONE_RSP

    movq %rsi, %rbx
    movq %rdx, %rcx
    movq %rdi, %rsi
    movq $EEXIT_OCALL_CLONE, %rdi
    mov	$0x104, %rax

    movq %gs:ENCLAVE_TLS_URSP, %rsp
    movq %gs:ENCLAVE_TLS_URBP, %rbp
    
    xorq %rdx, %rdx
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15

    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    subq %r11, %r11

	enclu

    movq %gs:ENCLAVE_TLS_ECLONE_RSP, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rbx
    ret







    