#include "enclave_runtime.h"
#include "enclave.h"
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#define OFFSET(sym, struct_name, field) \
    printf("#define %-30s 0x%zx\n", #sym, offsetof(struct_name, field))
#define DEFINE(sym, value) \
    printf("#define %-30s 0x%zx\n", #sym, value)

int main(void)
{
    printf("#ifndef RUNTIME_ASM_OFFSETS_H\n");
    printf("#define RUNTIME_ASM_OFFSETS_H\n");
    printf("/* Auto-generated offsets for struct enclave_tls */\n\n");

    OFFSET(ENCLAVE_TLS_ENCLAVE_BASE, enclave_tls, enclave_base);
    OFFSET(ENCLAVE_TLS_ENCLAVE_SIZE, enclave_tls, enclave_size);
    OFFSET(ENCLAVE_TLS_RUNTIME_BASE, enclave_tls, runtime_base);
    OFFSET(ENCLAVE_TLS_RUNTIME_SIZE, enclave_tls, runtime_size);
    OFFSET(ENCLAVE_TLS_USER_BASE, enclave_tls, user_base);
    OFFSET(ENCLAVE_TLS_USER_SIZE, enclave_tls, user_size);

    OFFSET(ENCLAVE_TLS_TCS_INDEX, enclave_tls, tcs_index);
    OFFSET(ENCLAVE_TLS_SSA, enclave_tls, ssa);
    OFFSET(ENCLAVE_TLS_USSA, enclave_tls, ussa);
    OFFSET(ENCLAVE_TLS_NSSA, enclave_tls, nssa);
    OFFSET(ENCLAVE_TLS_SSA_FRAME_SIZE, enclave_tls, ssa_frame_size);
    OFFSET(ENCLAVE_TLS_GPR, enclave_tls, gpr);
    OFFSET(ENCLAVE_TLS_UGPR, enclave_tls, ugpr);
    OFFSET(ENCLAVE_TLS_TCS_STACK_ADDR, enclave_tls, tcs_stack_addr);
    OFFSET(ENCLAVE_TLS_STACK_SIZE, enclave_tls, stack_size);
    OFFSET(ENCLAVE_TLS_RUNTIME_HEAP_BASE, enclave_tls, runtime_heap_base);
    OFFSET(ENCLAVE_TLS_RUNTIME_HEAP_SIZE, enclave_tls, runtime_heap_size);
    OFFSET(ENCLAVE_TLS_USER_HEAP_BASE, enclave_tls, user_heap_base);
    OFFSET(ENCLAVE_TLS_USER_HEAP_SIZE, enclave_tls, user_heap_size);
    OFFSET(ENCLAVE_TLS_SHARED_MEMORY_BASE, enclave_tls, shared_memory_base);
    OFFSET(ENCLAVE_TLS_SHARED_MEMORY_SIZE, enclave_tls, shared_memory_size);
    OFFSET(ENCLAVE_TLS_USER_ELF_EXIST, enclave_tls, user_elf_exist);
    OFFSET(ENCLAVE_TLS_USER_ENTRY, enclave_tls, user_entry);
    OFFSET(ENCLAVE_TLS_OCALL_XSAVE, enclave_tls, ocall_xsave);
    OFFSET(ENCLAVE_TLS_OCALL_GPR, enclave_tls, ocall_gpr);
    OFFSET(ENCLAVE_TLS_ECLONE_RSP, enclave_tls, eclone_rsp);
    OFFSET(ENCLAVE_TLS_NEXT_RIP, enclave_tls, next_rip);
    OFFSET(ENCLAVE_TLS_URSP, enclave_tls, ursp);
    OFFSET(ENCLAVE_TLS_URBP, enclave_tls, urbp);
    printf("\n#define ENCLAVE_TLS_SIZE 0x%02zx\n", sizeof(enclave_tls));

    DEFINE(SSA_MISC_EXINFO_SIZE, 16UL);

    /* sgx_pal_gpr_t offsets */
    printf("\n/* Auto-generated offsets for struct sgx_pal_gpr_t */\n\n");

    OFFSET(GPR_RAX, sgx_pal_gpr_t, rax);
    OFFSET(GPR_RCX, sgx_pal_gpr_t, rcx);
    OFFSET(GPR_RDX, sgx_pal_gpr_t, rdx);
    OFFSET(GPR_RBX, sgx_pal_gpr_t, rbx);
    OFFSET(GPR_RSP, sgx_pal_gpr_t, rsp);
    OFFSET(GPR_RBP, sgx_pal_gpr_t, rbp);
    OFFSET(GPR_RSI, sgx_pal_gpr_t, rsi);
    OFFSET(GPR_RDI, sgx_pal_gpr_t, rdi);
    OFFSET(GPR_R8, sgx_pal_gpr_t, r8);
    OFFSET(GPR_R9, sgx_pal_gpr_t, r9);
    OFFSET(GPR_R10, sgx_pal_gpr_t, r10);
    OFFSET(GPR_R11, sgx_pal_gpr_t, r11);
    OFFSET(GPR_R12, sgx_pal_gpr_t, r12);
    OFFSET(GPR_R13, sgx_pal_gpr_t, r13);
    OFFSET(GPR_R14, sgx_pal_gpr_t, r14);
    OFFSET(GPR_R15, sgx_pal_gpr_t, r15);
    OFFSET(GPR_RFLAGS, sgx_pal_gpr_t, rflags);
    OFFSET(GPR_RIP, sgx_pal_gpr_t, rip);
    OFFSET(GPR_URSP, sgx_pal_gpr_t, ursp);
    OFFSET(GPR_URBP, sgx_pal_gpr_t, urbp);
    OFFSET(GPR_EXITINFO, sgx_pal_gpr_t, exitinfo);
    OFFSET(GPR_SWITCHFLAG, sgx_pal_gpr_t, switch_flag);
    OFFSET(GPR_RESERVED, sgx_pal_gpr_t, reserved);
    OFFSET(GPR_AEXNOTIFY, sgx_pal_gpr_t, aexnotify);
    OFFSET(GPR_FSBASE, sgx_pal_gpr_t, fsbase);
    OFFSET(GPR_GSBASE, sgx_pal_gpr_t, gsbase);

    printf("\n#define SGX_PAL_GPR_SIZE 0x%02zx\n", sizeof(sgx_pal_gpr_t));

    OFFSET(ENCLAVE_RUN_FUNCTION, struct enclave_run, function); /* RAX, should be ERESUME or EENTER */
    OFFSET(ENCLAVE_RUN_RDI, struct enclave_run, rdi);
    OFFSET(ENCLAVE_RUN_RSI, struct enclave_run, rsi);
    OFFSET(ENCLAVE_RUN_RDX, struct enclave_run, rdx);
    /* rcx (AEP) is used by the library, not stored in this struct */
    OFFSET(ENCLAVE_RUN_R8, struct enclave_run, r8);
    OFFSET(ENCLAVE_RUN_R9, struct enclave_run, r9);
    OFFSET(ENCLAVE_RUN_TCS, struct enclave_run, tcs);
    OFFSET(ENCLAVE_RUN_USER_HANDLER, struct enclave_run, user_handler);  /* int (*)(rdi,rsi,rdx,r8,r9) */
    OFFSET(ENCLAVE_RUN_SIGNAL_MASK, struct enclave_run, signal_mask);
    //OFFSET(ENCLAVE_RUN_SIG_HANDLER, struct enclave_run, signal_handler); /* void (*)(int, siginfo_t*, struct ucontext*) */
    OFFSET(ENCLAVE_RUN_EXIT_REASON, struct enclave_run, exit_reason);
    OFFSET(ENCLAVE_RUN_SIGNUM, struct enclave_run, signum);

    OFFSET(TCS_STATE, struct tcs, state);
    OFFSET(TCS_ADDR, struct tcs, addr);
    OFFSET(TCS_MUTEX, struct tcs, mutex);

    printf("#endif\n");
    printf("\n");
    return 0;
}