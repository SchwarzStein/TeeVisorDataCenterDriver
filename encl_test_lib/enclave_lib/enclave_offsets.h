#ifndef RUNTIME_ASM_OFFSETS_H
#define RUNTIME_ASM_OFFSETS_H
/* Auto-generated offsets for struct enclave_tls */

#define ENCLAVE_TLS_ENCLAVE_BASE       0x0
#define ENCLAVE_TLS_ENCLAVE_SIZE       0x8
#define ENCLAVE_TLS_RUNTIME_BASE       0x10
#define ENCLAVE_TLS_RUNTIME_SIZE       0x18
#define ENCLAVE_TLS_USER_BASE          0x20
#define ENCLAVE_TLS_USER_SIZE          0x28
#define ENCLAVE_TLS_TCS_INDEX          0x30
#define ENCLAVE_TLS_SSA                0x38
#define ENCLAVE_TLS_USSA               0x40
#define ENCLAVE_TLS_NSSA               0x48
#define ENCLAVE_TLS_SSA_FRAME_SIZE     0x50
#define ENCLAVE_TLS_GPR                0x58
#define ENCLAVE_TLS_UGPR               0x60
#define ENCLAVE_TLS_TCS_STACK_ADDR     0x68
#define ENCLAVE_TLS_STACK_SIZE         0x70
#define ENCLAVE_TLS_RUNTIME_HEAP_BASE  0x78
#define ENCLAVE_TLS_RUNTIME_HEAP_SIZE  0x80
#define ENCLAVE_TLS_USER_HEAP_BASE     0x88
#define ENCLAVE_TLS_USER_HEAP_SIZE     0x90
#define ENCLAVE_TLS_SHARED_MEMORY_BASE 0x98
#define ENCLAVE_TLS_SHARED_MEMORY_SIZE 0xa0
#define ENCLAVE_TLS_USER_ELF_EXIST     0xa8
#define ENCLAVE_TLS_USER_ENTRY         0xb0
#define ENCLAVE_TLS_OCALL_XSAVE        0xb8
#define ENCLAVE_TLS_OCALL_GPR          0xc0
#define ENCLAVE_TLS_ECLONE_RSP         0xc8
#define ENCLAVE_TLS_NEXT_RIP           0xd0
#define ENCLAVE_TLS_URSP               0xd8
#define ENCLAVE_TLS_URBP               0xe0

#define ENCLAVE_TLS_SIZE 0xe8
#define SSA_MISC_EXINFO_SIZE           0x10

/* Auto-generated offsets for struct sgx_pal_gpr_t */

#define GPR_RAX                        0x0
#define GPR_RCX                        0x8
#define GPR_RDX                        0x10
#define GPR_RBX                        0x18
#define GPR_RSP                        0x20
#define GPR_RBP                        0x28
#define GPR_RSI                        0x30
#define GPR_RDI                        0x38
#define GPR_R8                         0x40
#define GPR_R9                         0x48
#define GPR_R10                        0x50
#define GPR_R11                        0x58
#define GPR_R12                        0x60
#define GPR_R13                        0x68
#define GPR_R14                        0x70
#define GPR_R15                        0x78
#define GPR_RFLAGS                     0x80
#define GPR_RIP                        0x88
#define GPR_URSP                       0x90
#define GPR_URBP                       0x98
#define GPR_EXITINFO                   0xa0
#define GPR_SWITCHFLAG                 0xa4
#define GPR_RESERVED                   0xa5
#define GPR_AEXNOTIFY                  0xa7
#define GPR_FSBASE                     0xa8
#define GPR_GSBASE                     0xb0

#define SGX_PAL_GPR_SIZE 0xb8
#define ENCLAVE_RUN_FUNCTION           0x0
#define ENCLAVE_RUN_RDI                0x8
#define ENCLAVE_RUN_RSI                0x10
#define ENCLAVE_RUN_RDX                0x18
#define ENCLAVE_RUN_R8                 0x20
#define ENCLAVE_RUN_R9                 0x28
#define ENCLAVE_RUN_TCS                0x30
#define ENCLAVE_RUN_USER_HANDLER       0x38
#define ENCLAVE_RUN_SIGNAL_MASK        0x40
#define ENCLAVE_RUN_EXIT_REASON        0x48
#define ENCLAVE_RUN_SIGNUM             0x4c
#define TCS_STATE                      0x0
#define TCS_ADDR                       0x8
#define TCS_MUTEX                      0x10
#endif

