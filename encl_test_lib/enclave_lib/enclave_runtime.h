#ifndef ENCLAVE_RUNTIME
#define ENCLAVE_RUNTIME
#ifndef __ASSEMBLER__
#include <stdint.h>
#include <assert.h>
#include "sgx_arch.h"
#include "sgx_user.h"

extern volatile int64_t cpu_counter;
typedef struct
{
    uint64_t enclave_base;
    uint64_t enclave_size;
    uint64_t runtime_base;
    uint64_t runtime_size;
    uint64_t user_base;
    uint64_t user_size;

    uint64_t tcs_index;
    uint64_t ssa;
    uint64_t ussa;
    uint64_t nssa;
    uint64_t ssa_frame_size;
    sgx_pal_gpr_t *gpr;
    sgx_pal_gpr_t *ugpr;
    uint64_t tcs_stack_addr;
    uint64_t stack_size;
    uint64_t runtime_heap_base;
    uint64_t runtime_heap_size;
    uint64_t user_heap_base;
    uint64_t user_heap_size;
    uint64_t shared_memory_base;
    uint64_t shared_memory_size;
    uint64_t user_elf_exist;
    uint64_t user_entry;
    uint64_t ocall_xsave;
    uint64_t ocall_gpr;
    uint64_t eclone_rsp;

    uint64_t next_rip;
    uint64_t ursp;
    uint64_t urbp;
} enclave_tls;
static_assert(sizeof(enclave_tls) < 4096, "struct enclave_tls exceeds page size");

struct eclone_metatdata {
    uint8_t clone_hash[32];
    uint64_t total_page_num;
    uint64_t metadata_page_num;
    uint64_t reserved[2];
}__attribute__((aligned(64)));;
static_assert(sizeof(struct eclone_metatdata) == 64, "struct eclone_metatdata should be 64 bytes");

#define GET_ENCLAVE_TLS(member)                                                                    \
    ({                                                                                             \
        enclave_tls* tmp;                                                                          \
        uint64_t val;                                                                              \
        static_assert(sizeof(tmp->member) == 8, "member should have 8-byte type");                 \
        __asm__("movq %%gs:%c1, %0"                                                                \
                : "=r"(val)                                                                        \
                : "i"(offsetof(enclave_tls, member))                                               \
                : "memory");                                                                       \
        (__typeof(tmp->member))val;                                                                \
    })

#define SET_ENCLAVE_TLS(member, value)                                                             \
    do {                                                                                           \
        enclave_tls* tmp;                                                                          \
        static_assert(sizeof(tmp->member) == 8, "member should have 8-byte type");                 \
        static_assert(sizeof(value) == 8, "only 8-byte type can be set");                          \
        __asm__("movq %0, %%gs:%c1"                                                                \
                :                                                                                  \
                : "ir"(value), "i"(offsetof(enclave_tls, member))                           \
                : "memory");                                                                       \
    } while (0)

struct ocall_print {
    char* ptr;
};

struct ocall_clone {
    struct eclone_metatdata * metadata;
    int ret;
};

struct ocall_emodt {
    struct sgx_enclave_modify_types * metadata;
    int ret;
};

struct ocall_clone_thread {
    int ret;
};

struct ocall_get_test_case {
    int ret;
};

int runtime_test_case();
void cpu_counter_inc();
void cpu_counter_dec();
int64_t cpu_counter_read(void);
#endif

#define ECALL_START 0

#define EEXIT_FAIL  0
#define EEXIT_TRAP  1
#define EEXIT_SYSCALL 2
#define EEXIT_EXIT 3
#define EEXIT_OCALL_PRINT 4
#define EEXIT_OCALL_CLONE 5
#define EEXIT_OCALL_EMODT 6
#define EEXIT_OCALL_CLONE_THREAD 7
#define EEXIT_OCALL_GET_TEST_CASE 8

#define EENTER  2
#define ERESUME 3
#endif