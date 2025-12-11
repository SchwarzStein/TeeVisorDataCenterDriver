#include "ocall.h"
#include "utils.h"

extern int __do_ocall(uint64_t rdi, uint64_t rsi);
extern int __do_eclone(uint64_t clone_ptr, uint64_t exit_addr, uint64_t metadata_vaddr);

void do_eexit(uint64_t rdi, uint64_t rsi)
{
    cpu_counter_dec();
    __do_eexit(rdi, rsi);
}

// Allocate an area for state saving and call eexit
int do_ocall(uint64_t rdi, uint64_t rsi)
{
    uint64_t ocall_stack_size = GET_ENCLAVE_TLS(ssa_frame_size) * 0x1000;
    void *ocall_stack_ptr = malloc_runtime(0x1000, ocall_stack_size);
    if (!ocall_stack_ptr)
    {
        return -1;
    }

    uint64_t gpr_offset = (uint64_t)GET_ENCLAVE_TLS(gpr) - (uint64_t)GET_ENCLAVE_TLS(ssa);
    
    // Compiler error happened when setting too large memory
    for (int i = 0; i < GET_ENCLAVE_TLS(ssa_frame_size); i++) {
        memset(ocall_stack_ptr + i * 0x1000, 0, 0x1000);
    }

    SET_ENCLAVE_TLS(ocall_xsave, ocall_stack_ptr);
    SET_ENCLAVE_TLS(ocall_gpr, ocall_stack_ptr + gpr_offset);
    cpu_counter_dec();
    __do_ocall(rdi, rsi);
    cpu_counter_inc();
    SET_ENCLAVE_TLS(ocall_xsave, 0UL);
    SET_ENCLAVE_TLS(ocall_gpr, 0UL);
    free_runtime(ocall_stack_ptr);
    return 0;
}


void ocall_print(char* str, int len) {
    struct ocall_print *print = malloc_shared(8, sizeof(struct ocall_print));
    if (!print) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_PRINT);
    }

    char *shared_str = malloc_shared(8, len + 1);
    if (!shared_str) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_PRINT);
    }

    memcpy(shared_str, str, len);
    shared_str[len] = 0;
    print->ptr = shared_str;
    if (do_ocall(EEXIT_OCALL_PRINT, (uint64_t)print)) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_PRINT);
    }

    free_shared(print);
    free_shared(shared_str);
}

void ocall_emodt(struct sgx_enclave_modify_types* metadata) {
    struct ocall_emodt *emodt = malloc_shared(8, sizeof(struct ocall_emodt));
    if (!emodt) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_EMODT);
    }

    struct sgx_enclave_modify_types *shared_metadata = malloc_shared(8, sizeof(struct sgx_enclave_modify_types));
    if (!shared_metadata) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_EMODT);
    }

    memcpy(shared_metadata, metadata, sizeof(struct sgx_enclave_modify_types));
    emodt->metadata = shared_metadata;
    if (do_ocall(EEXIT_OCALL_EMODT, (uint64_t)emodt)) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_EMODT);
    }

    memcpy(metadata, shared_metadata, sizeof(struct sgx_enclave_modify_types));

    free_shared(emodt);
    free_shared(shared_metadata);
}

int do_eclone(struct ocall_clone *clone)
{
    uint64_t exit_vaddr = GET_ENCLAVE_TLS(next_rip);
    uint64_t metadata_vaddr = (uint64_t)clone->metadata;
    int ret = __do_eclone((uint64_t)clone, exit_vaddr, metadata_vaddr);
    return ret;
}

void ocall_clone_thread(struct ocall_clone_thread *clone_thread)
{
    struct ocall_clone_thread *clone_thread_shared = malloc_shared(8, sizeof(struct ocall_clone_thread));
    if (!clone_thread_shared) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_CLONE_THREAD);
    }
    clone_thread_shared->ret = clone_thread->ret;
    if (do_ocall(EEXIT_OCALL_CLONE_THREAD, (uint64_t)clone_thread_shared)) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_CLONE_THREAD);
    }
    clone_thread->ret = clone_thread_shared->ret;
    free_shared(clone_thread_shared);
}

void ocall_get_test_case(struct ocall_get_test_case *test_case)
{
    struct ocall_clone_thread *test_case_shared = malloc_shared(8, sizeof(struct ocall_get_test_case));
    if (!test_case_shared) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_GET_TEST_CASE);
    }
    test_case_shared->ret = test_case->ret;
    if (do_ocall(EEXIT_OCALL_GET_TEST_CASE, (uint64_t)test_case_shared)) {
        do_eexit(EEXIT_FAIL, EEXIT_OCALL_GET_TEST_CASE);
    }
    test_case->ret = test_case_shared->ret;
    free_shared(test_case_shared);
}

int do_eaccept(uint64_t addr, uint64_t flags)
{
    __attribute__((__aligned__(64))) sgx_arch_sec_info_t secinfo = {
        .flags = flags,
    };

    return -enclu(EACCEPT, (uint64_t)&secinfo, addr, 0);
}

int do_emodp(uint64_t addr, uint64_t flags)
{
    __attribute__((__aligned__(64))) sgx_arch_sec_info_t secinfo = {
        .flags = flags,
    };

    return -enclu(EMODP, (uint64_t)&secinfo, addr, 0);
}

int do_ereport(sgx_target_info_t* target_info, sgx_report_data_t* report_data, sgx_report_t* output_report)
{
    return -enclu(EREPORT, (uint64_t)target_info, (uint64_t)report_data, (uint64_t)output_report);
}


int do_esetussa(uint64_t addr)
{
    return -enclu(ESETUSSA, addr, 0, 0);
}