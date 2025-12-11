#include "../enclave_runtime/ocall.h"

int runtime_test_case() {
    struct ocall_clone *clone = malloc_shared(8, sizeof(struct ocall_clone));
    if (!clone) {
        return -1;
    }

    uint64_t metadata = GET_ENCLAVE_TLS(shared_memory_base) + GET_ENCLAVE_TLS(shared_memory_size) + 0x1000;

    clone->metadata = (struct eclone_metatdata *)metadata;
    int ret = do_eclone(clone);

    free_shared(clone);
    return ret;
}