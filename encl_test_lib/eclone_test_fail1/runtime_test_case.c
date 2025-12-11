#include "../enclave_runtime/ocall.h"

int runtime_test_case() {
    struct ocall_clone *clone = malloc_shared(8, sizeof(struct ocall_clone));
    if (!clone) {
        return -1;
    }

    struct eclone_metatdata *metadata  = malloc_shared(64, sizeof(struct eclone_metatdata));
    if (!metadata) {
        return -1;
    }

    clone->metadata = metadata;
    int ret = do_eclone(clone);

    free_shared(clone);
    free_shared(metadata);

    return ret;
}