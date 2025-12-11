#include "../enclave_runtime/ocall.h"
#define SGX_CLONE_INVALID_ACTIVE_TCS 30

int runtime_test_case() {
    do {} while (cpu_counter_read() < 2);
    if (GET_ENCLAVE_TLS(tcs_index) == 0) {
        do {} while (cpu_counter_read() == 2);
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

        if (ret) {
            char str[] = " ECLONE failed!\n";
            ocall_print(str, sizeof(str));
        }
        if (clone->ret == 0) {
            char str[] = " ECLONE parent TCS 0 return!\n";
            ocall_print(str, sizeof(str));
        }

        if (clone->ret == 1) {
            char str[] = " ECLONE child TCS 0 return!\n";
            ocall_print(str, sizeof(str));
        }

        free_shared(clone);
        free_shared(metadata);

        return ret;
    } else {
        struct ocall_clone_thread oc = { 0 };
        ocall_clone_thread(&oc);

        if (oc.ret == 0) {
            char str[] = " ECLONE parent TCS 1 return!\n";
            ocall_print(str, sizeof(str));
        }

        if (oc.ret == 1) {
            char str[] = " ECLONE child TCS 1 return!\n";
            ocall_print(str, sizeof(str));
        }

        return 0;
    }
}