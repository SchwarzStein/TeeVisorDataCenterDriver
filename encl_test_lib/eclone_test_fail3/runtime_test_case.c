#include "../enclave_runtime/ocall.h"
#define SGX_CLONE_INVALID_ACTIVE_TCS 30
#include <stdbool.h>

long state = 0;    // 0: initial, 1: leader selected, 2: leader finished

int runtime_test_case() {
    int expected = 0;

    // Try to become leader (CAS)
    bool is_leader = __atomic_compare_exchange_n(
        &state, &expected, 1,
        false,                       // no weak CAS
        __ATOMIC_SEQ_CST,
        __ATOMIC_SEQ_CST);

    if (is_leader) {
        // === Leader path ===
        struct ocall_clone *clone = malloc_shared(8, sizeof(struct ocall_clone));
        if (!clone) return -1;

        struct eclone_metatdata *metadata = malloc_shared(64, sizeof(struct eclone_metatdata));
        if (!metadata) return -1;

        clone->metadata = metadata;

        int ret = do_eclone(clone);

        if (ret == SGX_CLONE_INVALID_ACTIVE_TCS) {
            char str[] = " ECLONE SGX_CLONE_INVALID_ACTIVE_TCS failed!\n";
            ocall_print(str, sizeof(str));
        }
        free_shared(clone);
        free_shared(metadata);

        // leader finished
        __atomic_store_n(&state, 2, __ATOMIC_SEQ_CST);

        return 0;
    } else {
        // === Follower path ===
        char w[] = "Follower waiting...\n";
        ocall_print(w, sizeof(w));

        // Wait until leader sets state=2
        while (__atomic_load_n(&state, __ATOMIC_SEQ_CST) != 2)
            ;

        char ok[] = "Follower leaving\n";
        ocall_print(ok, sizeof(ok));

        return 0;
    }
}
