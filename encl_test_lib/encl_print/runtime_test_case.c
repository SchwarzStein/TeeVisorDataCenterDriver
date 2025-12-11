#include "../enclave_runtime/ocall.h"

int runtime_test_case() {
    char test_str[] = "Print from enclave!\n";
    int len = sizeof(test_str) + 1;
    struct ocall_print *print = malloc_shared(8, sizeof(struct ocall_print));
    if (!print) {
        return -1;
    }

    char *shared_str = malloc_shared(8, len);
    if (!shared_str) {
        return -1;
    }

    memcpy(shared_str, test_str, len - 1);
    shared_str[len - 1] = 0;
    print->ptr = shared_str;
    int ret = do_ocall(EEXIT_OCALL_PRINT, (uint64_t)print);

    free_shared(print);
    free_shared(shared_str);

    return ret;
}