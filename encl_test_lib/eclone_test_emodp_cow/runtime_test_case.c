#include "../enclave_runtime/ocall.h"
#include <stdbool.h>

int runtime_test_case() {
    bool child = false;
    struct ocall_clone *clone = malloc_shared(8, sizeof(struct ocall_clone));
    if (!clone) {
        return -1;
    }

    struct eclone_metatdata *metadata  = malloc_shared(64, sizeof(struct eclone_metatdata));
    if (!metadata) {
        return -1;
    }

    void* page =  malloc_user(0x1000, 0x1000);

    clone->metadata = metadata;
    int ret = do_eclone(clone);

    if (ret) {
        char str1[] = "ECLONE instruction FAILED!\n";
        ocall_print(str1, sizeof(str1));
        goto out;
    }

    if (clone->ret > 0) {
        child = true;
        char str2[] = "Launch Child!\n";
        ocall_print(str2, sizeof(str2));
    } else if( clone->ret < 0) {
        char str3[] = "ECLONE Failed during fork!\n";
        ocall_print(str3, sizeof(str3));
    } else {
        child = false;
        char str4[] = "Launch Parent!\n";
        ocall_print(str4, sizeof(str4));
    }

    if (!child) {
        // Try to convert a page to not read write executable
        do_emodp((uint64_t) page, (SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT));
    } else {
        do {} while (cpu_counter_read() == 2);
        // try to write at the parent trim page
        *(char *)page = 'a';
        char write_page_success[] = "Child writes on the page after parent accept emodp trim page with the same vaddr!\n";
        ocall_print(write_page_success, sizeof(write_page_success));
        return 0;
    }
    
out:
    free_shared(clone);
    free_shared(metadata);
    return ret;
}