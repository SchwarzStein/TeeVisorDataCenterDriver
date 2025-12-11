#include "../enclave_runtime/ocall.h"
#include <stdbool.h>

int runtime_test_case() {
    void* page =  malloc_user(0x1000, 0x1000);

    struct sgx_enclave_modify_types modt = {
        .offset = (uint64_t) page,
        .length = 0x1000,
        .page_type = SGX_PAGE_TYPE_TRIM,
    };
    ocall_emodt(&modt);

    if (modt.result || modt.count != 0x1000) {
        char emodt_fail[] = "EMODT Failed!\n";
        ocall_print(emodt_fail, sizeof(emodt_fail));
    }


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
        char str1[] = "ECLONE instruction FAILED!\n";
        ocall_print(str1, sizeof(str1));
        goto out;
    }

    if (clone->ret > 0) {
        char str2[] = "Launch Child!\n";
        ocall_print(str2, sizeof(str2));
    } else if( clone->ret < 0) {
        char str3[] = "ECLONE Failed during fork!\n";
        ocall_print(str3, sizeof(str3));
    } else {
        char str4[] = "Launch Parent!\n";
        ocall_print(str4, sizeof(str4));
    }

    // Trigger cow here
    do_eaccept((uint64_t) page, (SGX_PAGE_TYPE_TRIM << SGX_SECINFO_FLAGS_TYPE_SHIFT) | SGX_SECINFO_FLAGS_MODIFIED);
    char str5[] = "EACCEPT done!\n";
    ocall_print(str5, sizeof(str5));
    
out:
    free_shared(clone);
    free_shared(metadata);
    return ret;
}