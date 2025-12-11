#include "../enclave_runtime/ocall.h"
#include <stdbool.h>

int runtime_test_case() {
    sgx_report_data_t* report_data =  malloc_runtime(128, 128);
    sgx_report_t* output_data =  malloc_runtime(512, 512);
    sgx_target_info_t* target_info =  malloc_runtime(512, 512);
    memset(report_data, 0, 128);
    memset(output_data, 0, 512);
    memset(target_info, 0, 512);

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
    do_ereport(target_info, report_data, output_data);
    char str5[] = "EREPORT done!\n";
    ocall_print(str5, sizeof(str5));
    
out:
    free_shared(clone);
    free_shared(metadata);
    return ret;
}