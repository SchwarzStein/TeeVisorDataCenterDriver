#include "../enclave_runtime/ocall.h"
#define SGX_CLONE_INVALID_ACTIVE_TCS 30

void* target_page = NULL;
typedef void (*handler_t)(void);

static void no_op() {
    return;
}

static void test_write() {
    char test_str[] = "Write to target page!\n";
    ocall_print(test_str, sizeof(test_str));
    *(char *)target_page = 'a';
    char test_str1[] = "Write finished!\n";
    ocall_print(test_str1, sizeof(test_str1));
    return;
}

static void test_eaccept_trim() {
    char test_str[] = "Eaccept target page!\n";
    ocall_print(test_str, sizeof(test_str));
    int ret = do_eaccept((uint64_t) target_page, (SGX_PAGE_TYPE_TRIM << SGX_SECINFO_FLAGS_TYPE_SHIFT) | SGX_SECINFO_FLAGS_MODIFIED);
    if (ret) {
        char test_fail_str[] = "Eaccept failed!\n";
        ocall_print(test_fail_str, sizeof(test_fail_str));
    }
    return;
}

static void test_emodp() {
    char test_str[] = "Emodp target page!\n";
    ocall_print(test_str, sizeof(test_str));
    do_emodp((uint64_t) target_page, (SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT));
    char test_finish_str[] = "EMODP finished!\n";
    ocall_print(test_finish_str, sizeof(test_finish_str));
    return;
}

static void test_ereport() {
    char test_str[] = "Ereport target page!\n";
    ocall_print(test_str, sizeof(test_str));
    sgx_report_data_t* report_data =  malloc_runtime(128, 128);
    do_ereport((target_page + 512), report_data, target_page);
    return;
}

static void test_esetussa() {
    char test_str[] = "Esetussa target page!\n";
    ocall_print(test_str, sizeof(test_str));
    int ret = do_esetussa((uint64_t) target_page);
    if (ret == -29) {
        char test_fail_str[] = "Esetussa SGX_INVALID_USSA!\n";
        ocall_print(test_fail_str, sizeof(test_fail_str));
    }
}

static void test_emodt() {
    char test_str[] = "Emodt target page!\n";
    ocall_print(test_str, sizeof(test_str));
    struct sgx_enclave_modify_types metadata = {
        .offset = (uint64_t) target_page,
        .length = 0x1000,
        .page_type = SGX_PAGE_TYPE_TRIM,
    };
    ocall_emodt(&metadata);

    if (metadata.result || metadata.count != 0x1000) {
        char emodt_fail[] = "EMODT Failed!\n";
        ocall_print(emodt_fail, sizeof(emodt_fail));
    }
}

static void test_read() {
    char c = *(char *)target_page;
    char read_str[] = "Read from target page!\n";
    ocall_print(read_str, sizeof(read_str));
    ocall_print(&c, 1);
}

handler_t table[] = {
    no_op,
    test_write,
    test_eaccept_trim,
    test_emodp,
    test_ereport,
    test_esetussa,
    test_emodt,
    test_read,
};

static void run_test() {
    struct ocall_get_test_case test_case = { .ret = -1};
    ocall_get_test_case(&test_case);
    if (test_case.ret < 0 || test_case.ret > 7) {
        char emodt_fail[] = "Get Invalid test case!\n";
        ocall_print(emodt_fail, sizeof(emodt_fail));
        return;
    }

    table[test_case.ret]();
}

int runtime_test_case() {
    do {} while (cpu_counter_read() < 2);
    if (GET_ENCLAVE_TLS(tcs_index) == 0) {
        target_page = malloc_runtime(0x4000, 0x4000);
        if (!target_page) {
            char malloc_fail[] = "Cannot malloc 4 pages!\n";
            ocall_print(malloc_fail, sizeof(malloc_fail));
            return -1;
        }
        memset(target_page, 0, 0x1000);
        run_test();
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
            char str[] = " ECLONE parent TCS 0 do test case!\n";
            ocall_print(str, sizeof(str));
            run_test();
        }

        if (clone->ret == 1) {
            char str[] = " ECLONE child TCS 0 do test case!\n";
            ocall_print(str, sizeof(str));
            run_test();
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

