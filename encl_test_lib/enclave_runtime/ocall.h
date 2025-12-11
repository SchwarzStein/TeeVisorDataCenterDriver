#ifndef OCALL_H
#define OCALL_H
#include <stdint.h>
#include "../enclave_lib/enclave_runtime.h"
#include "./mm/mm.h"
#include "./utils.h"

int do_eclone(struct ocall_clone *clone);
int do_ocall(uint64_t rdi, uint64_t rsi);
void ocall_print(char* str, int len);
void ocall_emodt(struct sgx_enclave_modify_types* metadata);
void ocall_clone_thread(struct ocall_clone_thread *clone_thread);
void ocall_get_test_case(struct ocall_get_test_case *test_case);
extern void __do_eexit(uint64_t rdi, uint64_t rsi);
void do_eexit(uint64_t rdi, uint64_t rsi);
int do_eaccept(uint64_t addr, uint64_t flags);
int do_emodp(uint64_t addr, uint64_t flags);
int do_ereport(sgx_target_info_t* target_info, sgx_report_data_t* report_data, sgx_report_t* out_put_report);
int do_esetussa(uint64_t addr);
#endif