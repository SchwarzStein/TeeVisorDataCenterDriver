#include "../enclave_lib/enclave.h"
#include "stdio.h"

int handle_enclave_exit(uint64_t rdi, uint64_t rsi, uint64_t rdx,
                        struct enclave_run *run, uint64_t r8, uint64_t r9)
{
    __UNUSED(rdx);
    __UNUSED(r8);
    __UNUSED(r9);
    if (run->exit_reason == EXIT_EEXIT)
    {
        switch (rdi)
        {
        case EEXIT_FAIL:
            printf("runtime failed\n");
            printf("output rsi:0x%lx\n", rsi);
            break;
        case EEXIT_SYSCALL:
            printf("Get runtime syscall\n");
            break;
        case EEXIT_TRAP:
            printf("Get runtime trap, trap number :%ld\n", rsi & 0xff);
            break;
        case EEXIT_EXIT:
            printf("Exit from enclave\n");
            break;
        default:
            printf("Get invalid rdi :%ld\n", rdi);
            break;
        }
    }
    else if (run->exit_reason == EXIT_SIGNAL)
    {
        printf("Get signal with number %d\n", run->signum);
    }

    return 0;
}

int main(void)
{
    /*
    struct enclave_build_param
    {
        uint64_t enclave_base;
        uint64_t enclave_size;
        uint64_t user_base;
        uint64_t user_size;
        uint64_t runtime_base;
        uint64_t runtime_size;
        uint64_t runtime_thread_stack_size;
        uint64_t attributes_flags;
        uint64_t attributes_xfrm;
        uint64_t tcs_count;
        uint64_t nssa;        // nssa in tcs, exclude ussa
        uint64_t ssa_frame_size;   // page number of each ssa
        uint64_t shared_memory_base;
        uint64_t shared_memory_size;
        char *runtime_path;        // The path of runtime code binary to run
        char *user_path;           // The path of program code binary to run
        char *handler_symbol_name; // Use to locate the symbol and add handler page
    };
    */
    struct enclave_build_param param =
        {
            .enclave_base = 0x0,
            .enclave_size = 0x2000000, // 32 MB
            .user_base = 0x0,
            .user_size = 0x1000000,
            .runtime_base = 0x1000000,
            .runtime_size = 0x1000000,
            .ssa_frame_size = 4,
            .shared_memory_base = 0x8000000000, // 512GB
            .shared_memory_size = 0x200000,   // 2MB
            .nssa = 2,
            .attributes_flags = ENCLAVE_DEFAULT_ATTRIBUTE_FLAG | SGX_FLAGS_CLONE,
            .attributes_xfrm = ENCLAVE_DEFAULT_ATTRIBUTE_XFRM,
            .tcs_count = 2,
            .runtime_thread_stack_size = 0x200000, // 2MB
            .user_path = NULL,
            .runtime_path = "./enclave_runtime",
            .handler_symbol_name = "handler_entry",
        };

    struct enclave *encl = build_enclave(&param);
    struct enclave_run run = {
        .rdi = ECALL_START,
        .rsi = 0,
        .function = EENTER,
        .exit_reason = 0,
        .r8 = 0,
        .r9 = 0,
        .signal_mask = 1 << SIGSEGV,
        .signum = 0,
        .tcs = &encl->tcs[0],
        .user_handler = handle_enclave_exit,
    };

    int ret = enter_enclave(&run);
    
    if (ret < 0) {
        printf("enter_enclave return error: %d", ret);
    }
    return 0;
}