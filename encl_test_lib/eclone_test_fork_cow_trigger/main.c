#include "../enclave_lib/enclave.h"
#include <pthread.h>
#include <poll.h>
#include <sys/eventfd.h>
#include "stdio.h"
struct enclave *encl = NULL;
int pipefd[2];
int case1, case2, case3;
bool parent = true;
volatile bool case_initialized = false;

/*
 * This function returns true (as int: 1) if the pipe between both
 * processes has been closed.
 */
int isPipeClosed(int *fd) {
    struct pollfd pfds;
    int time = 0;

    pfds.fd = fd[0];
    pfds.events = POLLHUP | POLLERR | POLLIN;
    pfds.revents = 0;

    if(poll(&pfds, 1, time) < 0) {
        //printf("Poll failed\n");
    }
    if (pfds.revents) {
        //printf("Pipe failed (%d)\n", pfds.revents);
        close (fd[0]);
        return 1;
    }
    return 0;
}

int handle_enclave_exit(uint64_t rdi, uint64_t rsi, uint64_t rdx,
                        struct enclave_run *run, uint64_t r8, uint64_t r9)
{
    int ret;
    __UNUSED(rdx);
    __UNUSED(r8);
    __UNUSED(r9);
    //printf("tid %d handle_enclave_exit rdi: %d\n",gettid(), rdi);
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
            break;
        case EEXIT_OCALL_PRINT:
            struct ocall_print *print = (struct ocall_print *)rsi;
            printf("%s", print->ptr);
            run->rdi = 0;
            run->function = EENTER;
            return EENTER;
        case EEXIT_OCALL_CLONE:
            struct ocall_clone *clone = (struct ocall_clone *)rsi;
            printf("Get ocall eclone!\n");
            printf("clone_hash: ");
            for (int i = 0; i < 32; i++) {
                printf("%02x ", clone->metadata->clone_hash[i]);
            }
            printf("\n");
            printf("total_page_num: 0x%lx\n", clone->metadata->total_page_num);
            printf("metadata_page_num: 0x%lx\n", clone->metadata->metadata_page_num);
            int clone_ret;
            ret = enclave_clone_bind((struct sgx_enclave_clone_metadata *)clone->metadata);
            if (ret)
            {
                perror("ECLONE BIND Failed!\n");
                return 0;
            } else {
                clone_ret = prepare_fork(encl->tcs_count, pipefd[1]);
                clone->ret = clone_ret;
                if (clone_ret) {
                    parent = false;
                }
            }
            printf("EEXIT_OCALL_CLONE Return to enclave!\n");
            run->function = ERESUME;
            return ERESUME;
        case EEXIT_OCALL_CLONE_THREAD:
            struct ocall_clone_thread *clone_thread = (struct ocall_clone_thread *)rsi;
            int clone_thread_ret;
            clone_thread_ret = prepare_fork(encl->tcs_count, pipefd[1]);
            clone_thread->ret = clone_thread_ret;
            if (clone_thread_ret) {
                parent = false;
            }

            run->function = EENTER;
            printf("EEXIT_OCALL_CLONE_THREAD Return to enclave!\n");
            return EENTER;
        case EEXIT_OCALL_GET_TEST_CASE:
            struct ocall_get_test_case *test_case = (struct ocall_get_test_case *)rsi;
            if (!case_initialized) {
                if (case1) {
                    test_case->ret = 6;
                } else {
                    test_case->ret = 0;
                }
                case_initialized = true;
            } else {
                if (parent) {
                    test_case->ret = case2;
                } else {
                    test_case->ret = case3;
                }
            }


            run->function = EENTER;
            return EENTER;
        case EEXIT_OCALL_EMODT:
            struct ocall_emodt *emodt = (struct ocall_emodt *)rsi;
            ret = enclave_modify_type(emodt->metadata);
            if (ret) {
                perror("EMODT Failed!\n");
                return 0;
            }
            run->function = EENTER;
            return EENTER;
            break;
        default:
            printf("Get invalid rdi :%ld\n", rdi);
            break;
        }
    }
    else if (run->exit_reason == EXIT_SIGNAL)
    {
        printf("Thread %d get signal with number %d\n",gettid(), run->signum);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("Missing argument\n");
        return -1;
    }

    case1 = atoi(argv[1]);
    if (case1 < 0 || case1 > 1) {
        printf("case1 error\n");
        return -1;
    }
    
    case2 = atoi(argv[2]);
    case3 = atoi(argv[3]);
    
    if (case2 < 0 || case2 > 7) {
        printf("case2 error\n");
        return -1;
    }

    if (case3 < 0 || case3 > 7) {
        printf("case3 error\n");
        return -1;
    }

    if (pipe(pipefd) < 0) {
        perror("pipefd");
        exit(1);
    }
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

    encl = build_enclave(&param);
    struct enclave_run run1 = {
        .rdi = ECALL_START,
        .rsi = 0,
        .function = EENTER,
        .exit_reason = 0,
        .r8 = 0,
        .r9 = 0,
        .signal_mask = 1 << SIGILL | 1 << SIGBUS | 1 << SIGSEGV,
        .signum = 0,
        .tcs = &encl->tcs[0],
        .user_handler = handle_enclave_exit,
    };

    struct enclave_run run2 = {
        .rdi = ECALL_START,
        .rsi = 0,
        .function = EENTER,
        .exit_reason = 0,
        .r8 = 0,
        .r9 = 0,
        .signal_mask = 1 << SIGILL | 1 << SIGBUS | 1 << SIGSEGV,
        .signum = 0,
        .tcs = &encl->tcs[1],
        .user_handler = handle_enclave_exit,
    };


    if (pthread_create(&encl->tcs[0].thread, NULL, enter_enclave, &run1) != 0) {
        perror("pthread_create 1");
        exit(1);
    }

    if (pthread_create(&encl->tcs[1].thread, NULL, enter_enclave, &run2) != 0) {
        perror("pthread_create 2");
        exit(1);
    }

    int pid = wait_for_fork(pipefd[0]);

    // Child recreate context
    if (!pid) {
        recreate_thread(&encl->tcs[0]);
        recreate_thread(&encl->tcs[1]);
    }
    
    
    wait_enclave_end(encl);

    return 0;
}