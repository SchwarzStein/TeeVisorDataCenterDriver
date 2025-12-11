#include "enclave.h"
#include <errno.h>
#include <asm/prctl.h> 
#include <syscall.h>

extern int enclu_loop(struct enclave_run *run);
static __thread struct enclave_run *local_run = NULL;
static __thread struct thread *self = NULL;
volatile int64_t fork_finish = 0;
volatile int64_t fork_count = 0;

extern int __clone(int (*func)(void *), void *stack, int flags, void *arg, ...);


static void signal_handler(int sig, siginfo_t *siginfo, void *ctx)
{
    __UNUSED(siginfo);
    __UNUSED(ctx);

    local_run->exit_reason = EXIT_SIGNAL;
    local_run->signum = sig;
    return;
}

int enter_enclave(struct enclave_run *run)
{
    uint64_t tcs_vaddr = run->tcs->addr;
    int ret;
    struct sigaction sa = {0};
    printf("Enter enclave tid: %d\n", gettid());
    // Cannot get the lock means the tcs is already used by other thread
    if (pthread_mutex_trylock(&run->tcs->mutex))
    {
        return -EBUSY;
    }
    local_run = run;
    self = &run->tcs->th;
    self->self_pid = gettid();
    syscall(SYS_arch_prctl, ARCH_GET_FS, (unsigned long)&self->fs_reg);
    syscall(SYS_arch_prctl, ARCH_GET_GS, (unsigned long)&self->gs_reg);
    run->exit_reason = EXIT_EEXIT;

    if (run->signal_mask)
    {
        sa.sa_sigaction = signal_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        for (int sig = 0; sig < 64; sig++)
        {
            if (run->signal_mask & (1UL << sig))
            {
                ret = sigaction(sig, &sa, NULL);
                if (ret)
                    goto err_signal;
            }
        }
    }

    ret = enclu_loop(run);

    local_run = NULL;
    pthread_mutex_unlock(&run->tcs->mutex);
    printf("Exit enclave tid: %d\n", gettid());
    tcs_terminate(run->tcs);
    return 0;

err_signal:
    printf("Unable to register the desired signal handler for handling aex!\n");
    pthread_mutex_unlock(&run->tcs->mutex);
    return ret;
}

static _Noreturn int resume_thread(void * t)
{
    ucontext_t ctx;
    struct thread * th = (struct thread *)t;
    self = th;
    swapcontext(&ctx, &th->saved_ctx);
    abort();
}

int recreate_thread(struct tcs *tcs)
{
    struct thread * th = &tcs->th;
    int flags = 0;
    int child = 0;
    int ret;
    flags = flags | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_IO;
    flags = flags | CLONE_CHILD_SETTID | CLONE_SYSVSEM | CLONE_THREAD | CLONE_SETTLS;
    
    ret = __clone(resume_thread, &th->switch_stack[4096], flags, (void*)th, &child,
                                th->fs_reg, &th->self_pid);
    __asm__ __volatile__("" ::: "memory");

    if (ret != -1) {
        th->self_pid = ret;
        return ret;
    } else {
        perror("recreate_thread failed!\n");
    }
    
    return -1;
}

// Return 1 for child, 0 for parent
int prepare_fork(int64_t tcs_num, int efd) {
    int ret = 1;
    if (self == NULL) {
        printf("Fork can be done after entering the enclave once!\n");
        return -1;
    }

    int64_t ready_count;
    __atomic_store_n(&fork_finish, 1, __ATOMIC_SEQ_CST);
    int count = __atomic_add_fetch(&fork_count, 1, __ATOMIC_RELEASE);

    getcontext(&self->saved_ctx);
    // Reassign the value here to return 1 in the case of child
    ret = 1;
    while(__atomic_load_n(&fork_finish, __ATOMIC_SEQ_CST) != 0) {
        // try to do the fork after all the threads are ready
        int64_t num = tcs_num;
        if (__atomic_compare_exchange_n(&fork_count, &num, 0, /*weak=*/false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            uint64_t op = EEXIT_OCALL_CLONE;
            write(efd, &op, sizeof(op));
        } else {
            sleep(1);
        }

        ret = 0;
    }
    return ret;
}

int wait_for_fork(int efd) {
    int pid;
    uint64_t op;
    read(efd, &op, sizeof(op));
    if (op != EEXIT_OCALL_CLONE) {
        printf("Invalid event op:%lx!\n", op);
    }
    pid = fork();
    __atomic_store_n(&fork_finish, 0, __ATOMIC_SEQ_CST);
    return pid;
}

void tcs_terminate(struct tcs * tcs) {
    tcs->state = TCS_STATE_TERMINATE;
}

void wait_enclave_end(struct enclave *encl) {
    for (int i = 0; i < encl->tcs_count; i++) {
        while (encl->tcs[i].state != TCS_STATE_TERMINATE) {
            sleep(1);
        }
    }
}