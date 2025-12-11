#include "mm.h"
#include "../../enclave_lib/enclave_runtime.h"
#include "../ocall.h"

typedef volatile int mutex_t;
tlsf_t tlsf_runtime;
tlsf_t tlsf_user;
tlsf_t tlsf_shared;
mutex_t tlsf_runtime_lock;
mutex_t tlsf_user_lock;
mutex_t tlsf_shared_lock;

#define MUTEX_UNLOCKED 0
#define MUTEX_LOCKED   1

static inline void mutex_init(mutex_t *m) {
    *m = MUTEX_UNLOCKED;
}

static inline void mutex_lock(mutex_t *m) {
    while (__atomic_test_and_set(m, __ATOMIC_ACQUIRE)) {
        // busy wait
    }
}

static inline void mutex_unlock(mutex_t *m) {
    __atomic_clear(m, __ATOMIC_RELEASE);
}

void init_allocator()
{
    tlsf_runtime = tlsf_create_with_pool((void *)GET_ENCLAVE_TLS(runtime_heap_base), GET_ENCLAVE_TLS(runtime_heap_size));
    tlsf_user = tlsf_create_with_pool((void *)GET_ENCLAVE_TLS(user_heap_base), GET_ENCLAVE_TLS(user_heap_size));
    tlsf_shared = tlsf_create_with_pool((void *)GET_ENCLAVE_TLS(shared_memory_base), GET_ENCLAVE_TLS(shared_memory_size));
    mutex_init(&tlsf_runtime_lock);
    mutex_init(&tlsf_user_lock);
    mutex_init(&tlsf_shared_lock);
}

void *malloc_runtime(size_t align, size_t size)
{
    void* ret;
    mutex_lock(&tlsf_runtime_lock);
    ret = tlsf_memalign(tlsf_runtime, align, size);
    mutex_unlock(&tlsf_runtime_lock);
    return ret;
}

void *malloc_user(size_t align, size_t size)
{
    void* ret;
    mutex_lock(&tlsf_user_lock);
    ret = tlsf_memalign(tlsf_user, align, size);
    mutex_unlock(&tlsf_user_lock);
    return ret;
}

void *malloc_shared(size_t align, size_t size)
{
    void* ret;
    mutex_lock(&tlsf_shared_lock);
    ret = tlsf_memalign(tlsf_shared, align, size);
    mutex_unlock(&tlsf_shared_lock);
    return ret;
}

void free_runtime(void *ptr)
{
    mutex_lock(&tlsf_runtime_lock);
    tlsf_free(tlsf_runtime, ptr);
    mutex_unlock(&tlsf_runtime_lock);
}

void free_user(void *ptr)
{
    mutex_lock(&tlsf_user_lock);
    tlsf_free(tlsf_user, ptr);
    mutex_unlock(&tlsf_user_lock);
}

void free_shared(void *ptr)
{
    mutex_lock(&tlsf_shared_lock);
    tlsf_free(tlsf_shared, ptr);
    mutex_unlock(&tlsf_shared_lock);
}