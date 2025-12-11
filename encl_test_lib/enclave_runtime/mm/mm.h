#ifndef MM_H
#define MM_H
#define NDEBUG
#define tlsf_assert(x) ((void)0)
#include "tlsf.h"
#include "stdint.h"

void init_allocator();
void* malloc_runtime(size_t align, size_t size);
void* malloc_user(size_t align, size_t size);
void* malloc_shared(size_t align, size_t size);
void free_runtime(void * ptr);
void free_user(void * ptr);
void free_shared(void * ptr);
#endif