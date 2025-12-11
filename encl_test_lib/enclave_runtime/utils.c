#include "utils.h"

void inline *memset(void *b, int c, uint64_t len)
{
    for (uint64_t i = 0; i < len; i++)
        ((uint8_t *)b)[i] = (uint8_t)c;
    return b;
}

void *memcpy(void *dst, const void *src, uint64_t n)
{
    asm volatile(
        "movq %[n], %%rcx\n\t"
        "rep movsb\n\t"
        :
        : [dst] "D"(dst),
          [src] "S"(src),
          [n] "r"(n)
        : "rcx", "memory");
    return dst;
}