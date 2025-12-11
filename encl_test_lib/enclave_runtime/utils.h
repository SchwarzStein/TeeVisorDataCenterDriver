#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>

void *memset(void *b, int c, uint64_t len);
void *memcpy(void *dst, const void *src, uint64_t n);
#endif