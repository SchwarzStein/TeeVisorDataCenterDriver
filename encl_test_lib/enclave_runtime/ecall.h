#ifndef ECALL_H
#define ECALL_H

void handle_ecall(unsigned long rdi, unsigned long rsi, unsigned long _aep/*rcx is set by firmware*/,
                    unsigned long r8, unsigned long r9);
#endif