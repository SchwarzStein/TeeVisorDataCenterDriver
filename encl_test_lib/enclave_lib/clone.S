    .text
    .global __clone
    .type __clone, @function

/* int __clone(int (*func)(void *), void *stack, int flags, void *arg, ... ) */
__clone:
    push    %rbp
    mov     %rbp, %rsp

/* ---------- save callee-saved ---------- */
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15

    mov     %rdi, %r12       /* func */
    mov     %rsi, %r13       /* stack */
    mov     %rdx, %r14       /* flags */
    mov     %rcx, %r15       /* arg */

    xor     %rbx, %rbx       /* parent_tid = NULL */
    xor     %r8, %r8         /* tls = NULL */
    xor     %r10, %r10       /* child_tid = NULL */

    /* CLONE_PARENT_SETTID */
    test    $0x00100, %r14
    jz      1f
    mov     %r8, %rbx
1:
    /* CLONE_SETTLS */
    test    $0x000800, %r14
    jz      2f
    mov     %r9, %r8
2:
    /* CLONE_CHILD_SETTID */
    test    $0x010000, %r14
    jz      3f
    mov     16(%rbp), %r10
3:

    mov     %r14, %rdi       /* flags */
    mov     %r13, %rsi       /* stack */
    mov     %rbx, %rdx       /* parent_tid */
    /* r10  child_tid is set */
    /* r8 = tls */
    xor     %r9, %r9

    mov     $56, %rax        /* SYS_clone */
    syscall

    test    %rax, %rax
    jnz     .parent

    /* ---------- child path ---------- */
    mov     %r15, %rdi       /* arg -> rdi */
    call    *%r12            /* func(arg) */

    mov     %eax, %edi
    mov     $60, %rax        /* SYS_exit */
    syscall

.parent:
    /* ---------- parent path ---------- */
    test    %rax, %rax
    jns     .done

    /* rax < 0 */
    mov     $-1, %rax

.done:
    /* ---------- restore callee-saved ---------- */
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    leave
    ret

    .size __clone, .-__clone
