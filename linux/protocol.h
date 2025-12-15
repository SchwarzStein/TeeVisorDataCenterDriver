#ifndef SVSM_PROTOCOL_H
#define SVSM_PROTOCOL_H

#include <linux/percpu-defs.h>
#include "arch.h"
#include <linux/types.h>
#include <asm/sev.h>
#include <asm/cmpxchg.h>
#include <asm/msr-index.h> // MSR_SVSM_CAA register is defined here.
#include <asm/svm.h>

#define SVSM_ENCL_CALL(x) ((0x10ULL << 32) | (x))
#define SVSM_ENCL_ENCLU 0
#define SVSM_ENCL_ECREATE 1
#define SVSM_ENCL_EADD 2
#define SVSM_ENCL_EEXTEND 3
#define SVSM_ENCL_EINIT 4
#define SVSM_ENCL_EAUG 5
#define SVSM_ENCL_ECCREATE 6
#define SVSM_ENCL_ECLONEINFO 7
#define SVSM_ENCL_EREMOVE 8
#define SVSM_ENCL_ESYNC 9
#define SVSM_ENCL_EMODPR 10
#define SVSM_ENCL_EMODT 11
#define SVSM_ENCL_EDBGRD 12
#define SVSM_ENCL_EDBGWR 13
#define SVSM_ENCL_EADDB 14
#define SVSM_ENCL_ECADD 15
#define SVSM_ENCL_ECINIT 16
#define SVSM_ENCL_ECABORT 17
#define SVSM_ENCL_EADDCOWCACHE 18
#define SVSM_ENCL_ECLEARCOWCACHE 19
#define SVSM_ENCL_ECSYNC 20
#define SVSM_ENCL_MAX 21

#define SVSM_ERR_PROTOCOL 0x80001000
#define SVSM_ENCLAVE_PROTOCOL_BASE 800
#define SVSM_ERR_PROTOCOL_ENCLAVE(x) (SVSM_ERR_PROTOCOL + SVSM_ENCLAVE_PROTOCOL_BASE + (x))
#define SVSM_ENCLAVE_FAULT(x) ((x) - SVSM_ERR_PROTOCOL - SVSM_ENCLAVE_PROTOCOL_BASE)
#define SVSM_ENCLAVE_ERROR(x) ((x) - SVSM_ERR_PROTOCOL)

#define SGX_SYNC_PAGE_FULL 33
#define SGX_NO_CACHE_PAGE 34

#define EXIT_REASON_EEXIT			0
#define EXIT_REASON_INTERRUPT		1
#define EXIT_REASON_TIMER   		2
#define EXIT_REASON_CLONE           3
#define EXIT_REASON_CACHE           4
#define EXIT_REASON_NO_FREE_SLOT    5

#define SVSM_VMPL 0
#define ENCLAVE_VMPL 1

// Kernel definition missed a parenthesis here
// will always switch to vmpl0
#define _GHCB_MSR_VMPL_REQ_LEVEL(v)			\
	/* GHCBData[39:32] */				\
	((((u64)(v) & GENMASK_ULL(7, 0)) << 32) |		\
	/* GHCBDdata[11:0] */				\
	GHCB_MSR_VMPL_REQ)

/*
 * SVSM protocol enclave extension structure
 */
struct sgx_eenter_args
{
	u64 tcs_paddr;
    u64 rax;
    u64 rbx;
    u64 rcx;
    u64 rdx;
    u64 rsi;
    u64 rdi;
    u64 rsp;
    u64 rbp;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 rip;
    u64 rflags;
    u64 cr2;
    u32 mxcsr;
    u16 fcw;
    u16 fsw;
    u64 exit_reason;
    u64 vector;
	u64 error_code;
    u64 apic_tdcr;
    u64 apic_tmcct;
} __attribute__((packed));

struct svsm_eaddb_call {
	u16 num_entries;
	u16 cur_index;

	u8 rsvd1[4];

	struct sgx_pageinfo pageinfo[];
}__attribute__((packed));


#define CLONE_PT_TCS 0
#define CLONE_PT_SSA 1
#define CLONE_PT_MAX 2
#define ECLONEINFO_MAX_ENTRY_NUM ((PAGE_SIZE - 8) / sizeof(struct sgx_cloneinfo_block))
struct svsm_ecloneinfo_call {
	u16 num_entries;
	u16 metadata_type;

	u8 rsvd1[4];

	struct sgx_cloneinfo_block cloneinfo[];
}__attribute__((packed));

struct svsm_ecaddinfo_call {
	u16 num_entries;
	u16 metadata_type;
    u16 next;
	u16 rsvd1;

	struct sgx_cloneinfo_block cloneinfo[];
}__attribute__((packed));


extern unsigned int measure_index;

int snp_sgx_encls(unsigned long index, unsigned long rcx, unsigned long rdx, unsigned long r8);
int snp_sgx_enclu(struct sgx_eenter_args *param);
void *get_buffer_page(void);
void alloc_eaddb_buffer(void);
void release_eaddb_buffer(void);
#endif 