#ifndef _X86_ENCLU_H
#define _X86_ENCLU_H
#include <asm/sev.h>

static inline int __enclu(struct sgx_eenter_args *param)
{
	return snp_sgx_enclu(param);
}
#endif