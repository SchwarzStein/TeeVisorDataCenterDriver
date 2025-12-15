#include <asm/traps.h>
#include <linux/sched/signal.h>
#include <linux/clocksource.h>
#include "protocol.h"
#include "encls.h"
#include <linux/mempool.h>

static DEFINE_PER_CPU(struct svsm_ca *, svsm_caa) = NULL;
static mempool_t *teevisor_mempool;
static DEFINE_PER_CPU(u64, svsm_caa_pa);

static inline u64 sev_snp_rd_caa_msr(void)
{
	return __rdmsr(MSR_SVSM_CAA);
}

static __always_inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static __always_inline void svsm_issue_call(struct svsm_call *call, u8 *pending)
{
	register unsigned long rax asm("rax") = call->rax;
	register unsigned long rcx asm("rcx") = call->rcx;
	register unsigned long rdx asm("rdx") = call->rdx;
	register unsigned long r8  asm("r8")  = call->r8;
	register unsigned long r9  asm("r9")  = call->r9;

	call->caa->call_pending = 1;

	asm volatile("rep; vmmcall\n\t"
		     : "+r" (rax), "+r" (rcx), "+r" (rdx), "+r" (r8), "+r" (r9)
		     : : "memory");

	*pending = xchg(&call->caa->call_pending, *pending);

	call->rax_out = rax;
	call->rcx_out = rcx;
	call->rdx_out = rdx;
	call->r8_out  = r8;
	call->r9_out  = r9;
}

static inline int svsm_process_enclave_result_codes(struct svsm_call *call)
{
	switch (call->rax_out) {
	case SVSM_SUCCESS:
		return 0;
	case SVSM_ERR_INCOMPLETE:
	case SVSM_ERR_BUSY:
		return -EAGAIN;
    case SVSM_ERR_PROTOCOL_ENCLAVE(X86_TRAP_GP):
    case SVSM_ERR_PROTOCOL_ENCLAVE(X86_TRAP_PF):
		//pr_err("get exception %lld", SVSM_ENCLAVE_FAULT(call->rax_out));
        return (int)(ENCLS_FAULT_FLAG | SVSM_ENCLAVE_FAULT(call->rax_out));
	default:
		//pr_err("get error code 0x%llx", call->rax_out);
		return (int)SVSM_ENCLAVE_ERROR(call->rax_out);
	}
}

static int svsm_perform_msr_protocol(struct svsm_call *call, u64 target_vmpl)
{
	u8 pending = 0;
	u64 val, resp;
	
	/*
	 * When using the MSR protocol, be sure to save and restore
	 * the current MSR value.
	 */
	val = sev_es_rd_ghcb_msr();

	sev_es_wr_ghcb_msr(_GHCB_MSR_VMPL_REQ_LEVEL(target_vmpl));

	svsm_issue_call(call, &pending);

	resp = sev_es_rd_ghcb_msr();

	sev_es_wr_ghcb_msr(val);

	if (pending)
		return -EINVAL;

	if (GHCB_RESP_CODE(resp) != GHCB_MSR_VMPL_RESP)
		return -EINVAL;

	if (GHCB_MSR_VMPL_RESP_VAL(resp))
		return -EINVAL;

	return svsm_process_enclave_result_codes(call);
}

static int svsm_perform_call_protocol(struct svsm_call *call, u64 target_vmpl)
{
	int ret;

	ret = svsm_perform_msr_protocol(call, target_vmpl);

    // if (ret)
	// {
	//    pr_err("svsm_perform_call_protocol id %llx failed with ret=0x%x\n",call->rax, ret);
	// }

	return ret;
}

int snp_sgx_encls(unsigned long index, unsigned long rcx, unsigned long rdx, unsigned long r8)
{
	unsigned long flags;
    int ret;
    struct svsm_ca *caa;
	struct svsm_call call = {};
    u64 caa_pa;
	u64 tcs0, tcs1;

	flags = native_local_irq_save();

    caa = this_cpu_read(svsm_caa);
    if (caa == NULL) {
        caa_pa = sev_snp_rd_caa_msr();
        caa = (struct svsm_ca *) __va(caa_pa);
        this_cpu_write(svsm_caa, caa);
        this_cpu_write(svsm_caa_pa, caa_pa);
    }

    call.caa = caa;
	call.rcx = rcx;
	call.rdx = rdx;
	call.r8 = r8;

	call.rax = SVSM_ENCL_CALL(index);
	tcs0 = get_cycles();
	ret = svsm_perform_call_protocol(&call, SVSM_VMPL);
	tcs1 = get_cycles();
	if (index == measure_index) {
		trace_printk("svsm protocol index %lu took %llu cycles\n", index, tcs1 - tcs0);
	}
	native_local_irq_restore(flags);
	return ret;
}

int snp_sgx_enclu(struct sgx_eenter_args *param)
{
	unsigned long flags;
    int ret;
	struct sgx_eenter_args *caa_param;
	struct svsm_call call = {};
    struct svsm_ca *caa;
    u64 caa_pa;

	flags = native_local_irq_save();
    caa = this_cpu_read(svsm_caa);
    caa_pa = this_cpu_read(svsm_caa_pa);
    if (caa == NULL) {
        caa_pa = sev_snp_rd_caa_msr();
        caa = (struct svsm_ca *) __va(caa_pa);
        this_cpu_write(svsm_caa, caa);
        this_cpu_write(svsm_caa_pa, caa_pa);
    }

	call.caa = caa;
	call.rcx = caa_pa + offsetof(struct svsm_ca, svsm_buffer);
	call.rax = SVSM_ENCL_CALL(SVSM_ENCL_ENCLU);

	caa_param = (struct sgx_eenter_args *)caa->svsm_buffer;
	*caa_param = *param;

	ret = svsm_perform_call_protocol(&call, ENCLAVE_VMPL);
	if(!ret) {
		*param = *caa_param;
	}
	native_local_irq_restore(flags);
	return ret;
}

void *get_buffer_page(void)
{
	struct page *buffer;
	// Block if there is no free page
	buffer = mempool_alloc(teevisor_mempool, GFP_KERNEL);
	if (!buffer) {
		pr_info("no available buffer now!");
		return NULL;
	}
	void *vaddr = page_address(buffer);

	return vaddr;
}

void free_buffer_page(void* buffer)
{
	struct page *page;
	page = virt_to_page(buffer);
	mempool_free(page, teevisor_mempool);
}

int alloc_eaddb_buffer(void)
{
	int cpu;

	cpu = num_online_cpus();
	teevisor_mempool = mempool_create_page_pool(cpu, 0);
	if (!teevisor_mempool) {
		pr_err("Failed to create shared mempool for eaddb buffers!\n");
		return -ENOMEM;
	}

	return 0;
}

void release_eaddb_buffer(void)
{
	mempool_destroy(teevisor_mempool);
}