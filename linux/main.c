// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*  Copyright(c) 2016-21 Intel Corporation. */

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/vmalloc.h>
#include <linux/sched/mm.h>
#include <linux/resume_user_mode.h>
#include <asm/msr.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/mce.h>
#include <linux/notifier.h>
#include <asm/sev.h>
#include "driver.h"
#include "encl.h"
#include "protocol.h"
#include "encls.h"

#include <linux/module.h>
#include "version.h"
#include "dcap.h"
#ifndef MSR_IA32_FEAT_CTL
#define MSR_IA32_FEAT_CTL MSR_IA32_FEATURE_CONTROL
#endif

#define MSR_X2APIC_TDCR 0x83E
#define MSR_X2APIC_CURRENT_COUNT 0x839
#define TIMER 0xff

#ifndef FEAT_CTL_LOCKED
#define FEAT_CTL_LOCKED FEATURE_CONTROL_LOCKED
#endif

static void (*k_mmput_async)(struct mm_struct *mm);

// struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
// static int sgx_nr_epc_sections;
// static struct task_struct *ksgxd_tsk;
//static DECLARE_WAIT_QUEUE_HEAD(ksgxd_waitq);
static struct task_struct *kenclaved_tsk;
static DECLARE_WAIT_QUEUE_HEAD(kenclaved_waitq);

/*
 * These variables are part of the state of the reclaimer, and must be accessed
 * with sgx_reclaimer_lock acquired.
 */
//static LIST_HEAD(sgx_active_page_list);

DEFINE_XARRAY(clone_sync_array);
DEFINE_XARRAY(cache_block_array);

// This list is stores all the allocated page.
static LIST_HEAD(sgx_page_pool);
static DEFINE_SPINLOCK(sgx_page_pool_lock);
// static DEFINE_SPINLOCK(sgx_reclaimer_lock);

static struct notifier_block die_notifier;

/*
 * Reset dirty EPC pages to uninitialized state. Laundry can be left with SECS
 * pages whose child pages blocked EREMOVE.
 */
/*
static void sgx_sanitize_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;
	LIST_HEAD(dirty);
	int ret;

	// init_laundry_list is thread-local, no need for a lock:
	while (!list_empty(&section->init_laundry_list)) {
		if (kthread_should_stop())
			return;

		// needed for access to ->page_list:
		spin_lock(&section->lock);

		page = list_first_entry(&section->init_laundry_list,
					struct sgx_epc_page, list);

		ret = __eremove(sgx_get_epc_virt_addr(page));
		if (!ret)
			list_move(&page->list, &section->page_list);
		else
			list_move_tail(&page->list, &dirty);

		spin_unlock(&section->lock);

		cond_resched();
	}

	list_splice(&dirty, &section->init_laundry_list);
}
*/

/*
static bool sgx_reclaimer_age(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	struct sgx_encl *encl = page->encl;
	struct sgx_encl_mm *encl_mm;
	bool ret = true;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
				mmap_read_lock(encl_mm->mm);
#else
		down_read(&encl_mm->mm->mmap_sem);
#endif
		ret = !sgx_encl_test_and_clear_young(encl_mm->mm, page);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
				mmap_read_unlock(encl_mm->mm);
#else
		up_read(&encl_mm->mm->mmap_sem);
#endif

				k_mmput_async(encl_mm->mm);

		if (!ret)
			break;
	}

	srcu_read_unlock(&encl->srcu, idx);

	if (!ret)
		return false;

	return true;
}
*/

/*
static void sgx_reclaimer_block(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	unsigned long addr = page->desc & PAGE_MASK;
	struct sgx_encl *encl = page->encl;
	unsigned long mm_list_version;
	struct sgx_encl_mm *encl_mm;
	struct vm_area_struct *vma;
	int idx, ret;

	do {
		mm_list_version = encl->mm_list_version;

		*/
/* Pairs with smp_rmb() in sgx_encl_mm_add(). */ /*
smp_rmb();

idx = srcu_read_lock(&encl->srcu);

list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
   if (!mmget_not_zero(encl_mm->mm))
	   continue;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
   mmap_read_lock(encl_mm->mm);
#else
   down_read(&encl_mm->mm->mmap_sem);
#endif

   ret = sgx_encl_find(encl_mm->mm, addr, &vma);
   if (!ret && encl == vma->vm_private_data)
	   zap_vma_ptes(vma, addr, PAGE_SIZE);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
   mmap_read_unlock(encl_mm->mm);
#else
   up_read(&encl_mm->mm->mmap_sem);
#endif

			   k_mmput_async(encl_mm->mm);
}

srcu_read_unlock(&encl->srcu, idx);
} while (unlikely(encl->mm_list_version != mm_list_version));

mutex_lock(&encl->lock);

ret = __eblock(sgx_get_epc_virt_addr(epc_page));
if (encls_failed(ret))
ENCLS_WARN(ret, "EBLOCK");

mutex_unlock(&encl->lock);
}
*/

/*
static int __sgx_encl_ewb(struct sgx_epc_page *epc_page, void *va_slot,
			  struct sgx_backing *backing)
{
	struct sgx_pageinfo pginfo;
	int ret;

	pginfo.addr = 0;
	pginfo.secs = 0;

	pginfo.contents = (unsigned long)kmap_atomic(backing->contents);
	pginfo.metadata = (unsigned long)kmap_atomic(backing->pcmd) +
			  backing->pcmd_offset;

	ret = __ewb(&pginfo, sgx_get_epc_virt_addr(epc_page), va_slot);

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata -
						  backing->pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	return ret;
}
*/

/*
static void sgx_ipi_cb(void *info)
{
}
*/

/*
static const cpumask_t *sgx_encl_ewb_cpumask(struct sgx_encl *encl)
{
	cpumask_t *cpumask = &encl->cpumask;
	struct sgx_encl_mm *encl_mm;
	int idx;
	*/
/*
 * Can race with sgx_encl_mm_add(), but ETRACK has already been
 * executed, which means that the CPUs running in the new mm will enter
 * into the enclave with a fresh epoch.
 */
/*
cpumask_clear(cpumask);

idx = srcu_read_lock(&encl->srcu);

list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
 if (!mmget_not_zero(encl_mm->mm))
	 continue;

 cpumask_or(cpumask, cpumask, mm_cpumask(encl_mm->mm));

		 k_mmput_async(encl_mm->mm);
}

srcu_read_unlock(&encl->srcu, idx);

return cpumask;
}
*/

/*
 * Swap page to the regular memory transformed to the blocked state by using
 * EBLOCK, which means that it can no loger be referenced (no new TLB entries).
 *
 * The first trial just tries to write the page assuming that some other thread
 * has reset the count for threads inside the enlave by using ETRACK, and
 * previous thread count has been zeroed out. The second trial calls ETRACK
 * before EWB. If that fails we kick all the HW threads out, and then do EWB,
 * which should be guaranteed the succeed.
 */
/*
static void sgx_encl_ewb(struct sgx_epc_page *epc_page,
			 struct sgx_backing *backing)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_va_page *va_page;
	unsigned int va_offset;
	void *va_slot;
	int ret;

	encl_page->desc &= ~SGX_ENCL_PAGE_BEING_RECLAIMED;

	va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
				   list);
	va_offset = sgx_alloc_va_slot(va_page);
	va_slot = sgx_get_epc_virt_addr(va_page->epc_page) + va_offset;
	if (sgx_va_page_full(va_page))
		list_move_tail(&va_page->list, &encl->va_pages);

	ret = __sgx_encl_ewb(epc_page, va_slot, backing);
	if (ret == SGX_NOT_TRACKED) {
		ret = __etrack(sgx_get_epc_virt_addr(encl->secs.epc_page));
		if (ret) {
			if (encls_failed(ret))
				ENCLS_WARN(ret, "ETRACK");
		}

		ret = __sgx_encl_ewb(epc_page, va_slot, backing);
		if (ret == SGX_NOT_TRACKED) {
			*/
/*
 * Slow path, send IPIs to kick cpus out of the
 * enclave.  Note, it's imperative that the cpu
 * mask is generated *after* ETRACK, else we'll
 * miss cpus that entered the enclave between
 * generating the mask and incrementing epoch.
 */
/*
on_each_cpu_mask(sgx_encl_ewb_cpumask(encl),
	  sgx_ipi_cb, NULL, 1);
ret = __sgx_encl_ewb(epc_page, va_slot, backing);
}
}

if (ret) {
if (encls_failed(ret))
ENCLS_WARN(ret, "EWB");

sgx_free_va_slot(va_page, va_offset);
} else {
encl_page->desc |= va_offset;
encl_page->va_page = va_page;
}
}
*/

/*
static void sgx_reclaimer_write(struct sgx_epc_page *epc_page,
				struct sgx_backing *backing)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_backing secs_backing;
	int ret;

	mutex_lock(&encl->lock);

	sgx_encl_ewb(epc_page, backing);
	encl_page->epc_page = NULL;
	encl->secs_child_cnt--;

	if (!encl->secs_child_cnt && test_bit(SGX_ENCL_INITIALIZED, &encl->flags)) {
		ret = sgx_encl_get_backing(encl, PFN_DOWN(encl->size),
					   &secs_backing);
		if (ret)
			goto out;

		sgx_encl_ewb(encl->secs.epc_page, &secs_backing);

		sgx_free_epc_page(encl->secs.epc_page);
		encl->secs.epc_page = NULL;

		sgx_encl_put_backing(&secs_backing, true);
	}

out:
	mutex_unlock(&encl->lock);
}
*/

/*
 * Take a fixed number of pages from the head of the active page pool and
 * reclaim them to the enclave's private shmem files. Skip the pages, which have
 * been accessed since the last scan. Move those pages to the tail of active
 * page pool so that the pages get scanned in LRU like fashion.
 *
 * Batch process a chunk of pages (at the moment 16) in order to degrade amount
 * of IPI's and ETRACK's potentially required. sgx_encl_ewb() does degrade a bit
 * among the HW threads with three stage EWB pipeline (EWB, ETRACK + EWB and IPI
 * + EWB) but not sufficiently. Reclaiming one page at a time would also be
 * problematic as it would increase the lock contention too much, which would
 * halt forward progress.
 */
/*
static void sgx_reclaim_pages(void)
{
	struct sgx_epc_page *chunk[SGX_NR_TO_SCAN];
	struct sgx_backing backing[SGX_NR_TO_SCAN];
	struct sgx_epc_section *section;
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	pgoff_t page_index;
	int cnt = 0;
	int ret;
	int i;

	spin_lock(&sgx_reclaimer_lock);
	for (i = 0; i < SGX_NR_TO_SCAN; i++) {
		if (list_empty(&sgx_active_page_list))
			break;

		epc_page = list_first_entry(&sgx_active_page_list,
						struct sgx_epc_page, list);
		list_del_init(&epc_page->list);
		encl_page = epc_page->owner;

		if (kref_get_unless_zero(&encl_page->encl->refcount) != 0)
			chunk[cnt++] = epc_page;
		else*/
/* The owner is freeing the page. No need to add the
 * page back to the list of reclaimable pages.
 */
/*epc_page->flags &= ~SGX_EPC_PAGE_RECLAIMER_TRACKED;
}
spin_unlock(&sgx_reclaimer_lock);

for (i = 0; i < cnt; i++) {
epc_page = chunk[i];
encl_page = epc_page->owner;

if (!sgx_reclaimer_age(epc_page))
goto skip;

page_index = PFN_DOWN(encl_page->desc - encl_page->encl->base);
ret = sgx_encl_get_backing(encl_page->encl, page_index, &backing[i]);
if (ret)
goto skip;

mutex_lock(&encl_page->encl->lock);
encl_page->desc |= SGX_ENCL_PAGE_BEING_RECLAIMED;
mutex_unlock(&encl_page->encl->lock);
continue;

skip:
spin_lock(&sgx_reclaimer_lock);
list_add_tail(&epc_page->list, &sgx_active_page_list);
spin_unlock(&sgx_reclaimer_lock);

kref_put(&encl_page->encl->refcount, sgx_encl_release);

chunk[i] = NULL;
}

for (i = 0; i < cnt; i++) {
epc_page = chunk[i];
if (epc_page)
sgx_reclaimer_block(epc_page);
}

for (i = 0; i < cnt; i++) {
epc_page = chunk[i];
if (!epc_page)
continue;

encl_page = epc_page->owner;
sgx_reclaimer_write(epc_page, &backing[i]);
sgx_encl_put_backing(&backing[i], true);

kref_put(&encl_page->encl->refcount, sgx_encl_release);
epc_page->flags &= ~SGX_EPC_PAGE_RECLAIMER_TRACKED;

section = &sgx_epc_sections[epc_page->section];
spin_lock(&section->lock);
list_add_tail(&epc_page->list, &section->page_list);
section->free_cnt++;
spin_unlock(&section->lock);
}
}
*/
/*
static unsigned long sgx_nr_free_pages(void)
{
	unsigned long cnt = 0;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++)
		cnt += sgx_epc_sections[i].free_cnt;

	return cnt;
}
*/

/*
static bool sgx_should_reclaim(unsigned long watermark)
{
	return sgx_nr_free_pages() < watermark &&
		   !list_empty(&sgx_active_page_list);
}
*/

/*
static int ksgxd(void *p)
{
	int i;

	set_freezable();
	*/
/*
 * Sanitize pages in order to recover from kexec(). The 2nd pass is
 * required for SECS pages, whose child pages blocked EREMOVE.
 */
/*
for (i = 0; i < sgx_nr_epc_sections; i++)
	sgx_sanitize_section(&sgx_epc_sections[i]);

for (i = 0; i < sgx_nr_epc_sections; i++) {
	sgx_sanitize_section(&sgx_epc_sections[i]);

	// Should never happen.
	if (!list_empty(&sgx_epc_sections[i].init_laundry_list))
		WARN(1, "EPC section %d has unsanitized pages.\n", i);
}


while (!kthread_should_stop()) {
	if (try_to_freeze())
		continue;

	wait_event_freezable(ksgxd_waitq,
				 kthread_should_stop() ||
				 sgx_should_reclaim(SGX_NR_HIGH_PAGES));

	if (sgx_should_reclaim(SGX_NR_HIGH_PAGES))
		sgx_reclaim_pages();

	cond_resched();
}

return 0;
}
*/

/*
static bool __init sgx_page_reclaimer_init(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(ksgxd, NULL, "ksgxd");
	if (IS_ERR(tsk))
		return false;

	ksgxd_tsk = tsk;

	return true;
}
*/
/*
// Based on arch/x86/kernel/cpu/intel.c
static bool detect_sgx(struct cpuinfo_x86 *c)
{
	unsigned long long fc;

	rdmsrl(MSR_IA32_FEAT_CTL, fc);
	if (!(fc & FEAT_CTL_LOCKED)) {
		pr_err_once("The feature control MSR is not locked\n");
		return false;
	}

	if (!(fc & FEAT_CTL_SGX_ENABLED)) {
		pr_err_once("SGX is not enabled in IA32_FEATURE_CONTROL MSR\n");
		return false;
	}

	if (!cpu_has(c, X86_FEATURE_SGX)) {
		pr_err_once("SGX1 instruction set is not supported\n");
		return false;
	}

	if (!(fc & FEAT_CTL_SGX_LC_ENABLED)) {
		pr_err_once("Locked launch policy not supported\n");
		return false;
	}

	return true;
}
*/

static inline bool detect_svsm(void)
{
	return snp_vmpl > 0;
}

/*
static struct sgx_epc_page *__sgx_alloc_epc_page_from_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	spin_lock(&section->lock);

	if (list_empty(&section->page_list)) {
		spin_unlock(&section->lock);
		return NULL;
	}

	page = list_first_entry(&section->page_list, struct sgx_epc_page, list);
	list_del_init(&page->list);
	section->free_cnt--;

	spin_unlock(&section->lock);
	return page;
}
*/

/**
 * __sgx_alloc_epc_page() - Allocate an EPC page
 *
 * Iterate through EPC sections and borrow a free EPC page to the caller. When a
 * page is no longer needed it must be released with sgx_free_epc_page().
 *
 * Return:
 *   an EPC page,
 *   -errno on error
 */
/*
struct sgx_epc_page *__sgx_alloc_epc_page(void)
{
	struct sgx_epc_section *section;
	struct sgx_epc_page *page;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];

		page = __sgx_alloc_epc_page_from_section(section);
		if (page)
			return page;
	}

	return ERR_PTR(-ENOMEM);
}
*/

struct sgx_epc_page *__sgx_alloc_epc_page(void)
{
	struct sgx_epc_page *epc_page;
	epc_page = vmalloc(sizeof(struct sgx_epc_page));
	atomic_long_set_release(&epc_page->counter, 1);
	epc_page->flags = 0;
	epc_page->owner = NULL;
	struct page *page = alloc_page(GFP_KERNEL);

	if (!page)
	{
		return ERR_PTR(-ENOMEM);
	}

	epc_page->pfn = page_to_pfn(page);
	spin_lock(&sgx_page_pool_lock);
	list_add_tail(&epc_page->list, &sgx_page_pool);
	spin_unlock(&sgx_page_pool_lock);
	return epc_page;
}

/**
 * sgx_mark_page_reclaimable() - Mark a page as reclaimable
 * @page:	EPC page
 *
 * Mark a page as reclaimable and add it to the active page list. Pages
 * are automatically removed from the active list when freed.
 */
/*
void sgx_mark_page_reclaimable(struct sgx_epc_page *page)
{
	spin_lock(&sgx_reclaimer_lock);
	page->flags |= SGX_EPC_PAGE_RECLAIMER_TRACKED;
	list_add_tail(&page->list, &sgx_active_page_list);
	spin_unlock(&sgx_reclaimer_lock);
}
*/

/**
 * sgx_unmark_page_reclaimable() - Remove a page from the reclaim list
 * @page:	EPC page
 *
 * Clear the reclaimable flag and remove the page from the active page list.
 *
 * Return:
 *   0 on success,
 *   -EBUSY if the page is in the process of being reclaimed
 */
/*
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page)
{
	spin_lock(&sgx_reclaimer_lock);
	if (page->flags & SGX_EPC_PAGE_RECLAIMER_TRACKED) {*/
/* The page is being reclaimed. */ /*
 if (list_empty(&page->list)) {
	 spin_unlock(&sgx_reclaimer_lock);
	 return -EBUSY;
 }

 list_del(&page->list);
 page->flags &= ~SGX_EPC_PAGE_RECLAIMER_TRACKED;
}
spin_unlock(&sgx_reclaimer_lock);

return 0;
}
*/

struct sgx_epc_page *sgx_alloc_epc_page_cache(void *owner, unsigned long pfn)
{
	struct sgx_epc_page *epc_page;
	epc_page = vmalloc(sizeof(struct sgx_epc_page));
	if (!epc_page) {
		return NULL;
	}
	atomic_long_set_release(&epc_page->counter, 1);
	//pr_info("sgx_alloc_epc_page_cache pfn: %lx", pfn);
	epc_page->pfn = pfn;
	epc_page->flags = SGX_EPC_PAGE_BLOCK_CACHE;
	epc_page->owner = owner;

	spin_lock(&sgx_page_pool_lock);
	list_add_tail(&epc_page->list, &sgx_page_pool);
	spin_unlock(&sgx_page_pool_lock);

	
	return epc_page;
}

/**
 * sgx_alloc_epc_page() - Allocate an EPC page
 * @owner:	the owner of the EPC page
 * @reclaim:	reclaim pages if necessary
 *
 * Iterate through EPC sections and borrow a free EPC page to the caller. When a
 * page is no longer needed it must be released with sgx_free_epc_page(). If
 * @reclaim is set to true, directly reclaim pages when we are out of pages. No
 * mm's can be locked when @reclaim is set to true.
 *
 * Finally, wake up ksgxd when the number of pages goes below the watermark
 * before returning back to the caller.
 *
 * Return:
 *   an EPC page,
 *   -errno on error
 */
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim)
{
	struct sgx_epc_page *page;

	for (;;)
	{
		page = __sgx_alloc_epc_page();
		if (!IS_ERR(page))
		{
			page->owner = owner;
			break;
		}

		/*
		if (list_empty(&sgx_active_page_list))
			return ERR_PTR(-ENOMEM);
		*/

		// If reclaim is not supported, just return enomem
		return ERR_PTR(-ENOMEM);

		if (!reclaim)
		{
			page = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current))
		{
			page = ERR_PTR(-ERESTARTSYS);
			break;
		}

		// sgx_reclaim_pages();
		// cond_resched();
	}

	/*
	if (sgx_should_reclaim(SGX_NR_LOW_PAGES))
		wake_up(&ksgxd_waitq);
	*/

	return page;
}

/**
 * sgx_free_epc_page() - Free an EPC page
 * @page:	an EPC page
 *
 * Call EREMOVE for an EPC page and insert it back to the list of free pages.
 */
/*
void sgx_free_epc_page(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = &sgx_epc_sections[page->section];
	int ret;

	WARN_ON_ONCE(page->flags & SGX_EPC_PAGE_RECLAIMER_TRACKED);

	ret = __eremove(sgx_get_epc_virt_addr(page));
	if (WARN_ONCE(ret, "EREMOVE returned %d (0x%x)", ret, ret))
		return;

	spin_lock(&section->lock);
	list_add_tail(&page->list, &section->page_list);
	section->free_cnt++;
	spin_unlock(&section->lock);
}
*/

/**
 * sgx_free_epc_page() - Free an EPC page
 * @page:	an EPC page
 *
 * Call EREMOVE for an EPC page
 */
void sgx_free_epc_page(struct sgx_epc_page *epc_page, unsigned long secs)
{
	int ret;

	//WARN_ON_ONCE(epc_page->flags & SGX_EPC_PAGE_RECLAIMER_TRACKED);
retry:
	ret = __eremove(sgx_get_epc_phys_addr(epc_page), secs);

	// Cloned enclave share one epcm with parent, in epcm contention cases, retry
	if(ret == (ENCLS_FAULT_FLAG | X86_TRAP_GP)) {
		pr_info("sgx_free_epc_page EPCM lock contention, retry\n");
		goto retry;
	}

	if (ret)
	{
		pr_err("EREMOVE page paddr: 0x%lx returned %d (0x%x), vaddr: 0x%lx", 
				sgx_get_epc_phys_addr(epc_page), ret, ret, epc_page->owner->desc);
		return;
	}

	long epc_counter = atomic_long_dec_return_release(&epc_page->counter);
	// unsigned long page_vaddr;
	// if (epc_page->owner) {
	// 	page_vaddr = epc_page->owner->desc;
	// } else {
	// 	page_vaddr = 0;
	// }
	
	// // pr_info("sgx_free_epc_page epc_counter: %ld paddr: 0x%lx vaddr: 0x%lx\n", 
	// // 	epc_counter,sgx_get_epc_phys_addr(epc_page), page_vaddr);
	if (epc_counter == 0) {
		spin_lock(&sgx_page_pool_lock);
		list_del_init(&epc_page->list);
		spin_unlock(&sgx_page_pool_lock);
		if (!(epc_page->flags & SGX_EPC_PAGE_BLOCK_CACHE)) {
			struct page *page = pfn_to_page(epc_page->pfn);
			__free_page(page);
		} else {
			struct enclave_cache_block_entry* block_entry;
			unsigned long size_pages;

			block_entry = xa_find(&cache_block_array, &epc_page->pfn, ULONG_MAX, XA_PRESENT);
			if (!block_entry) {
				pr_err("Invalid cache epc_page, cannot find the backend block!");
			}

			long block_counter = atomic_long_dec_return_acquire(&block_entry->counter);
			//pr_info("block_counter %ld\n", block_counter);
			if (block_counter == 0 && atomic_long_read_acquire(&block_entry->consumed)) {
				//pr_info("Free page block\n");
				size_pages = (block_entry->end - block_entry->start + PAGE_SIZE) >> PAGE_SHIFT;
				free_pages((unsigned long)phys_to_virt(block_entry->start), fls(size_pages) - 1);
				xa_erase(&cache_block_array, PFN_DOWN(block_entry->end));
				kfree(block_entry);
			}
		}
		vfree(epc_page);
	}

}

/**
 * sgx_free_epc_page_pre_eadd() - Free an EPC page
 * @page:	an EPC page
 *
 * free the allocated epc_page struct, do not call eremove
 */
void sgx_free_epc_page_pre_eadd(struct sgx_epc_page *epc_page)
{
	struct page *page = pfn_to_page(epc_page->pfn);

	spin_lock(&sgx_page_pool_lock);
	list_del_init(&epc_page->list);
	spin_unlock(&sgx_page_pool_lock);
	__free_page(page);
	vfree(epc_page);
}

/*
static bool __init sgx_setup_epc_section(u64 phys_addr, u64 size,
					 unsigned long index,
					 struct sgx_epc_section *section)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long i;

	section->virt_addr = memremap(phys_addr, size, MEMREMAP_WB);
	if (!section->virt_addr)
		return false;

	section->pages = vmalloc(nr_pages * sizeof(struct sgx_epc_page));
	if (!section->pages) {
		memunmap(section->virt_addr);
		return false;
	}

	section->phys_addr = phys_addr;
	spin_lock_init(&section->lock);
	INIT_LIST_HEAD(&section->page_list);
	INIT_LIST_HEAD(&section->init_laundry_list);

	for (i = 0; i < nr_pages; i++) {
		section->pages[i].section = index;
		section->pages[i].flags = 0;
		section->pages[i].owner = NULL;
		list_add_tail(&section->pages[i].list, &section->init_laundry_list);
	}

	section->free_cnt = nr_pages;
	return true;
}
*/

/**
 * A section metric is concatenated in a way that @low bits 12-31 define the
 * bits 12-31 of the metric and @high bits 0-19 define the bits 32-51 of the
 * metric.
 */
/*
static inline u64 __init sgx_calc_section_metric(u64 low, u64 high)
{
	return (low & GENMASK_ULL(31, 12)) +
		   ((high & GENMASK_ULL(19, 0)) << 32);
}
*/
/*
static bool __init sgx_page_cache_init(void)
{
	u32 eax, ebx, ecx, edx, type;
	u64 pa, size;
	int i;

	for (i = 0; i < ARRAY_SIZE(sgx_epc_sections); i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_EPC, &eax, &ebx, &ecx, &edx);

		type = eax & SGX_CPUID_EPC_MASK;
		if (type == SGX_CPUID_EPC_INVALID)
			break;

		if (type != SGX_CPUID_EPC_SECTION) {
			pr_err_once("Unknown EPC section type: %u\n", type);
			break;
		}

		pa   = sgx_calc_section_metric(eax, ebx);
		size = sgx_calc_section_metric(ecx, edx);

		pr_info("EPC section 0x%llx-0x%llx\n", pa, pa + size - 1);

		if (!sgx_setup_epc_section(pa, size, i, &sgx_epc_sections[i])) {
			pr_err("No free memory for an EPC section\n");
			break;
		}

		sgx_nr_epc_sections++;
	}

	if (!sgx_nr_epc_sections) {
		pr_err("There are zero EPC sections.\n");
		return false;
	}

	return true;
}
*/

static struct sgx_encl *get_encl_from_vaddr(unsigned long vaddr)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct task_struct *tsk;
	struct xarray *enclave_array;
	struct sgx_encl *encl = NULL;
	int ret;

	tsk = current;
	mm = tsk->mm;

	ret = sgx_encl_find(mm, vaddr, &vma);

	if (!ret)
	{
		enclave_array = vma->vm_private_data;
		encl = xa_load(enclave_array, (unsigned long)vma->vm_mm);
	}

	return encl;
}

struct vdso_exception_table_entry
{
	int insn, fixup;
};

// eenter is always called in the vdso area, signal may be downgraded there.
static bool try_fixup_vdso_exception(struct pt_regs *regs, int trapnr,
									 unsigned long error_code, unsigned long fault_addr)
{
	const struct vdso_image *image = current->mm->context.vdso_image;
	const struct vdso_exception_table_entry *extable;
	unsigned int nr_entries, i;
	unsigned long base;

	/*
	 * Do not attempt to fixup #DB or #BP.  It's impossible to identify
	 * whether or not a #DB/#BP originated from within an SGX enclave and
	 * SGX enclaves are currently the only use case for vDSO fixup.
	 */
	if (trapnr == X86_TRAP_DB || trapnr == X86_TRAP_BP)
		return false;

	if (!current->mm->context.vdso)
		return false;

	base = (unsigned long)current->mm->context.vdso + image->extable_base;
	nr_entries = image->extable_len / (sizeof(*extable));
	extable = image->extable;

	for (i = 0; i < nr_entries; i++)
	{
		if (regs->ip == base + extable[i].insn)
		{
			regs->ip = base + extable[i].fixup;
			regs->di = trapnr;
			regs->si = error_code;
			regs->dx = fault_addr;
			return true;
		}
	}

	return false;
}

static void handle_pf(struct pt_regs *regs,
					  unsigned long error_code,
					  unsigned long address,
					  struct sgx_encl *encl)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct sgx_encl_sync_page *sync_entry;
	struct sgx_encl_sync_page *new_sync_entry;
	struct sgx_mm_sync_array *sync_array_entry;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_DEFAULT;
	unsigned int gup_flags = 0;
	struct page *page = NULL;
	struct kernel_siginfo info;
	bool write;
	u64 paddr;
	int ret;

	tsk = current;
	mm = tsk->mm;
	clear_siginfo(&info);

	//pr_info("try to handle pf address:%lx, error_code: %lx", address, error_code);
	if (error_code & X86_PF_WRITE)
	{
		flags |= FAULT_FLAG_WRITE;
		gup_flags |= FOLL_WRITE;
	}
	if (error_code & X86_PF_INSTR)
		flags |= FAULT_FLAG_INSTRUCTION;

	flags |= FAULT_FLAG_USER;

retry:
	down_read(&mm->mmap_lock);
	vma = vma_lookup(mm, address);
	if (!vma)
	{
		force_sig(SIGSEGV);
		// force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)address);
		up_read(&mm->mmap_lock);
		return;
	}

	fault = handle_mm_fault(vma, address, flags, regs);

	//pr_info("try to handle pf address:%lx, error_code: %lx, return: %x", address, error_code, fault);

	// If VM_FAULT_COMPLETED is set, mmap_lock is released
	if (fault & VM_FAULT_COMPLETED)
	{
		down_read(&mm->mmap_lock);
	}

	if (fault & VM_FAULT_RETRY)
	{
		flags |= FAULT_FLAG_TRIED;
		goto retry;
	}

	if (!(fault & VM_FAULT_ERROR))
	{
		// Try to sync the page if the page is outside the enclave
		if (!vaddr_inside_enclave(encl, address))
		{
			sync_array_entry = xa_load(&encl->mm_sync_array, (unsigned long)mm);

			if (!sync_array_entry)
				goto sync_fail_before_lock;
			mutex_lock(&sync_array_entry->sync_lock);

			ret = get_user_pages(address, 1, gup_flags, &page);
			if (ret < 1)
			{
				if (!fatal_signal_pending(current)) {
					pr_err("Cannot get the physical address of a user page!\n");
				}
				goto sync_fail;
			}

			/*
			 * Use the page returned by GUP as the source of truth.  Walking the
			 * page tables separately can race with COW, migration and reclaim,
			 * resulting in a different page being sent to the supervisor than
			 * the page pinned below.
			 *
			 * A read fault is initially synchronized read-only.  A later write
			 * fault pins the page with FOLL_WRITE (breaking COW if necessary)
			 * and upgrades the supervisor mapping.
			 */
			write = error_code & X86_PF_WRITE;
			paddr = page_to_phys(page) | 0x1;
			if (write)
				paddr |= 0x2;

			sync_entry = xa_load(&sync_array_entry->array, PFN_DOWN(address));

			// If the vaddr has already been synced, first try to unsync
			if (sync_entry)
			{
				if (sync_entry->paddr == paddr)
				{
					// The page is already synced
					mutex_unlock(&sync_array_entry->sync_lock);
					put_page(page);
					up_read(&mm->mmap_lock);
					return;
				}


				// pr_info("eunsync address: 0x%lx, paddr: 0x%llx", address, sync_entry->paddr);
				ret = sgx_encl_eunsync(encl, sync_entry->paddr, address, (u64)mm);
				if (ret)
				{
					pr_err("eunsync has an error with vaddr:0x%lx, paddr:0x%llx\n",
						   address, sync_entry->paddr);
					goto sync_fail_page;
				}

				xa_erase(&sync_array_entry->array, PFN_DOWN(address));
				if (sync_entry->paddr & 0x2)
					set_page_dirty(sync_entry->page);
				put_page(sync_entry->page);
				encl->sync_page_cnt--;
				kfree(sync_entry);
			}

			new_sync_entry = kzalloc(sizeof(*new_sync_entry), GFP_KERNEL);
			if (!new_sync_entry)
			{
				pr_err("esync OOM");
				goto sync_fail_page;
			}

			ret = sgx_encl_esync(encl, paddr, address & PAGE_MASK, true,
						 write, false, (u64)mm);
			if (ret)
			{
				pr_err("esync has an error with vaddr:0x%lx, paddr:0x%llx, rw: 1%d\n",
					   address, paddr, write);
				kfree(new_sync_entry);
				goto sync_fail_page;
			}

			new_sync_entry->page = page;
			new_sync_entry->paddr = paddr;
			ret = xa_insert(&sync_array_entry->array, PFN_DOWN(address),
					new_sync_entry, GFP_KERNEL);
			if (ret) {
				pr_err("esync OOM");
				if (sgx_encl_eunsync(encl, paddr, address, (u64)mm))
					pr_err("failed to roll back esync for vaddr:0x%lx, paddr:0x%llx\n",
						   address, paddr);
				kfree(new_sync_entry);
				goto sync_fail_page;
			}

			encl->sync_page_cnt++;
			mutex_unlock(&sync_array_entry->sync_lock);
			// hold the page if esync is successful
		}
		up_read(&mm->mmap_lock);
		return;
	}

	up_read(&mm->mmap_lock);
	// Here just kill the current task if OOM.
	if (fault & VM_FAULT_OOM)
	{
		force_sig(SIGKILL);
	}
	else
	{
		if (fault & (VM_FAULT_SIGBUS | VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
		{
			if (try_fixup_vdso_exception(regs, X86_TRAP_PF, error_code, address))
				return;
			info.si_signo = SIGBUS;
			info.si_code = BUS_ADRERR;
			info.si_addr = (void __user *)address;
			send_sig_info(SIGBUS, &info, current);
		}
		else if (fault & VM_FAULT_SIGSEGV)
		{
			if (try_fixup_vdso_exception(regs, X86_TRAP_PF, error_code, address))
				return;
			info.si_signo = SIGSEGV;
			info.si_code = vaddr_inside_enclave(encl, address) ? SEGV_ACCERR : SEGV_MAPERR;
			info.si_addr = (void __user *)address;
			send_sig_info(SIGSEGV, &info, current);
		}
		else
		{
			pr_err("PF handling bug!\n");
			force_sig(SIGKILL);
		}
	}

	return;

sync_fail_page:
	put_page(page);
sync_fail:
	mutex_unlock(&sync_array_entry->sync_lock);
sync_fail_before_lock:
	force_sig(SIGKILL);
	up_read(&mm->mmap_lock);
	return;
}

static void do_trap(int trapnr, int signr, struct pt_regs *regs,
					long error_code, int sicode, void __user *addr)
{
	if (try_fixup_vdso_exception(regs, trapnr, error_code, (unsigned long)addr))
		return;

	if (!sicode)
		force_sig(signr);
	else {
		struct kernel_siginfo info;
		clear_siginfo(&info);
		info.si_signo = signr;
		info.si_code = sicode;
		info.si_addr = addr;
		send_sig_info(signr, &info, current);
	}
}

static __attribute__((unused))
void dump_sgx_args(struct sgx_eenter_args *args)
{
	trace_printk("SGX EENTER args:\n");
	trace_printk("  tcs_paddr = 0x%016llx\n", args->tcs_paddr);
	trace_printk("  rax = 0x%016llx  rbx = 0x%016llx  rcx = 0x%016llx  rdx = 0x%016llx\n",
				 args->rax, args->rbx, args->rcx, args->rdx);
	trace_printk("  rsi = 0x%016llx  rdi = 0x%016llx  rsp = 0x%016llx  rbp = 0x%016llx\n",
				 args->rsi, args->rdi, args->rsp, args->rbp);
	trace_printk("  r8  = 0x%016llx  r9  = 0x%016llx  r10 = 0x%016llx  r11 = 0x%016llx\n",
				 args->r8, args->r9, args->r10, args->r11);
	trace_printk("  r12 = 0x%016llx  r13 = 0x%016llx  r14 = 0x%016llx  r15 = 0x%016llx\n",
				 args->r12, args->r13, args->r14, args->r15);
	trace_printk("  rip = 0x%016llx  rflags = 0x%016llx  cr2 = 0x%016llx\n",
				 args->rip, args->rflags, args->cr2);
	trace_printk("  mxcsr = 0x%08x  fcw = 0x%04x  fsw = 0x%04x\n",
				 args->mxcsr, args->fcw, args->fsw);
	trace_printk("  exit_reason = 0x%016llx  vector = 0x%016llx  error_code = 0x%016llx\n",
				 args->exit_reason, args->vector, args->error_code);
}

static void emulate_enclu(struct callback_head *work)
{
	struct pt_regs *regs;
	struct sgx_eenter_args param = {0};
	struct sgx_encl_page *entry;
	u64 tcs_vaddr;
	struct sgx_encl *encl;
	struct task_struct *tsk;
	struct mm_struct *mm;
	int ret;

	tsk = current;
	mm = tsk->mm;
	regs = task_pt_regs(current);
	tcs_vaddr = regs->bx;
	encl = get_encl_from_vaddr(tcs_vaddr);
	if (!encl)
	{
		pr_err("emulate_enclu get enclave failed");
		do_trap(X86_TRAP_PF, SIGSEGV, regs, 0, 0, (void *)regs->bx);
		kfree(work);
		return;
	}

	if (test_bit(SGX_ENCL_CLONE, &encl->flags)) {
		kfree(work);
		cond_resched();
		return;
	}

	entry = xa_load(&encl->tcs_array, PFN_DOWN(tcs_vaddr));
	if (!entry)
	{
		pr_err("emulate_enclu get tcs_array failed");
		do_trap(X86_TRAP_PF, SIGSEGV, regs, 0, 0, (void *)regs->bx);
		kfree(work);
		return;
	}

	//rdmsrl(MSR_X2APIC_TDCR, tdcr);
	//rdmsrl(MSR_X2APIC_CURRENT_COUNT, tmcct);

	param.tcs_paddr = PFN_PHYS(entry->epc_page->pfn);
	param.rax = regs->ax;
	param.rbx = regs->bx;
	param.rcx = regs->cx;
	param.rdx = regs->dx;
	param.rsi = regs->si;
	param.rdi = regs->di;
	param.rsp = regs->sp;
	param.rbp = regs->bp;
	param.r8 = regs->r8;
	param.r9 = regs->r9;
	param.r10 = regs->r10;
	param.r11 = regs->r11;
	param.r12 = regs->r12;
	param.r13 = regs->r13;
	param.r14 = regs->r14;
	param.r15 = regs->r15;
	param.rip = regs->ip;
	param.rflags = regs->flags;
	param.mm = (u64)mm;
	//param.apic_tdcr = tdcr;
	//param.apic_tmcct = tmcct;
	//trace_printk("input param: ");
	//dump_sgx_args(&param);
	// TODO: error is hiden here, should return exact error if enclu failed
	//       now just return GP.
	// pr_info("cpu %d run enclu, tcs_paddr: 0x%llx, mm: 0x%llx", smp_processor_id(), param.tcs_paddr, param.mm);
	ret = snp_sgx_enclu(&param);
	// pr_info("cpu %d return from enclu, param.exit_reason %lld", smp_processor_id(), param.exit_reason);
	//trace_printk("output param: ");
	//dump_sgx_args(&param);
	if (ret == SGX_ENCLAVE_CLONING) {
		cond_resched();
		return;
	}
	if (ret)
	{
		pr_err("enclu failed with ret: %d", ret);
		do_trap(X86_TRAP_GP, SIGSEGV, regs, 0, 0, (void *)regs->ip);
		return;
	}

	regs->ax = param.rax;
	regs->bx = param.rbx;
	regs->cx = param.rcx;
	regs->dx = param.rdx;
	regs->si = param.rsi;
	regs->di = param.rdi;
	regs->sp = param.rsp;
	regs->bp = param.rbp;
	regs->r8 = param.r8;
	regs->r9 = param.r9;
	regs->r10 = param.r10;
	regs->r11 = param.r11;
	regs->r12 = param.r12;
	regs->r13 = param.r13;
	regs->r14 = param.r14;
	regs->r15 = param.r15;
	regs->ip = param.rip;

	//pr_info("param.exit_reason %d", param.exit_reason);
	switch (param.exit_reason)
	{
	case EXIT_REASON_INTERRUPT:
		current->thread.trap_nr = param.vector;
		current->thread.error_code = param.error_code;
		//pr_info("EXIT_REASON_INTERRUPT vector:%lld", param.vector);
		switch (param.vector)
		{
		case X86_TRAP_DE:
			do_trap(X86_TRAP_DE, SIGFPE, regs, 0, FPE_INTDIV, (void __user *)param.rip);
			break;
		case X86_TRAP_DB:
			// Debug has no fixup_vdso path
			force_sig(SIGTRAP);
			break;
		case X86_TRAP_BP:
			do_trap(X86_TRAP_BP, SIGTRAP, regs, 0, 0, NULL);
			break;
		case X86_TRAP_OF:
		case X86_TRAP_BR:
		case X86_TRAP_GP:
			do_trap(param.exit_reason, SIGSEGV, regs, 0, 0, NULL);
			break;
		case X86_TRAP_UD:
			do_trap(X86_TRAP_UD, SIGILL, regs, 0, ILL_ILLOPN, (void __user *)param.rip);
			break;
		case X86_TRAP_SS:
			do_trap(X86_TRAP_SS, SIGBUS, regs, 0, 0, NULL);
			break;
		case X86_TRAP_PF:
			handle_pf(regs, param.error_code, param.cr2, encl);
			break;
		// since the floating point is unknown, return FPE_FLTUNK
		case X86_TRAP_MF:
			do_trap(X86_TRAP_MF, SIGFPE, regs, 0, FPE_FLTUNK, (void __user *)param.rip);
			break;
		case X86_TRAP_AC:
			do_trap(X86_TRAP_AC, SIGBUS, regs, 0, 0, NULL);
			break;
		case X86_TRAP_MC:
			do_machine_check(regs);
			break;
		case X86_TRAP_XF:
			do_trap(X86_TRAP_XF, SIGFPE, regs, 0, FPE_FLTUNK, (void __user *)param.rip);
			break;
		// NMI should be injected back again by the svsm firmware,
		// and continue executing
		case X86_TRAP_NMI:
			pr_err("nmi\n");
			break;
		default:
			pr_info("Unexpected interrupt %lld in enclave\n", param.vector);
			break;
		}
		break;
	case EXIT_REASON_EEXIT:
		//pr_info("EXIT_REASON_EEXIT");
		break;
	case EXIT_REASON_TIMER:
		cond_resched();
		break;
	case EXIT_REASON_CLONE:
		set_bit(SGX_ENCL_CLONE, &encl->flags);
		break;
	// No enough cache for the copy on write. Add new cache block.
	case EXIT_REASON_CACHE:
		mutex_lock(&encl->lock);
		ret = add_enclave_cache_block(encl);
		mutex_unlock(&encl->lock);
		if (ret) {
			do_trap(X86_TRAP_GP, SIGSEGV, regs, 0, 0, (void *)regs->ip);
		}
		break;
	// No free slot in the clone sync page, handle the page here.
	case EXIT_REASON_NO_FREE_SLOT:
		try_do_sync_page(encl);
		break;
	default:
		break;
	}
	kfree(work);
}

void try_do_sync_page(struct sgx_encl *encl)
{
	struct enclave_clone_sync_entry* sync_entry;
	sync_entry = xa_load(&clone_sync_array, encl->secs.epc_page->pfn);
	if (!sync_entry) {
		pr_err("sync page does not exist in the clone_sync_array\n");
		return;
	}
	sync_page_once(sync_entry, false);
	return;
}

// Enclave lock should be acquire before calling the function
int add_enclave_cache_block(struct sgx_encl *encl)
{
	bool get_block = false;
	unsigned long block_addr;
	struct enclave_cache_block_entry *block_entry;
	int ret;

	// In multi thread cases, if a block is already added, just return
	if (encl->current_cache_block && !atomic_long_read_acquire(&encl->current_cache_block->consumed))
	{
		return 0;
	}

	for(unsigned int order = 10; order >= 0; order--) {
		block_addr = __get_free_pages(GFP_KERNEL, order);
		if (block_addr) {
			block_entry = kmalloc(sizeof(struct enclave_cache_block_entry), GFP_KERNEL);
			if (!block_entry) {
				free_pages(block_addr, order);
				pr_err("cannot allocate a block_entry for cow cache!");
				return -ENOMEM;
			}
			block_entry->start = virt_to_phys((void *)block_addr);
			block_entry->end = virt_to_phys((void *)block_addr) + ((1 << order) - 1) * PAGE_SIZE;
			atomic_long_set_release(&block_entry->counter, 0);
			// use the end pfn as the index since xa api only support get index forward
			if (xa_insert(&cache_block_array, PFN_DOWN(block_entry->end), block_entry, GFP_KERNEL)) {
				free_pages(block_addr, order);
				kfree(block_entry);
				pr_err("cannot insert block entry into cache block array!");
				return -ENOMEM;
			}

			ret = __ecaddcache(sgx_get_epc_phys_addr(encl->secs.epc_page), block_entry->start, 1<<order);
			if (ret) {
				xa_erase(&cache_block_array, PFN_DOWN(block_entry->end));
				free_pages(block_addr, order);
				kfree(block_entry);
				pr_err("ECADDCACHE returned %d\n", ret);
				return ret;
			}
			get_block = true;
			encl->current_cache_block = block_entry;
			break;
		}
	}
	if (!get_block) {
		pr_err("cannot allocate a block for cow cache!");
		return -ENOMEM;
	}

	return 0;
}

static int handle_die_event(struct notifier_block *self,
							unsigned long val,
							void *data)
{
	struct die_args *args = data;

	if (val == DIE_TRAP && args->trapnr == X86_TRAP_UD)
	{
		struct pt_regs *regs = args->regs;
		unsigned char buf[3];
		// enclu

		if (copy_from_user(buf, (void __user *)regs->ip, 3))
			return NOTIFY_DONE;

		if (buf[0] == 0x0f && buf[1] == 0x01 && buf[2] == 0xd7)
		{
			struct callback_head *head;
			// pr_info("handle_die_event emulate");
			struct callback_head *work = kmalloc(sizeof(*work), GFP_KERNEL);
			work->func = emulate_enclu;
			head = READ_ONCE(current->task_works);
			do
			{
				work->next = head;
			} while (!try_cmpxchg(&current->task_works, &head, work));
			set_notify_resume(current);
			return NOTIFY_STOP;
		}
	}

	return NOTIFY_DONE;
}

static void __init register_sgx_die_notifier(void)
{
	die_notifier.notifier_call = handle_die_event;
	die_notifier.priority = 0x7fffffff;
	register_die_notifier(&die_notifier);
	pr_info("hook #ud\n");
}

static void __exit unregister_sgx_die_notifier(void)
{
	unregister_die_notifier(&die_notifier);
	pr_info("unhook #ud\n");
}

static bool enclave_should_sync(void)
{
	unsigned long secs;
	struct enclave_clone_sync_entry* sync_entry;
	struct enclave_sync_page_slot* sync_slot;

	rcu_read_lock();
	xa_for_each(&clone_sync_array, secs, sync_entry) {
    	sync_slot = (struct enclave_sync_page_slot*)sgx_get_epc_virt_addr(sync_entry->sync_page_epc);
		for (int i = 0; i < SYNC_PAGE_SLOT_NUM; i++) {
			if (sync_slot[i].state == SLOT_READY) {
				rcu_read_unlock();
				return true;
			}
		}
	}
	rcu_read_unlock();
	return false;
}

void sync_page_once(struct enclave_clone_sync_entry* sync_entry, bool terminate)
{
	struct sgx_encl *encl;
	struct enclave_sync_page_slot* sync_slot;
	uint64_t old_state;
	struct sgx_encl_page *page_entry;
	struct enclave_cache_block_entry* block_entry;
	struct sgx_epc_page *cache_page_epc;
	long counter;
	unsigned long new_paddr_pfn, block_end_paddr;

	encl = sync_entry->encl;
	mutex_lock(&sync_entry->lock);
	mutex_lock(&encl->lock);
	sync_slot = (struct enclave_sync_page_slot*)sgx_get_epc_virt_addr(sync_entry->sync_page_epc);
	for (int i = 0; i < SYNC_PAGE_SLOT_NUM; i++) {
		old_state = READ_ONCE(sync_slot[i].state);
		if (old_state == SLOT_READY && try_cmpxchg(&sync_slot[i].state, &old_state, SLOT_READING)) {
			// update slot if the slot is ready
			page_entry = xa_load(&encl->page_array, PFN_DOWN(sync_slot[i].vaddr));
			if (!page_entry || page_entry->epc_page->pfn != PFN_DOWN(sync_slot[i].old_paddr)) {
				if (!page_entry) {
					pr_err("page_entry does not exist!\n");
				} else {
					pr_err("page_entry->epc_page->pfn :%lx, old_paddr :%llx, ", page_entry->epc_page->pfn, sync_slot[i].old_paddr);
				}
				
				sync_slot[i].state = SLOT_READY;
				mutex_unlock(&encl->lock);
				mutex_unlock(&sync_entry->lock);
				return;
			}

			// To sync the update, first get the common epc_page and decrement the counter.
			// Then allocate a new epc_page for the cache page and link it to the encl_page
			counter = atomic_long_read(&page_entry->epc_page->counter);
			if (counter < 2) {
				pr_err("Invalid epc page to update, the page should have more than one reference!");
				sync_slot[i].state = SLOT_READY;
				mutex_unlock(&encl->lock);
				mutex_unlock(&sync_entry->lock);
				return;
			}

			pr_info("Get cache update: vaddr: 0x%llx, paddr: 0x%llx, old_paddr: 0x%llx\n", sync_slot[i].vaddr, sync_slot[i].new_paddr, sync_slot[i].old_paddr);
			atomic_long_dec_return_release(&page_entry->epc_page->counter);
			new_paddr_pfn = PFN_DOWN(sync_slot[i].new_paddr);
			block_end_paddr = new_paddr_pfn;

			block_entry = xa_find(&cache_block_array, &block_end_paddr, ULONG_MAX, XA_PRESENT);
			if (!block_entry || block_entry->start > sync_slot[i].new_paddr) {
				pr_err("Invalid new paddr, cannot find the backend block!");
				mutex_unlock(&encl->lock);
				mutex_unlock(&sync_entry->lock);
				return;
			}

			atomic_long_inc_return_release(&block_entry->counter);
			if (sync_slot[i].new_paddr == block_entry->end) {
				atomic_long_set_release(&block_entry->consumed, 1);
			}

			cache_page_epc = sgx_alloc_epc_page_cache(page_entry, new_paddr_pfn);
			if (cache_page_epc) {
				page_entry->epc_page = cache_page_epc;
				sync_slot[i].state = SLOT_FREE;
			}
		}
	}

	if (terminate && encl->current_cache_block) {
		atomic_long_set_release(&encl->current_cache_block->consumed, 1);
	}
	mutex_unlock(&encl->lock);
	mutex_unlock(&sync_entry->lock);
}

static void do_page_sync(void)
{
	unsigned long secs;
	struct enclave_clone_sync_entry* sync_entry;

	rcu_read_lock();
	xa_for_each(&clone_sync_array, secs, sync_entry) {
		//pr_info("do page sync secs: 0x%lx", secs);
		sync_page_once(sync_entry, false);
	}

	rcu_read_unlock();

}

static int kenclaved(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable_timeout(kenclaved_waitq,
					kthread_should_stop() || enclave_should_sync(),
					msecs_to_jiffies(100));

		do_page_sync();
		cond_resched();
	}

	if (!xa_empty(&clone_sync_array)) {
		pr_err("clone_sync_array is not null when thread stop!\n");
	}

	xa_destroy(&clone_sync_array);
	return 0;
}

static bool __init sgx_page_syncer_init(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(kenclaved, NULL, "kenclaved");
	pr_info("start kenclaved!");
	if (IS_ERR(tsk))
		return false;

	kenclaved_tsk = tsk;

	return true;
}

static int __init sgx_init(void)
{
	int ret;
	// int i;
	if (!detect_svsm())
		return -ENODEV;

	// if (!sgx_page_cache_init())
	//	return -EFAULT;
#ifdef HAVE_MMPUT_ASYNC
	k_mmput_async = mmput_async;
#else
#ifdef HAVE_KSYM_LOOKUP
	k_mmput_async = (void *)kallsyms_lookup_name("mmput_async");
#else
#error "kernel version is not be supported. We need either mmput_async or kallsyms_lookup_name exported from kernel"
#endif
#endif
	if (!k_mmput_async)
	{
		pr_err("mmput_async support missing from kernel.\n");
		return -EFAULT;
	}
	// if (!sgx_page_reclaimer_init())
	//	goto err_page_cache;

	if (!sgx_page_syncer_init())
		return -EFAULT;
	
	ret = alloc_eaddb_buffer();
	if (ret)
		goto err_kthread;

	ret = sgx_drv_init();
	if (ret)
		goto err_buffer;

	pr_info(DRV_DESCRIPTION " v" DRV_VERSION "\n");

	register_sgx_die_notifier();
	return 0;

	err_buffer:
		release_eaddb_buffer();
	err_kthread:
		kthread_stop(kenclaved_tsk);
	/*
		kthread_stop(ksgxd_tsk);

	err_page_cache:
		for (i = 0; i < sgx_nr_epc_sections; i++) {
			vfree(sgx_epc_sections[i].pages);
			memunmap(sgx_epc_sections[i].virt_addr);
		}
	*/
		return -EFAULT;
}
module_init(sgx_init);

static void __exit sgx_exit(void)
{
	// int i;
	sgx_drv_exit();
	kthread_stop(kenclaved_tsk);
	// kthread_stop(ksgxd_tsk);
	struct sgx_epc_page *epc_page;
	unsigned long index, size_pages;
	struct enclave_cache_block_entry *block_entry;

	spin_lock(&sgx_page_pool_lock);
	while (!list_empty(&sgx_page_pool))
	{
		epc_page = list_first_entry(&sgx_page_pool, struct sgx_epc_page, list);
		list_del_init(&epc_page->list);
		pr_info("page %lx is not freed when module exit\n", sgx_get_epc_phys_addr(epc_page));
		//sgx_free_epc_page(epc_page);
	}
	spin_unlock(&sgx_page_pool_lock);
	
	rcu_read_lock();
	xa_for_each(&cache_block_array, index, block_entry) {
		if (atomic_long_read_acquire(&block_entry->counter) && atomic_long_read_acquire(&block_entry->consumed)) {
			pr_err("cache block unreleased when module exit start:0x%llx, end:0x%llx\n", block_entry->start, block_entry->end);
		} else {
			//pr_info("Release free block\n");
			size_pages = (block_entry->end - block_entry->start + PAGE_SIZE) >> PAGE_SHIFT;
			free_pages((unsigned long)phys_to_virt(block_entry->start), fls(size_pages) - 1);
			kfree(block_entry);
		}
	}
	rcu_read_unlock();

	xa_destroy(&cache_block_array);
	unregister_sgx_die_notifier();
	release_eaddb_buffer();
	pr_info(DRV_DESCRIPTION " v" DRV_VERSION " removed\n");
	/*
	for (i = 0; i < sgx_nr_epc_sections; i++) {
		vfree(sgx_epc_sections[i].pages);
		memunmap(sgx_epc_sections[i].virt_addr);
	}
	*/
}
module_exit(sgx_exit);
