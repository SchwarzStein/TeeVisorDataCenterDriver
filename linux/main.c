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
static DECLARE_WAIT_QUEUE_HEAD(ksgxd_waitq);

/*
 * These variables are part of the state of the reclaimer, and must be accessed
 * with sgx_reclaimer_lock acquired.
 */
static LIST_HEAD(sgx_active_page_list);

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

		if (list_empty(&sgx_active_page_list))
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
void sgx_free_epc_page(struct sgx_epc_page *epc_page)
{
	int ret;
	struct page *page = pfn_to_page(epc_page->pfn);

	WARN_ON_ONCE(epc_page->flags & SGX_EPC_PAGE_RECLAIMER_TRACKED);

	ret = __eremove(sgx_get_epc_phys_addr(epc_page));
	if (ret)
	{
		pr_err("EREMOVE returned %d (0x%x)", ret, ret);
		return;
	}

	spin_lock(&sgx_page_pool_lock);
	list_del_init(&epc_page->list);
	spin_unlock(&sgx_page_pool_lock);
	__free_page(page);
	vfree(epc_page);
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
	struct sgx_encl *encl = NULL;
	int ret;

	tsk = current;
	mm = tsk->mm;

	ret = sgx_encl_find(mm, vaddr, &vma);

	if (!ret)
		encl = (struct sgx_encl *)vma->vm_private_data;

	return encl;
}

static pte_t *vaddr_to_pte(unsigned long vaddr, struct mm_struct *mm)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	p4d_t *p4d;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd))
	{
		pr_err("not mapped in pgd\n");
		return NULL;
	}

	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d))
	{
		pr_err("not mapped in p4d\n");
		return NULL;
	}

	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud))
	{
		pr_err("not mapped in pud\n");
		return NULL;
	}

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd))
	{
		pr_err("not mapped in pmd\n");
		return NULL;
	}

	if (pmd_trans_huge(*pmd))
	{
		pr_err("hugepage is currently nosupported in pmd\n");
		return NULL;
	}

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte))
	{
		pr_err("not mapped in pte\n");
		return NULL;
	}

	return pte;
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
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_DEFAULT;
	struct page *page = NULL;
	pte_t *pte;
	u64 paddr;
	int ret;
	bool unsynced = false;
	void *old_sync_entry;

	tsk = current;
	mm = tsk->mm;
	//pr_info("try to handle pf address:%lx, error_code: %lx", address, error_code);
	if (error_code & X86_PF_WRITE)
		flags |= FAULT_FLAG_WRITE;
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

	//pr_info("handle_mm_fault return value %x", fault);

	// If VM_FAULT_COMPLETED is set, mmap_lock is released
	if (fault & VM_FAULT_COMPLETED)
	{
		return;
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
			mutex_lock(&encl->lock);
			sync_entry = xa_load(&encl->sync_array, PFN_DOWN(address));

			// If the vaddr has already been synced, first try to unsync
			if (sync_entry)
			{
				pr_info("eunsync address: 0x%lx, paddr: 0x%llx", address, sync_entry->paddr);
				ret = sgx_encl_eunsync(encl, sync_entry->paddr, address);
				if (ret)
				{
					pr_err("eunsync has an error with vaddr:0x%lx, paddr:0x%llx\n",
						   address, sync_entry->paddr);
					goto sync_fail;
				}
				encl->sync_page_cnt--;
				unsynced = true;
			}

			ret = get_user_pages(address, 1, 0, &page);
			if (ret < 1)
			{
				pr_err("Cannot get the physical address of a user page!\n");
				goto sync_fail;
			}
			pte = vaddr_to_pte(address, mm);
			if (!pte)
			{
				pr_err("Cannot get the pte of a user address!\n");
				goto sync_fail_page;
			}

			paddr = pte_pfn(*pte) << PAGE_SHIFT;

			ret = sgx_encl_esync(encl, paddr, address & PAGE_MASK, pte_present(*pte),
								 pte_write(*pte), false);
			//pr_info("esync address: 0x%lx, paddr: 0x%llx, pte: 0x%lx", address, paddr, pte->pte);
			if (ret)
			{
				pr_err("esync has an error with vaddr:0x%lx, paddr:0x%llx, rwx: %d%d%d\n",
					   address, paddr, pte_present(*pte), pte_write(*pte), pte_exec(*pte));
				goto sync_fail_page;
			}

			sync_entry = kzalloc(sizeof(struct sgx_encl_sync_page), GFP_KERNEL);
			if (!sync_entry)
			{
				pr_err("esync OOM");
				goto sync_fail_page;
			}

			encl->sync_page_cnt++;
			sync_entry->paddr = paddr;
			old_sync_entry = xa_store(&encl->sync_array, PFN_DOWN(address), sync_entry, GFP_KERNEL);

			if (old_sync_entry)
			{
				if (!unsynced)
				{
					pr_err("old_sync_entry can be not null only after old page is unsynced");
					goto sync_fail_page;
				}
				kfree(old_sync_entry);
			}
			mutex_unlock(&encl->lock);
			put_page(page);
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
			force_sig(SIGBUS);
		}
		// force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)address);
		else if (fault & VM_FAULT_SIGSEGV)
		{
			if (try_fixup_vdso_exception(regs, X86_TRAP_PF, error_code, address))
				return;
			force_sig(SIGSEGV);
		}
		// force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)address);
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
	force_sig(SIGKILL);
	mutex_unlock(&encl->lock);
	up_read(&mm->mmap_lock);
	return;
}

static void do_trap(int trapnr, int signr, struct pt_regs *regs,
					long error_code, int sicode, void __user *addr)
{
	if (try_fixup_vdso_exception(regs, trapnr, error_code, (unsigned long)addr))
		return;

	// force_sig_fault is not exported
	force_sig(signr);
	/*
	if (!sicode)
		force_sig(signr);
	else
		force_sig_fault(signr, sicode, addr);
	*/
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
	u64 tcs_vaddr, tdcr, tmcct;
	struct sgx_encl *encl;
	struct task_struct *tsk;
	struct mm_struct *mm;
	int ret;

	tsk = current;
	mm = tsk->mm;
	regs = task_pt_regs(current);
	tcs_vaddr = regs->bx;
	//pr_info("tcs_vaddr :%llx", tcs_vaddr);
	encl = get_encl_from_vaddr(tcs_vaddr);
	if (!encl)
	{
		pr_err("emulate_enclu get enclave failed");
		do_trap(X86_TRAP_PF, SIGSEGV, regs, 0, 0, (void *)regs->bx);
		return;
	}

	entry = xa_load(&encl->tcs_array, PFN_DOWN(tcs_vaddr));
	if (!entry)
	{
		pr_err("emulate_enclu get tcs_array failed");
		do_trap(X86_TRAP_PF, SIGSEGV, regs, 0, 0, (void *)regs->bx);
		return;
	}

	rdmsrl(MSR_X2APIC_TDCR, tdcr);
	rdmsrl(MSR_X2APIC_CURRENT_COUNT, tmcct);

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
	param.apic_tdcr = tdcr;
	param.apic_tmcct = tmcct;
	//trace_printk("input param: ");
	//dump_sgx_args(&param);
	// TODO: error is hiden here, should return exact error if enclu failed
	//       now just return GP.
	//pr_info("run enclu");
	ret = snp_sgx_enclu(&param);
	//pr_info("return from enclu");
	//trace_printk("output param: ");
	//dump_sgx_args(&param);
	if (ret)
	{
		pr_err("enclu failed");
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
		case TIMER:
			cond_resched();
			break;
		default:
			pr_info("Unexpected interrupt %lld in enclave\n", param.vector);
			break;
		}
		break;
	case EXIT_REASON_EEXIT:
		//pr_info("EXIT_REASON_EEXIT");
		break;
	default:
		break;
	}
	kfree(work);
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

	ret = sgx_drv_init();
	if (ret)
		return -EFAULT;
	// goto err_kthread;

	pr_info(DRV_DESCRIPTION " v" DRV_VERSION "\n");
	alloc_eaddb_buffer();
	register_sgx_die_notifier();
	return 0;

	/*
	err_kthread:
		kthread_stop(ksgxd_tsk);

	err_page_cache:
		for (i = 0; i < sgx_nr_epc_sections; i++) {
			vfree(sgx_epc_sections[i].pages);
			memunmap(sgx_epc_sections[i].virt_addr);
		}
		return -EFAULT;
	*/
}
module_init(sgx_init);

static void __exit sgx_exit(void)
{
	// int i;
	sgx_drv_exit();
	// kthread_stop(ksgxd_tsk);
	struct sgx_epc_page *epc_page;

	spin_lock(&sgx_page_pool_lock);
	while (!list_empty(&sgx_page_pool))
	{
		epc_page = list_first_entry(&sgx_page_pool, struct sgx_epc_page, list);
		list_del_init(&epc_page->list);
		pr_info("remove page %lx when module exit\n", sgx_get_epc_phys_addr(epc_page));
		sgx_free_epc_page(epc_page);
	}
	spin_unlock(&sgx_page_pool_lock);

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
