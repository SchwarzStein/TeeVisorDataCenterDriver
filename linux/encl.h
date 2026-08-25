/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
 * Copyright(c) 2016-21 Intel Corporation.
 *
 * Contains the software defined data structures for enclaves.
 */
#ifndef _X86_ENCL_H
#define _X86_ENCL_H

#include <linux/version.h>
#include <linux/cpumask.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
#include <linux/xarray.h>
#else
#include <linux/radix-tree.h>
#endif
#include <linux/srcu.h>
#include <linux/workqueue.h>
#include "sgx.h"

/* 'desc' bits holding the offset in the VA (version array) page. */
#define SGX_ENCL_PAGE_VA_OFFSET_MASK	GENMASK_ULL(11, 3)

/* 'desc' bit marking that the page is being reclaimed. */
#define SGX_ENCL_PAGE_BEING_RECLAIMED	BIT(3)

struct sgx_encl_page {
	unsigned long desc;
	unsigned long vm_max_prot_bits:8;
	enum sgx_page_type type:16;
	struct sgx_epc_page *epc_page;
	struct sgx_encl *encl;
	struct sgx_va_page *va_page;
};

struct sgx_mm_sync_array {
	struct mutex sync_lock;
	struct xarray array;
};

struct sgx_encl_sync_page {
	struct page* page; // acquire after get_user_page
	u64 paddr; // the page permission can change, just record the pte when the page is synced
};

enum sgx_encl_flags {
	SGX_ENCL_IOCTL		= BIT(0),
	SGX_ENCL_DEBUG		= BIT(1),
	SGX_ENCL_CREATED	= BIT(2),
	SGX_ENCL_INITIALIZED	= BIT(3),
	SGX_ENCL_RUNTIME	= BIT(4),
	SGX_ENCL_CLONE = BIT(5),	// Current Enclave is in clone state
	SGX_ENCL_CLONE_FAIL = BIT(6), // Indicate the recent clone failed or not
};

struct sgx_encl_mm {
	struct sgx_encl *encl;
	struct mm_struct *mm;
	struct list_head list;
	struct mmu_notifier mmu_notifier;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
	struct rcu_head rcu;
#endif
};

struct sgx_encl {
	unsigned long base;
	unsigned long size;
	unsigned long runtime_base;
	unsigned long runtime_size;
	unsigned long flags;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	unsigned int sync_page_cnt;
	struct mutex lock;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	struct xarray page_array;
	struct xarray mm_sync_array;
	struct xarray tcs_array;
	struct xarray eaug_retry_array;
	struct xarray* enclave_array;
#else
	struct radix_tree_root page_tree;
#endif
	struct enclave_clone_info *clone_info;
	struct sgx_encl_page secs;
	struct sgx_encl_page cow_sync_page;
	struct enclave_cache_block_entry *current_cache_block;
	unsigned long attributes;
	unsigned long attributes_mask;

	cpumask_t cpumask;
	//struct file *backing;
	struct kref refcount;
	//struct list_head va_pages;
	unsigned long mm_list_version;
	struct list_head mm_list;
	spinlock_t mm_lock;
	struct srcu_struct srcu;
};

#define SGX_VA_SLOT_COUNT 512

struct sgx_va_page {
	struct sgx_epc_page *epc_page;
	DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
	struct list_head list;
};

struct sgx_backing {
	pgoff_t page_index;
	struct page *contents;
	struct page *pcmd;
	unsigned long pcmd_offset;
};

extern const struct vm_operations_struct sgx_vm_ops;

extern struct xarray clone_sync_array;
extern struct xarray cache_block_array;
extern struct mutex clone_sync_array_lock;

struct enclave_sync_page_slot
{
	uint64_t vaddr;
	uint64_t old_paddr;
	uint64_t new_paddr;
	uint64_t state;
};

#define SYNC_PAGE_SLOT_NUM (PAGE_SIZE / sizeof(struct enclave_sync_page_slot))

struct enclave_sync_page
{
	struct enclave_sync_page_slot slots[SYNC_PAGE_SLOT_NUM];
};

enum enclave_sync_page_slot_state
{
	SLOT_FREE = 0,
	SLOT_WRITING = 1,
	SLOT_READY = 2,
	SLOT_READING = 3,
};

struct enclave_clone_sync_entry {
	struct sgx_encl *encl;
	struct sgx_epc_page *sync_page_epc;
	struct mutex lock;
};

#define SGX_ENCLAVE_CLONING 35

// A cache block can be freed when the (last page is allocated or the owner enclave is destroyed)
//  and counter is 0.
struct enclave_cache_block_entry {
	atomic_long_t consumed;
	atomic_long_t counter;
	u64 start;
	u64 end; 
};

struct enclave_clone_info {
	struct sgx_clone_info *clone_info;
	struct task_struct *parent;
	struct sgx_encl *child_encl;
	struct sgx_encl_page *metadata_list[];
};

static inline int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
				struct vm_area_struct **vma)
{
	struct vm_area_struct *result;
	down_read(&mm->mmap_lock);  
	result = find_vma(mm, addr);
	if (!result || result->vm_ops != &sgx_vm_ops || addr < result->vm_start) {
		pr_info("invalid find_vma");
		up_read(&mm->mmap_lock);
		return -EINVAL;
	}

	up_read(&mm->mmap_lock);
	*vma = result;

	return 0;
}

static inline bool vaddr_inside_enclave(struct sgx_encl *encl, unsigned long vaddr)
{
	if (vaddr >= encl->base && vaddr < (encl->base + encl->size))
		return true;
	
	if (test_bit(SGX_ENCL_RUNTIME, &encl->flags) &&
		(vaddr >= encl->runtime_base
			&& vaddr < (encl->runtime_base + encl->runtime_size)))
		return true;

	return false;
}

#define SVSM_PAGEINFO_ENTRY_MAX (PAGE_SIZE / sizeof(struct sgx_pageinfo) - 1)

int sgx_encl_may_map(struct sgx_encl *encl, unsigned long start,
		     unsigned long end, unsigned long vm_flags);
struct sgx_encl_page *sgx_encl_page_alloc(struct sgx_encl *encl,
					  unsigned long offset,
					  u64 secinfo_flags);
void sgx_encl_release(struct kref *ref);
int sgx_encl_mm_add(struct sgx_encl *encl, struct mm_struct *mm);
//int sgx_encl_get_backing(struct sgx_encl *encl, unsigned long page_index,
//			 struct sgx_backing *backing);
//void sgx_encl_put_backing(struct sgx_backing *backing, bool do_write);
//int sgx_encl_test_and_clear_young(struct mm_struct *mm,
//				  struct sgx_encl_page *page);
int sgx_encl_esync(struct sgx_encl *encl, u64 paddr, u64 vaddr, 
	bool read, bool write, bool execute, u64 mm);
int sgx_encl_eunsync(struct sgx_encl *encl, u64 paddr, u64 vaddr, u64 mm);
struct sgx_encl_page *sgx_encl_load_page(struct sgx_encl *encl,
						unsigned long addr);
void sync_page_once(struct enclave_clone_sync_entry* sync_entry, bool terminate);
long sgx_enclave_clone_abort(struct sgx_encl *encl);
void try_do_sync_page(struct sgx_encl *encl);
int add_enclave_cache_block(struct sgx_encl *encl);
//struct sgx_epc_page *sgx_alloc_va_page(void);
//unsigned int sgx_alloc_va_slot(struct sgx_va_page *va_page);
//void sgx_free_va_slot(struct sgx_va_page *va_page, unsigned int offset);
//bool sgx_va_page_full(struct sgx_va_page *va_page);

#endif /* _X86_ENCL_H */
