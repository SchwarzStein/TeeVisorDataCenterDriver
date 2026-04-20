// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*  Copyright(c) 2016-21 Intel Corporation. */

#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <linux/suspend.h>
#include <linux/sched/mm.h>
#include "arch.h"
#include "encl.h"
#include "encls.h"
#include "sgx.h"
#include "dcap.h"
#include "driver.h"
#include <linux/version.h>


/*
 * ELDU: Load an EPC page as unblocked. For more info, see "OS Management of EPC
 * Pages" in the SDM.
 */
/*
static int __sgx_encl_eldu(struct sgx_encl_page *encl_page,
			   struct sgx_epc_page *epc_page,
			   struct sgx_epc_page *secs_page)
{
	unsigned long va_offset = encl_page->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_pageinfo pginfo;
	struct sgx_backing b;
	pgoff_t page_index;
	int ret;

	if (secs_page)
		page_index = PFN_DOWN(encl_page->desc - encl_page->encl->base);
	else
		page_index = PFN_DOWN(encl->size);

	ret = sgx_encl_get_backing(encl, page_index, &b);
	if (ret)
		return ret;

	pginfo.addr = encl_page->desc & PAGE_MASK;
	pginfo.contents = (unsigned long)kmap_atomic(b.contents);
	pginfo.metadata = (unsigned long)kmap_atomic(b.pcmd) +
			  b.pcmd_offset;

	if (secs_page)
		pginfo.secs = (u64)sgx_get_epc_virt_addr(secs_page);
	else
		pginfo.secs = 0;

	ret = __eldu(&pginfo, sgx_get_epc_virt_addr(epc_page),
		     sgx_get_epc_virt_addr(encl_page->va_page->epc_page) + va_offset);
	if (ret) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "ELDU");

		ret = -EFAULT;
	}

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - b.pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	sgx_encl_put_backing(&b, false);

	return ret;
}
*/

/*
static struct sgx_epc_page *sgx_encl_eldu(struct sgx_encl_page *encl_page,
					  struct sgx_epc_page *secs_page)
{

	unsigned long va_offset = encl_page->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_epc_page(encl_page, false);
	if (IS_ERR(epc_page))
		return epc_page;

	ret = __sgx_encl_eldu(encl_page, epc_page, secs_page);
	if (ret) {
		sgx_free_epc_page(epc_page);
		return ERR_PTR(ret);
	}

	sgx_free_va_slot(encl_page->va_page, va_offset);
	list_move(&encl_page->va_page->list, &encl->va_pages);
	encl_page->desc &= ~SGX_ENCL_PAGE_VA_OFFSET_MASK;
	encl_page->epc_page = epc_page;

	return epc_page;
}
*/
int sgx_encl_esync(struct sgx_encl *encl, u64 paddr, u64 vaddr, bool read, bool write, bool execute)
{
	struct sgx_pageinfo *pginfo;
	struct sgx_secinfo *secinfo;
	int ret;

	pginfo = kmalloc(sizeof(struct sgx_pageinfo), GFP_KERNEL);
	secinfo = kzalloc(sizeof(struct sgx_secinfo), GFP_KERNEL);

	if (!pginfo || !secinfo) {
		return -ENOMEM;
	}

	pginfo->secs = (unsigned long)sgx_get_epc_phys_addr(encl->secs.epc_page);
	pginfo->addr = vaddr;
	pginfo->metadata = virt_to_phys(secinfo);
	pginfo->contents = paddr & PAGE_MASK;

	secinfo->flags = SGX_SECINFO_SYNC;

	if (read) {
		secinfo->flags |= SGX_SECINFO_R;
	}

	if (write) {
		secinfo->flags |= SGX_SECINFO_W;
	}

	if (execute) {
		secinfo->flags |= SGX_SECINFO_X;
	}

retry:
	ret = __esync(virt_to_phys(pginfo));

	if (ret == -EAGAIN)
		goto retry;

	kfree(pginfo);
	kfree(secinfo);

	return ret ? -EIO : 0;
}

int sgx_encl_eunsync(struct sgx_encl *encl, u64 paddr, u64 vaddr)
{
	struct sgx_pageinfo *pginfo;
	struct sgx_secinfo *secinfo;
	int ret;

	pginfo = kmalloc(sizeof(struct sgx_pageinfo) ,GFP_KERNEL);
	secinfo = kzalloc(sizeof(struct sgx_secinfo), GFP_KERNEL);

	if (!pginfo || !secinfo) {
		return -ENOMEM;
	}

	pginfo->secs = (unsigned long)sgx_get_epc_phys_addr(encl->secs.epc_page);
	pginfo->addr = vaddr;
	pginfo->metadata = virt_to_phys(secinfo);
	pginfo->contents = paddr & PAGE_MASK;
retry:
	ret = __esync(virt_to_phys(pginfo));

	// Cloned enclave share one epcm with parent, in epcm contention cases, retry
	if(ret == (ENCLS_FAULT_FLAG | X86_TRAP_GP) && encl->attributes & SGX_ATTR_CLONE) {
		pr_info("sgx_encl_eunsync EPCM lock contention, retry\n");
		goto retry;
	}

	if (ret == -EAGAIN)
		goto retry;
	kfree(pginfo);
	kfree(secinfo);

	return ret ? -EIO : 0;
}

static struct sgx_encl_page *sgx_get_encl_page(struct sgx_encl *encl,
						unsigned long addr,
						unsigned long vm_flags)
{
	unsigned long vm_prot_bits = vm_flags & (VM_READ | VM_WRITE | VM_EXEC);
	struct sgx_encl_page *entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	entry = xa_load(&encl->page_array, PFN_DOWN(addr));
#else
	entry = radix_tree_lookup(&encl->page_tree, PFN_DOWN(addr));
#endif
	if (!entry)
		return ERR_PTR(-EFAULT);

	/*
	 * Verify that the faulted page has equal or higher build time
	 * permissions than the VMA permissions (i.e. the subset of {VM_READ,
	 * VM_WRITE, VM_EXECUTE} in vma->vm_flags).
	 */
	if ((entry->vm_max_prot_bits & vm_prot_bits) != vm_prot_bits)
		return ERR_PTR(-EFAULT);
	/* Entry successfully located. */
	return entry;
}

struct sgx_encl_page *sgx_encl_load_page(struct sgx_encl *encl,
						unsigned long addr)
{
	//struct sgx_epc_page *epc_page;
	struct sgx_encl_page *entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	entry = xa_load(&encl->page_array, PFN_DOWN(addr));
#else
	entry = radix_tree_lookup(&encl->page_tree, PFN_DOWN(addr));
#endif
	if (!entry)
		return ERR_PTR(-EFAULT);

	/* Entry successfully located. *//*
	if (entry->epc_page) {
		if (entry->desc & SGX_ENCL_PAGE_BEING_RECLAIMED)
			return ERR_PTR(-EBUSY);

		return entry;
	}

	if (!(encl->secs.epc_page)) {
		epc_page = sgx_encl_eldu(&encl->secs, NULL);
		if (IS_ERR(epc_page))
			return ERR_CAST(epc_page);
	}

	epc_page = sgx_encl_eldu(entry, encl->secs.epc_page);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	encl->secs_child_cnt++;
	sgx_mark_page_reclaimable(entry->epc_page);*/

	return entry;
}


/**
 * sgx_encl_eaug_page() - Dynamically add page to initialized enclave
 * @vma:	VMA obtained from fault info from where page is accessed
 * @encl:	enclave accessing the page
 * @addr:	address that triggered the page fault
 *
 * When an initialized enclave accesses a page with no backing EPC page
 * on a SGX2 system then the EPC can be added dynamically via the SGX2
 * ENCLS[EAUG] instruction.
 *
 * Returns: Appropriate vm_fault_t: VM_FAULT_NOPAGE when PTE was installed
 * successfully, VM_FAULT_SIGBUS or VM_FAULT_OOM as error otherwise.
 */
static vm_fault_t sgx_encl_eaug_page(struct vm_area_struct *vma,
				     struct sgx_encl *encl, unsigned long addr)
{
	vm_fault_t vmret = VM_FAULT_SIGBUS;
	struct sgx_pageinfo *pginfo;
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	//struct sgx_va_page *va_page;
	//unsigned long phys_addr;
	u64 secinfo_flags;
	int ret;

	if (!test_bit(SGX_ENCL_INITIALIZED, &encl->flags))
		return VM_FAULT_SIGBUS;

	/*
	 * Ignore internal permission checking for dynamically added pages.
	 * They matter only for data added during the pre-initialization
	 * phase. The enclave decides the permissions by the means of
	 * EACCEPT, EACCEPTCOPY and EMODPE.
	 */
	secinfo_flags = SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X;
	encl_page = sgx_encl_page_alloc(encl, addr, secinfo_flags);
	if (IS_ERR(encl_page))
		return VM_FAULT_OOM;

	mutex_lock(&encl->lock);

	//epc_page = sgx_encl_load_secs(encl);
	epc_page = encl->secs.epc_page;
	if (IS_ERR(epc_page)) {
		if (PTR_ERR(epc_page) == -EBUSY)
			vmret = VM_FAULT_NOPAGE;
		goto err_out_unlock;
	}

	epc_page = sgx_alloc_epc_page(encl_page, false);
	if (IS_ERR(epc_page)) {
		if (PTR_ERR(epc_page) == -EBUSY)
			vmret =  VM_FAULT_NOPAGE;
		goto err_out_unlock;
	}

	/*
	va_page = sgx_encl_grow(encl, false);
	if (IS_ERR(va_page)) {
		if (PTR_ERR(va_page) == -EBUSY)
			vmret = VM_FAULT_NOPAGE;
		goto err_out_epc;
	}

	if (va_page)
		list_add(&va_page->list, &encl->va_pages);
	*/

	ret = xa_insert(&encl->page_array, PFN_DOWN(encl_page->desc),
			encl_page, GFP_KERNEL);
	/*
	 * If ret == -EBUSY then page was created in another flow while
	 * running without encl->lock
	 */
	if (ret)
		goto err_out_shrink;

	pginfo = kzalloc(sizeof(struct sgx_pageinfo) ,GFP_KERNEL);

	if (!pginfo) {
		return -ENOMEM;
	}

	pginfo->secs = (unsigned long)sgx_get_epc_phys_addr(encl->secs.epc_page);
	pginfo->addr = encl_page->desc & PAGE_MASK;
	pginfo->metadata = 0;

	ret = __eaug(virt_to_phys(pginfo), sgx_get_epc_phys_addr(epc_page));
	if (ret == SGX_ENCLAVE_CLONING) {
		ret = xa_insert(&encl->eaug_retry_array, PFN_DOWN(addr), encl_page, GFP_KERNEL);
		if (ret) {
			goto err_out;
		}
	} else if (ret) {
		goto err_out;
	}

	encl_page->encl = encl;
	encl_page->epc_page = epc_page;
	encl_page->type = SGX_PAGE_TYPE_REG;
	encl->secs_child_cnt++;

	//sgx_mark_page_reclaimable(encl_page->epc_page);

	//phys_addr = sgx_get_epc_phys_addr(epc_page);
	/*
	 * Do not undo everything when creating PTE entry fails - next #PF
	 * would find page ready for a PTE.
	 */

	/*
	vmret = vmf_insert_pfn(vma, addr, PFN_DOWN(phys_addr));
	if (vmret != VM_FAULT_NOPAGE) {
		mutex_unlock(&encl->lock);
		return VM_FAULT_SIGBUS;
	}
	*/
	kfree(pginfo);
	mutex_unlock(&encl->lock);
	return VM_FAULT_NOPAGE;

err_out:
	kfree(pginfo);
	xa_erase(&encl->page_array, PFN_DOWN(encl_page->desc));

err_out_shrink:
	//sgx_encl_shrink(encl, va_page);
//err_out_epc:
	sgx_free_epc_page(epc_page, sgx_get_epc_phys_addr(encl->secs.epc_page));
err_out_unlock:
	mutex_unlock(&encl->lock);
	kfree(encl_page);

	return vmret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0))
static vm_fault_t sgx_vma_fault(struct vm_fault *vmf)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0))
static unsigned int sgx_vma_fault(struct vm_fault *vmf)
#else
    #if( defined(RHEL_RELEASE_VERSION) && defined(RHEL_RELEASE_CODE))
        #if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(8, 1))
static unsigned int sgx_vma_fault(struct vm_fault *vmf)
        #else
static int sgx_vma_fault(struct vm_fault *vmf)
        #endif
    #else
static int sgx_vma_fault(struct vm_fault *vmf)
    #endif
#endif
{
	unsigned long addr = (unsigned long)vmf->address;
	struct vm_area_struct *vma = vmf->vma;
	//struct sgx_encl_page *entry;
	//unsigned long phys_addr;
	struct xarray *enclave_array = vma->vm_private_data;
	struct sgx_encl *encl;
	//pte_t *pte;
	//spinlock_t *ptl;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0))
	vm_fault_t ret;
#else
	int ret = VM_FAULT_NOPAGE;
#endif

	if (unlikely(!enclave_array))
		return VM_FAULT_SIGBUS;
	encl = xa_load(enclave_array, (unsigned long)vma->vm_mm);

	/*
	 * It's very unlikely but possible that allocating memory for the
	 * mm_list entry of a forked process failed in sgx_vma_open(). When
	 * this happens, vm_private_data is set to NULL.
	 */
	if (unlikely(!encl))
		return VM_FAULT_SIGBUS;

	//mutex_lock(&encl->lock);

	/*
	 * If the page is not added, try to call eaug.
	 * Otherwise the page is tried to visit either from outside or
	 * with wrong permission, just return an VM_FAULT_NOPAGE, and in handle_pf
	 * set the signal according to the present bit which cannot be checked here.
	 */
	if (!xa_load(&encl->page_array, PFN_DOWN(addr)))
		return sgx_encl_eaug_page(vma, encl, addr);
	else 
		ret = VM_FAULT_NOPAGE;	
	//mutex_unlock(&encl->lock);
	/*

	entry = sgx_encl_load_page(encl, addr, vma->vm_flags);
	if (IS_ERR(entry)) {
		mutex_unlock(&encl->lock);

		if (PTR_ERR(entry) == -EBUSY)
			return VM_FAULT_NOPAGE;

		return VM_FAULT_SIGBUS;
	}

	phys_addr = sgx_get_epc_phys_addr(entry->epc_page);*/

	/* Check if another thread got here first to insert the PTE. *//*
	if (!follow_pte(vma, addr, &pte, &ptl)) {
		mutex_unlock(&encl->lock);

		return VM_FAULT_NOPAGE;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	ret = vmf_insert_pfn(vma, addr, PFN_DOWN(phys_addr));
	if (ret != VM_FAULT_NOPAGE) {
#else
    #if( defined(RHEL_RELEASE_VERSION) && defined(RHEL_RELEASE_CODE))
        #if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(8, 1))
            ret = vmf_insert_pfn(vma, addr, PFN_DOWN(phys_addr));
            if (ret != VM_FAULT_NOPAGE) {
        #else //8.1 or below
            ret = vm_insert_pfn(vma, addr, PFN_DOWN(phys_addr));
            if (!ret){
                ret = VM_FAULT_NOPAGE;
            }
            else{
        #endif
    #else
	ret = vm_insert_pfn(vma, addr, PFN_DOWN(phys_addr));
	if (!ret){
		ret = VM_FAULT_NOPAGE;
	}
	else{
    #endif
#endif
		
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	sgx_encl_test_and_clear_young(vma->vm_mm, entry);

out:
	mutex_unlock(&encl->lock);*/
	return ret;
}

static void sgx_vma_close(struct vm_area_struct* vma)
{
	struct xarray *enclave_array = vma->vm_private_data;
	struct sgx_encl *encl;

	if (unlikely(!enclave_array))
		return;

	//pr_info("vma_close\n");
	encl = xa_load(enclave_array, (unsigned long)vma->vm_mm);
	
	if (!encl) {
		return;
	}
	
	//pr_info("before decrement refcount=%d\n", kref_read(&encl->refcount));
	kref_put(&encl->refcount, sgx_encl_release);
	return;
}

static struct sgx_encl *clone_enclave(struct sgx_encl *parent_encl)
{
	struct svsm_ecloneinfo_call *ec;
	struct svsm_ecaddinfo_call *ea;
	struct sgx_encl *child_encl;
	struct sgx_encl_page *entry, *encl_page, *child_encl_page;
	struct sgx_encl_sync_page *sync_entry, *child_sync_entry;
	unsigned long index;
	int ret;
	bool loop = false;
	u64 added_page_num = 0;
	u16 num_entries;

	child_encl = parent_encl->clone_info->child_encl;
	mutex_lock(&parent_encl->lock);
	mutex_lock(&child_encl->lock);

	//pr_info("ECCREATE child secs paddr: 0x%llx\n", parent_encl->clone_info->clone_info->child_secs);
	ret = __eccreate(virt_to_phys(parent_encl->clone_info->clone_info));
	if (ret) {
		pr_err("ECCREATE failed with ret 0x%x", ret);
		ret = -EINVAL;
		goto clone_abort;
	}

	ec = get_buffer_page();
	if (!ec) {
		goto clone_abort;
	}

	ea = (struct svsm_ecaddinfo_call *)ec;
	// First copy the page array and sync array from the parent enclave
	xa_for_each(&parent_encl->page_array, index, entry) {
		if (entry->epc_page && entry->type != SGX_PAGE_TYPE_TCS) {
			child_encl_page = kzalloc(sizeof(struct sgx_encl_page), GFP_KERNEL);
			if (!child_encl_page) {
				goto clone_abort;
			}

			child_encl_page->desc = entry->desc;
			child_encl_page->epc_page = entry->epc_page;
			child_encl_page->encl = child_encl;
			child_encl_page->vm_max_prot_bits = entry->vm_max_prot_bits;
			child_encl_page->type = entry->type;
			ret = xa_insert(&child_encl->page_array, PFN_DOWN(child_encl_page->desc), child_encl_page, GFP_KERNEL);
			if (ret) {
				kfree(child_encl_page);
				goto clone_abort;
			}
			atomic_long_inc_return_release(&entry->epc_page->counter);
		}
	}

	xa_for_each(&parent_encl->sync_array, index, sync_entry) {
		child_sync_entry =  kzalloc(sizeof(struct sgx_encl_sync_page), GFP_KERNEL);
		if (!child_sync_entry) {
			goto clone_abort;
		}
		child_sync_entry->paddr = sync_entry->paddr;
		ret = xa_insert(&child_encl->sync_array, index, child_sync_entry, GFP_KERNEL);
		if (ret) {
			kfree(child_sync_entry);
			goto clone_abort;
		}
	}

	for (u16 i = 0; i < CLONE_PT_MAX; i++) {
		do {
			loop = false;

			// First get unadded metadata page details from svsm
			ec->num_entries = ECLONEINFO_MAX_ENTRY_NUM;
			ec->metadata_type = i;
			ret = __ecloneinfo(virt_to_phys(ec), sgx_get_epc_phys_addr(child_encl->secs.epc_page));
			if (ret) {
				pr_err("Failed to fetch pages details when doing eclone in fork with ret %d!", ret);
				goto clone_abort;
			}

			// num_entries has been updated by the firmware, if unchanged, then refetch again after adding
			if (ec->num_entries == ECLONEINFO_MAX_ENTRY_NUM) {
				loop = true;
			}

			if (added_page_num + ec->num_entries > parent_encl->clone_info->clone_info->metadata_page_num - 1) {
				pr_err("Invalid num_entries, exceed defined number!\n");
				ret = -EFAULT;
				goto clone_abort;
			}

			num_entries = ec->num_entries;
			//pr_info("ECADD type: %d", ec->metadata_type);
			for (u16 j = 0; j < num_entries; j++) {

				encl_page = parent_encl->clone_info->metadata_list[added_page_num + j];
				// Check if vaddr and paddr match in the parent enclave
				if (i == CLONE_PT_TCS) {
					entry = xa_load(&parent_encl->tcs_array, PFN_DOWN(ec->cloneinfo[j].vaddr));
					encl_page->type = SGX_PAGE_TYPE_TCS;
				} else {
					entry = xa_load(&parent_encl->page_array, PFN_DOWN(ec->cloneinfo[j].vaddr));
					encl_page->type = SGX_PAGE_TYPE_REG;
				}
				
				if (!entry) {
					pr_err("Invalid vaddr: 0x%llx in fetched cloneinfo", ec->cloneinfo[j].vaddr);
					ret = -EFAULT;
					goto clone_abort;
				}

				// if (PFN_PHYS(entry->epc_page->pfn) != ec->cloneinfo[j].paddr) {
				// 	pr_err("Invalid paddr: 0x%llx in fetched cloneinfo", ec->cloneinfo[j].paddr);
				// 	ret = -EFAULT;
				// 	goto clone_abort;
				// }

				encl_page->desc = ec->cloneinfo[j].vaddr;
				encl_page->encl = child_encl;
				encl_page->vm_max_prot_bits = VM_READ | VM_WRITE;

				// update the paddr for adding pages
				ec->cloneinfo[j].paddr = PFN_PHYS(parent_encl->clone_info->metadata_list[added_page_num + j]->epc_page->pfn);
				//pr_info("vaddr: %llx, paddr: %llx", ec->cloneinfo[j].vaddr, ec->cloneinfo[j].paddr);
			}

			ea->next = 0;
			added_page_num += ec->num_entries;

			//pr_info("ECADD\n");
			ret = __ecadd(virt_to_phys(ea), sgx_get_epc_phys_addr(child_encl->secs.epc_page));
			if (ret) {
				pr_err("Failed to add metadata page for cloned enclave with ret %d!", ret);
				goto clone_abort;
			}

			// First add epc page to tcs array
			if (!loop && i == CLONE_PT_TCS) {
				for (u16 tcs_index = 0; tcs_index < added_page_num; tcs_index++) {
					encl_page = parent_encl->clone_info->metadata_list[tcs_index];
					ret = xa_insert(&child_encl->tcs_array, PFN_DOWN(encl_page->desc), encl_page, GFP_KERNEL);
					if (ret) {
						pr_err("xa_insert tcs_array failed in eclone!\n");
						goto clone_abort;
					}
				}
			}
		} while (loop);
	}
	
	// If added_page_num does not match the number defined in eccreate, secs page is excluded
	if (added_page_num != parent_encl->clone_info->clone_info->metadata_page_num - 1) {
		pr_err("metadata page number does not match!\n");
		goto clone_abort;
	}

	// Add all the pages to page_list of child enclave
	for (u64 i = 0; i < added_page_num; i++) {
		encl_page = parent_encl->clone_info->metadata_list[i];
		entry = xa_store(&child_encl->page_array, PFN_DOWN(encl_page->desc), encl_page, GFP_KERNEL);
		if (xa_is_err(entry)) {
			pr_err("xa_store page_array failed in eclone!");
			goto clone_abort;
		}

		// Metadata Pages are already copied from its parent, decrement the previous counter
		if (entry) {
			atomic_long_dec_return_release(&entry->epc_page->counter);
			kfree(entry);
		}
	}

	//pr_info("ECINIT\n");
	// Finish the clone after adding all the metadata pages
	ret = __ecinit(virt_to_phys(parent_encl->clone_info->clone_info));
	if (ret) {
		pr_err("Failed to initialize the cloned enclave with ret %x!", ret);
		goto clone_abort;
	}

	kfree(parent_encl->clone_info->clone_info);
	clear_bit(SGX_ENCL_CLONE, &child_encl->flags);
	clear_bit(SGX_ENCL_CLONE, &parent_encl->flags);
	//pr_info("parent_encl encl flag: %lx",parent_encl->flags);
	//pr_info("child_encl encl flag: %lx",child_encl->flags);
	// cache sync page is not shared and will be added later
	child_encl->page_cnt = parent_encl->page_cnt - 1;
	child_encl->secs_child_cnt = parent_encl->secs_child_cnt - 1;
	child_encl->sync_page_cnt = parent_encl->sync_page_cnt;

	// If any eaug happened between eclone and ecinit, retry here
	if (!xa_empty(&parent_encl->eaug_retry_array)) {
		struct sgx_pageinfo *pginfo;
		pginfo = kzalloc(sizeof(struct sgx_pageinfo) ,GFP_KERNEL);
		if (!pginfo) {
			force_sig(SIGBUS);
			goto end_elcone;
		}
		xa_for_each(&parent_encl->eaug_retry_array, index, entry) {
			pginfo->secs = (unsigned long)sgx_get_epc_phys_addr(parent_encl->secs.epc_page);
			pginfo->addr = entry->desc & PAGE_MASK;
			pginfo->metadata = 0;
			ret = __eaug(virt_to_phys(pginfo), sgx_get_epc_phys_addr(entry->epc_page));
			if (ret) {
				xa_erase(&parent_encl->page_array, PFN_DOWN(entry->desc));
				sgx_free_epc_page(entry->epc_page, sgx_get_epc_phys_addr(parent_encl->secs.epc_page));
				kfree(entry);
				force_sig(SIGBUS);
			}
		}
		xa_destroy(&parent_encl->page_array);
		kfree(pginfo);
	}
	
end_elcone:
	kfree(parent_encl->clone_info);
	parent_encl->clone_info = NULL;
	mutex_unlock(&child_encl->lock);
	mutex_unlock(&parent_encl->lock);
	preempt_enable();
	return child_encl;

clone_abort:
	xa_for_each(&child_encl->sync_array, index, sync_entry) {
		kfree(sync_entry);
	}

	long epc_page_counter;

	// Free the encl_page struct if the page is not a new page(metadata page)
	// These encl_page will be freed in sgx_enclave_clone_abort;
	xa_for_each(&child_encl->page_array, index, entry) {
		epc_page_counter = atomic_long_dec_return_release(&entry->epc_page->counter);

		// For metadata pages, memory released in sgx_enclave_clone_abort.
		// Revert the decrement of the counter to make colleciton correct.
		if (epc_page_counter == 0) {
			atomic_long_inc_return_release(&entry->epc_page->counter);
		} else {
			kfree(entry);
		}
	}

	xa_destroy(&child_encl->page_array);
	xa_destroy(&child_encl->sync_array);
	mutex_unlock(&child_encl->lock);
	mutex_unlock(&parent_encl->lock);
	sgx_enclave_clone_abort(parent_encl);
	pr_info("sgx_enclave_clone_abort finished");
	
	return NULL;
}

// Open can be trigger 1) after mmap 2) might after mprotect 3) after fork
// Use vma_open and vma_close to manage the enclave lifecycle
// Increment the counter unless this is the first vma_open after mmap
// Decrement the counter in vma_close
static void sgx_vma_open(struct vm_area_struct *vma)
{
	struct sgx_encl *encl, *parent_encl;
	struct xarray *enclave_array = vma->vm_private_data;
	struct enclave_clone_sync_entry* sync_entry;
	struct sgx_epc_page *sync_page_epc;
	bool clone = false;
	int ret;

	//pr_info("vma_open\n");
	if (unlikely(!enclave_array))
		return;

	encl = xa_load(enclave_array, (unsigned long)vma->vm_mm);

	// If cannot search enclave but has a parent enclave
	// In child thread, if there is not an ongoing fork, vma->vm_private_data
	// will be set to NULL, later 
	if (!encl) {
		parent_encl = xa_load(enclave_array, (unsigned long)current->mm);
		if (parent_encl) {
			pr_info("parent_encl existed\n");
		} else {
			pr_info("Cannot find parent enclave\n");
		}
		if (parent_encl && parent_encl->clone_info) {
			clone = true;
			pr_info("start clone!\n");
			
			// do eclone if child is binded
			encl = clone_enclave(parent_encl);
			// Register the sync page after child is cloned
			if (encl) {
				//insert it into the enclave list
				// pr_info("clone parent mm: 0x%lx, child mm: 0x%lx\n",(unsigned long)current->mm, (unsigned long)vma->vm_mm);
				encl->enclave_array = enclave_array;
				ret = xa_insert(enclave_array, (unsigned long)vma->vm_mm,encl, GFP_KERNEL);
				if (ret) {
					goto encl_failed_after_clone;
				}

				sync_entry = kmalloc(sizeof(struct enclave_clone_sync_entry), GFP_KERNEL);
				if (!sync_entry) {
					goto encl_failed_after_insert;
				}

				sync_page_epc = sgx_alloc_epc_page(&encl->secs, true);
				if (IS_ERR(sync_page_epc)) {
					kfree(sync_entry);
					pr_err("sgx_alloc_epc_page for sync page of child enclave error\n");
					goto encl_failed_after_insert;
				}
				sync_entry->encl = encl;
				sync_entry->sync_page_epc = sync_page_epc;
				mutex_init(&sync_entry->lock);
				encl->page_cnt++;
				encl->secs_child_cnt++;
				encl->cow_sync_page.epc_page = sync_page_epc;

				// If clone attribute bit is set, register the sync page and add it to the work_list
				ret = __ecsync(sgx_get_epc_phys_addr(encl->secs.epc_page), sgx_get_epc_phys_addr(sync_page_epc));
				if (ret) {
					pr_err("ECSYNC returned %d\n", ret);
					ret = -EIO;
					goto err_ecsync;
				}

				if (xa_insert(&clone_sync_array, encl->secs.epc_page->pfn, sync_entry, GFP_KERNEL)) {
					pr_err("sync page of the enclave has already been added!");
					ret = -EIO;
					goto err_ecsync;
				}
				clear_bit(SGX_ENCL_CLONE_FAIL, &parent_encl->flags);
				clear_bit(SGX_ENCL_CLONE_FAIL, &encl->flags);
			} else {
				pr_err("clone_enclave failed\n");
				goto encl_open_failed;
			}
		} else {
			// If the function is tirggered not by fork after eclone, but parent enclave exists,
			// falls back to the normal clone flow.
			if (parent_encl) {
				encl = parent_encl;
				// pr_info("fall back parent mm: 0x%lx, child mm: 0x%lx\n",(unsigned long)current->mm, (unsigned long)vma->vm_mm);
				ret = xa_insert(enclave_array, (unsigned long)vma->vm_mm,encl, GFP_KERNEL);
				if (ret) {
					pr_err("cannot insert into enclave array\n");
					goto encl_open_failed;
				}
			}
			else {
				pr_err("vma_open without parent enclave!\n");
				goto encl_open_failed;
			}
		}
	}
		
		

	// To keep the refcount correctly, do not increment the counter first time after clone
	// counter is initialized set to one during clone
	if (test_and_set_bit(SGX_ENCL_MMAP, &encl->flags)) {
		kref_get(&encl->refcount);
	}

	// If register the encl failed, release the encl here, it will not released in sgx_vma_close
	if (sgx_encl_mm_add(encl, vma->vm_mm)) {
		kref_put(&encl->refcount, sgx_encl_release);
		goto encl_open_failed;
	}
	//pr_info("vma_open refcount=%d\n", kref_read(&encl->refcount));

	return;
err_ecsync:
	encl->cow_sync_page.epc_page = NULL;
	sgx_free_epc_page(sync_page_epc, sgx_get_epc_phys_addr(encl->secs.epc_page));
	synchronize_rcu();
	kfree(sync_entry);
	encl->page_cnt--;
	encl->secs_child_cnt--;
encl_failed_after_insert:
	xa_erase(enclave_array, (unsigned long)vma->vm_mm);
encl_failed_after_clone:
	kref_put(&encl->refcount, sgx_encl_release);
encl_open_failed:
	if (clone) {
		set_bit(SGX_ENCL_CLONE_FAIL, &parent_encl->flags);
	}
	vma->vm_private_data = NULL;
	pr_info("vma_open clone failed end\n");
	return;
}


/**
 * sgx_encl_may_map() - Check if a requested VMA mapping is allowed
 * @encl:		an enclave pointer
 * @start:		lower bound of the address range, inclusive
 * @end:		upper bound of the address range, exclusive
 * @vm_flags:		VMA flags
 *
 * Iterate through the enclave pages contained within [@start, @end) to verify
 * that the permissions requested by a subset of {VM_READ, VM_WRITE, VM_EXEC}
 * do not contain any permissions that are not contained in the build time
 * permissions of any of the enclave pages within the given address range.
 *
 * An enclave creator must declare the strongest permissions that will be
 * needed for each enclave page. This ensures that mappings have the identical
 * or weaker permissions than the earlier declared permissions.
 *
 * Return: 0 on success, -EACCES otherwise
 */
int sgx_encl_may_map(struct sgx_encl *encl, unsigned long start,
		     unsigned long end, unsigned long vm_flags)
{
	unsigned long vm_prot_bits = vm_flags & (VM_READ | VM_WRITE | VM_EXEC);
	struct sgx_encl_page *page;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	unsigned long count = 0;
	int ret = 0;

	XA_STATE(xas, &encl->page_array, PFN_DOWN(start));
#else
	unsigned long idx;
	unsigned long idx_start = PFN_DOWN(start);
	unsigned long idx_end = PFN_DOWN(end - 1);

#endif
	/*
	 * Disallow READ_IMPLIES_EXEC tasks as their VMA permissions might
	 * conflict with the enclave page permissions.
	 */
	if (current->personality & READ_IMPLIES_EXEC)
		return -EACCES;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	mutex_lock(&encl->lock);
	xas_lock(&xas);
	xas_for_each(&xas, page, PFN_DOWN(end - 1)) {
		if (~page->vm_max_prot_bits & vm_prot_bits) {
			ret = -EACCES;
			break;
		}

		/* Reschedule on every XA_CHECK_SCHED iteration. */
		if (!(++count % XA_CHECK_SCHED)) {
			xas_pause(&xas);
			xas_unlock(&xas);
			mutex_unlock(&encl->lock);

			cond_resched();

			mutex_lock(&encl->lock);
			xas_lock(&xas);
		}
	}
	xas_unlock(&xas);
	mutex_unlock(&encl->lock);

	return ret;

#else
	for (idx = idx_start; idx <= idx_end; ++idx) {
		mutex_lock(&encl->lock);
		page = radix_tree_lookup(&encl->page_tree, idx);
		mutex_unlock(&encl->lock);
		if (!page || (~page->vm_max_prot_bits & vm_prot_bits))
			return -EACCES;
	}
	return 0;
#endif
}


static int sgx_vma_mprotect(struct vm_area_struct *vma, unsigned long start,
			    unsigned long end, unsigned long newflags)
{
	struct xarray *enclave_array = vma->vm_private_data;
	struct sgx_encl *encl;
	if (!enclave_array) {
		return -EFAULT;
	}
	
	encl = xa_load(enclave_array, (unsigned long)vma->vm_mm);
	return sgx_encl_may_map(encl, start, end, newflags);
}

static int sgx_encl_debug_read(struct sgx_encl *encl, struct sgx_encl_page *page,
			       unsigned long addr, void *data)
{
	unsigned long offset = addr & ~PAGE_MASK;
	int ret;


	ret = __edbgrd(sgx_get_epc_phys_addr(page->epc_page) + offset, virt_to_phys(data));
	if (ret)
		return -EIO;

	return 0;
}

static int sgx_encl_debug_write(struct sgx_encl *encl, struct sgx_encl_page *page,
				unsigned long addr, void *data)
{
	unsigned long offset = addr & ~PAGE_MASK;
	int ret;

	ret = __edbgwr(sgx_get_epc_phys_addr(page->epc_page) + offset, *(u64 *)data);
	if (ret)
		return -EIO;

	return 0;
}

/*
 * Load an enclave page to EPC if required, and take encl->lock.
 */
static struct sgx_encl_page *sgx_encl_reserve_page(struct sgx_encl *encl,
						   unsigned long addr,
						   unsigned long vm_flags)
{
	struct sgx_encl_page *entry;

	for ( ; ; ) {
		mutex_lock(&encl->lock);

		entry = sgx_get_encl_page(encl, addr, vm_flags);
		if (PTR_ERR(entry) != -EBUSY)
			break;

		mutex_unlock(&encl->lock);
	}

	if (IS_ERR(entry))
		mutex_unlock(&encl->lock);

	return entry;
}

static int sgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
			  void *buf, int len, int write)
{
	struct xarray *enclave_array = vma->vm_private_data;
	struct sgx_encl *encl;
	struct sgx_encl_page *entry = NULL;
	char *data;
	unsigned long align;
	int offset;
	int cnt;
	int ret = 0;
	int i;

	/*
	 * If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (unlikely(!enclave_array))
		return -EFAULT;

	encl = xa_load(vma->vm_private_data, (unsigned long)vma->vm_mm);
	
	data = kzalloc(sizeof(unsigned long) ,GFP_KERNEL);
	//pr_info("sgx_vma_access addr: 0x%lx, buf: 0x%lx, len: 0x%x, write: %d", addr, (unsigned long)buf, len, write);
	if (!encl)
		return -EFAULT;

	if (!test_bit(SGX_ENCL_DEBUG, &encl->flags))
		return -EFAULT;

	for (i = 0; i < len; i += cnt) {
		entry = sgx_encl_reserve_page(encl, (addr + i) & PAGE_MASK,
					      vma->vm_flags);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry);
			break;
		}

		align = ALIGN_DOWN(addr + i, sizeof(unsigned long));
		offset = (addr + i) & (sizeof(unsigned long) - 1);
		cnt = sizeof(unsigned long) - offset;
		cnt = min(cnt, len - i);

		ret = sgx_encl_debug_read(encl, entry, align, data);
		if (ret)
			goto out;

		if (write) {
			memcpy(data + offset, buf + i, cnt);
			ret = sgx_encl_debug_write(encl, entry, align, data);
			if (ret)
				goto out;
		} else {
			memcpy(buf + i, data + offset, cnt);
		}

out:
		mutex_unlock(&encl->lock);

		if (ret)
			break;
	}

	return ret < 0 ? ret : i;
}

const struct vm_operations_struct sgx_vm_ops = {
	.fault = sgx_vma_fault,
	.mprotect = sgx_vma_mprotect,
	.open = sgx_vma_open,
	.close = sgx_vma_close,
	.access = sgx_vma_access,
};

/**
 * sgx_encl_release - Destroy an enclave instance
 * @kref:	address of a kref inside &sgx_encl
 *
 * Used together with kref_put(). Frees all the resources associated with the
 * enclave and the instance itself.
 */
void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);
	//struct sgx_va_page *va_page;
	struct sgx_encl_page *entry;
	struct sgx_encl_sync_page *sync_entry;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0))
	struct radix_tree_iter iter;
	void **slot;
#else
	unsigned long index;
#endif
	unsigned long sync_vfn;
	struct sgx_encl_mm *encl_mm;
	pr_info("enclave start releasing\n");
	/*
	 * Drain the remaining mm_list entries. At this point the list contains
	 * entries for processes, which have closed the enclave file but have
	 * not exited yet. The processes, which have exited, are gone from the
	 * list by sgx_mmu_notifier_release().
	 */
	for ( ; ; )  {
		spin_lock(&encl->mm_lock);

		if (list_empty(&encl->mm_list)) {
			encl_mm = NULL;
		} else {
			encl_mm = list_first_entry(&encl->mm_list,
						   struct sgx_encl_mm, list);
			list_del_rcu(&encl_mm->list);
		}

		spin_unlock(&encl->mm_lock);

		/* The enclave is no longer mapped by any mm. */
		if (!encl_mm)
			break;

		synchronize_srcu(&encl->srcu);
		xa_erase(encl->enclave_array, (unsigned long)encl_mm->mm);
		mmu_notifier_unregister(&encl_mm->mmu_notifier, encl_mm->mm);
		kfree(encl_mm);
	}


	if (test_bit(SGX_ENCL_CLONE, &encl->flags)) {
		sgx_enclave_clone_abort(encl);
	}

	// First remove all the unused cache pages by ECCLEARCACHE
	// Then Sync all the updates and release the sync page
	// Skip if the enclave is cloned and not initialized
	if (encl->attributes & SGX_ATTR_CLONE && 
		encl->cow_sync_page.epc_page) {
		struct enclave_clone_sync_entry* clone_sync_entry;
		int ret;
		ret = __ecclearcache(sgx_get_epc_phys_addr(encl->secs.epc_page));
		if (ret) {
			pr_err("ECCLEARCACHE failed with ret %d!", ret);
		}
		
		clone_sync_entry = xa_erase(&clone_sync_array, encl->secs.epc_page->pfn);
		sync_page_once(clone_sync_entry, true);
		synchronize_rcu();
		sgx_free_epc_page(encl->cow_sync_page.epc_page, sgx_get_epc_phys_addr(encl->secs.epc_page));
		encl->secs_child_cnt--;
		encl->cow_sync_page.epc_page = NULL;
		kfree(clone_sync_entry);
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0))
	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;
#else
	xa_for_each(&encl->page_array, index, entry) {
#endif
		if (entry->epc_page) {
			/*
			 * The page and its radix tree entry cannot be freed
			 * if the page is being held by the reclaimer.
			 */
			//if (sgx_unmark_page_reclaimable(entry->epc_page))
			//	continue;

			sgx_free_epc_page(entry->epc_page, sgx_get_epc_phys_addr(encl->secs.epc_page));
			encl->secs_child_cnt--;
			entry->epc_page = NULL;
		}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0))
		radix_tree_delete(&entry->encl->page_tree,
				  PFN_DOWN(entry->desc));
#endif
		kfree(entry);
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	xa_destroy(&encl->page_array);
#endif

	xa_for_each(&encl->sync_array, sync_vfn, sync_entry) {
		if (sgx_encl_eunsync(encl, sync_entry->paddr, sync_vfn << PAGE_SHIFT))
			pr_err("eunsync in sgx release failed with vaddr:0x%lx, paddr:0x%llx\n"
			, sync_vfn << PAGE_SHIFT, sync_entry->paddr);

		encl->sync_page_cnt--;
		kfree(sync_entry);
	}
	xa_destroy(&encl->sync_array);
	xa_destroy(&encl->tcs_array);

	if (encl->secs_child_cnt) {
		pr_err("sgx_encl_release has unreleased child page, count: %d\n",encl->secs_child_cnt);
	}

	if (!encl->secs_child_cnt && encl->secs.epc_page) {
		sgx_free_epc_page(encl->secs.epc_page, sgx_get_epc_phys_addr(encl->secs.epc_page));
		encl->secs.epc_page = NULL;
	}

	/*
	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
					   list);
		list_del(&va_page->list);
		sgx_free_epc_page(va_page->epc_page);
		kfree(va_page);
	}
	*/

	//if (encl->backing)
	//	fput(encl->backing);
	synchronize_srcu_expedited(&encl->srcu);
	cleanup_srcu_struct(&encl->srcu);

	WARN_ON_ONCE(!list_empty(&encl->mm_list));

	/* Detect EPC page leak's. */
	WARN_ON_ONCE(encl->secs_child_cnt);
	WARN_ON_ONCE(encl->secs.epc_page);

	pr_info("enclave released\n");
	kfree(encl);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
static void sgx_encl_mm_release_deferred(struct rcu_head *rcu)
{
	struct sgx_encl_mm *encl_mm =
		container_of(rcu, struct sgx_encl_mm, rcu);

	kfree(encl_mm);
}
#endif

/*
 * 'mm' is exiting and no longer needs mmu notifications.
 */
static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	// The callback function will remove the item in mm_list which is required in encl_release
	// just skip this part.
// 	struct sgx_encl_mm *encl_mm = container_of(mn, struct sgx_encl_mm, mmu_notifier);
// 	struct sgx_encl_mm *tmp = NULL;

// 	/*
// 	 * The enclave itself can remove encl_mm.  Note, objects can't be moved
// 	 * off an RCU protected list, but deletion is ok.
// 	 */
// 	spin_lock(&encl_mm->encl->mm_lock);
// 	list_for_each_entry(tmp, &encl_mm->encl->mm_list, list) {
// 		if (tmp == encl_mm) {
// 			list_del_rcu(&encl_mm->list);
// 			break;
// 		}
// 	}
// 	spin_unlock(&encl_mm->encl->mm_lock);

// 	if (tmp == encl_mm) {
// 		synchronize_srcu(&encl_mm->encl->srcu);
// #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0))
// 		mmu_notifier_put(mn);
// #else
//             /*
//             * Delay freeing encl_mm until after mmu_notifier synchronizes
//             * its SRCU to ensure encl_mm cannot be dereferenced.
//             */
//             mmu_notifier_unregister_no_release(mn, mm);
//             mmu_notifier_call_srcu(&encl_mm->rcu,
//                                &sgx_encl_mm_release_deferred);
// #endif
// 	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0))
static void sgx_mmu_notifier_free(struct mmu_notifier *mn)
{
	struct sgx_encl_mm *encl_mm = container_of(mn, struct sgx_encl_mm, mmu_notifier);

	kfree(encl_mm);
}
#endif

static int sgx_mmu_notifier_invalidate(struct mmu_notifier *mn,
				      const struct mmu_notifier_range *range)
{
	struct sgx_encl* encl;
	struct mm_struct *mm;
	unsigned long sync_vfn;
	unsigned long start = PFN_DOWN(range->start);
	// range is [start, end) but in the xa_for_each_range is [start, last]
	unsigned long last = (range->end - 1) >> PAGE_SHIFT;

	struct sgx_encl_sync_page *sync_entry;
	struct sgx_encl_mm *encl_mm = container_of(mn, struct sgx_encl_mm, mmu_notifier);

	//pr_info("mmu_notifier start，range start=0x%lx, end=0x%lx\n", range->start, range->end);
	encl = encl_mm->encl;
	mm = encl_mm->mm;
	mutex_lock(&encl->sync_lock);
	xa_for_each_range(&encl->sync_array, sync_vfn, sync_entry, start, last) {
		 // pr_info("eunsync: paddr=0x%llx, vaddr=0x%lx， mm=0x%lx\n",
         // sync_entry->paddr, sync_vfn << PAGE_SHIFT, (unsigned long)mm);
		int ret = sgx_encl_eunsync(encl, sync_entry->paddr, sync_vfn << PAGE_SHIFT);
		if (!ret) {
			xa_erase(&encl->sync_array, sync_vfn);
			kfree(sync_entry);
		}
	}
	mutex_unlock(&encl->sync_lock);
	//pr_info("mmu_notifier end\n");

	return 0;
}

static const struct mmu_notifier_ops sgx_mmu_notifier_ops = {
	.release		= sgx_mmu_notifier_release,
	.invalidate_range_start = sgx_mmu_notifier_invalidate,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0))
	.free_notifier		= sgx_mmu_notifier_free,
#endif
};

static struct sgx_encl_mm *sgx_encl_find_mm(struct sgx_encl *encl,
					    struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm = NULL;
	struct sgx_encl_mm *tmp;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(tmp, &encl->mm_list, list) {
		if (tmp->mm == mm) {
			encl_mm = tmp;
			break;
		}
	}

	srcu_read_unlock(&encl->srcu, idx);

	return encl_mm;
}

int sgx_encl_mm_add(struct sgx_encl *encl, struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm;
	int ret;

	/*
	 * Even though a single enclave may be mapped into an mm more than once,
	 * each 'mm' only appears once on encl->mm_list. This is guaranteed by
	 * holding the mm's mmap lock for write before an mm can be added or
	 * remove to an encl->mm_list.
	 */
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
	mmap_assert_write_locked(mm);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0))
	lockdep_assert_held_write(&mm->mmap_sem);
#else
	lockdep_assert_held_exclusive(&mm->mmap_sem);
#endif

	/*
	 * It's possible that an entry already exists in the mm_list, because it
	 * is removed only on VFS release or process exit.
	 */
	if (sgx_encl_find_mm(encl, mm))
		return 0;

	encl_mm = kzalloc(sizeof(*encl_mm), GFP_KERNEL);
	if (!encl_mm)
		return -ENOMEM;

	encl_mm->encl = encl;
	encl_mm->mm = mm;
	encl_mm->mmu_notifier.ops = &sgx_mmu_notifier_ops;

	ret = __mmu_notifier_register(&encl_mm->mmu_notifier, mm);
	if (ret) {
		kfree(encl_mm);
		return ret;
	}

	spin_lock(&encl->mm_lock);
	list_add_rcu(&encl_mm->list, &encl->mm_list);
	/* Pairs with smp_rmb() in sgx_reclaimer_block(). */
	//smp_wmb();
	encl->mm_list_version++;
	spin_unlock(&encl->mm_lock);

	return 0;
}

/*
static struct page *sgx_encl_get_backing_page(struct sgx_encl *encl,
					      pgoff_t index)
{
	struct inode *inode = encl->backing->f_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfpmask = mapping_gfp_mask(mapping);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}
*/
/**
 * sgx_encl_get_backing() - Pin the backing storage
 * @encl:	an enclave pointer
 * @page_index:	enclave page index
 * @backing:	data for accessing backing storage for the page
 *
 * Pin the backing storage pages for storing the encrypted contents and Paging
 * Crypto MetaData (PCMD) of an enclave page.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise.
 */
/*
int sgx_encl_get_backing(struct sgx_encl *encl, unsigned long page_index,
			 struct sgx_backing *backing)
{
	pgoff_t pcmd_index = PFN_DOWN(encl->size) + 1 + (page_index >> 5);
	struct page *contents;
	struct page *pcmd;

	contents = sgx_encl_get_backing_page(encl, page_index);
	if (IS_ERR(contents))
		return PTR_ERR(contents);

	pcmd = sgx_encl_get_backing_page(encl, pcmd_index);
	if (IS_ERR(pcmd)) {
		put_page(contents);
		return PTR_ERR(pcmd);
	}

	backing->page_index = page_index;
	backing->contents = contents;
	backing->pcmd = pcmd;
	backing->pcmd_offset =
		(page_index & (PAGE_SIZE / sizeof(struct sgx_pcmd) - 1)) *
		sizeof(struct sgx_pcmd);

	return 0;
}
*/

/**
 * sgx_encl_put_backing() - Unpin the backing storage
 * @backing:	data for accessing backing storage for the page
 * @do_write:	mark pages dirty
 */
/*
void sgx_encl_put_backing(struct sgx_backing *backing, bool do_write)
{
	if (do_write) {
		set_page_dirty(backing->pcmd);
		set_page_dirty(backing->contents);
	}

	put_page(backing->pcmd);
	put_page(backing->contents);
}
*/

/*
static int sgx_encl_test_and_clear_young_cb(pte_t *ptep,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0))
    #if( defined(RHEL_RELEASE_VERSION) && defined(RHEL_RELEASE_CODE))
        #if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(8, 1))
				       pgtable_t token,
        #endif
    #else
				       pgtable_t token,
    #endif
#endif
				       unsigned long addr, void *data)
{
	pte_t pte;
	int ret;

	ret = pte_young(*ptep);
	if (ret) {
		pte = pte_mkold(*ptep);
		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
	}

	return ret;
}
*/
/**
 * sgx_encl_test_and_clear_young() - Test and reset the accessed bit
 * @mm:		mm_struct that is checked
 * @page:	enclave page to be tested for recent access
 *
 * Checks the Access (A) bit from the PTE corresponding to the enclave page and
 * clears it.
 *
 * Return: 1 if the page has been recently accessed and 0 if not.
 */
/*
int sgx_encl_test_and_clear_young(struct mm_struct *mm,
				  struct sgx_encl_page *page)
{
	unsigned long addr = page->desc & PAGE_MASK;
	struct sgx_encl *encl = page->encl;
	struct vm_area_struct *vma;
	int ret;

	ret = sgx_encl_find(mm, addr, &vma);
	if (ret)
		return 0;

	if (encl != vma->vm_private_data)
		return 0;

	ret = apply_to_page_range(vma->vm_mm, addr, PAGE_SIZE,
				  sgx_encl_test_and_clear_young_cb, vma->vm_mm);
	if (ret < 0)
		return 0;

	return ret;
}
*/
/**
 * sgx_alloc_va_page() - Allocate a Version Array (VA) page
 *
 * Allocate a free EPC page and convert it to a Version Array (VA) page.
 *
 * Return:
 *   a VA page,
 *   -errno otherwise
 */
/*
struct sgx_epc_page *sgx_alloc_va_page(void)
{
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_epc_page(NULL, true);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	ret = __epa(sgx_get_epc_virt_addr(epc_page));
	if (ret) {
		WARN_ONCE(1, "EPA returned %d (0x%x)", ret, ret);
		sgx_free_epc_page(epc_page);
		return ERR_PTR(-EFAULT);
	}

	return epc_page;
}
*/

/**
 * sgx_alloc_va_slot - allocate a VA slot
 * @va_page:	a &struct sgx_va_page instance
 *
 * Allocates a slot from a &struct sgx_va_page instance.
 *
 * Return: offset of the slot inside the VA page
 */
/*
unsigned int sgx_alloc_va_slot(struct sgx_va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, SGX_VA_SLOT_COUNT);

	if (slot < SGX_VA_SLOT_COUNT)
		set_bit(slot, va_page->slots);

	return slot << 3;
}
*/


/**
 * sgx_free_va_slot - free a VA slot
 * @va_page:	a &struct sgx_va_page instance
 * @offset:	offset of the slot inside the VA page
 *
 * Frees a slot from a &struct sgx_va_page instance.
 */
/*
void sgx_free_va_slot(struct sgx_va_page *va_page, unsigned int offset)
{
	clear_bit(offset >> 3, va_page->slots);
}
*/

/**
 * sgx_va_page_full - is the VA page full?
 * @va_page:	a &struct sgx_va_page instance
 *
 * Return: true if all slots have been taken
 */
/*
bool sgx_va_page_full(struct sgx_va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, SGX_VA_SLOT_COUNT);

	return slot == SGX_VA_SLOT_COUNT;
}
*/