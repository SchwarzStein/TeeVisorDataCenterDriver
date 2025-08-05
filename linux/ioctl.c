// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*  Copyright(c) 2016-21 Intel Corporation. */

#include <asm/mman.h>
#include <linux/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include "driver.h"
#include "encl.h"
#include "encls.h"

#include <linux/version.h>

/*
static struct sgx_va_page *sgx_encl_grow(struct sgx_encl *encl)
{
	struct sgx_va_page *va_page = NULL;
	void *err;

	BUILD_BUG_ON(SGX_VA_SLOT_COUNT !=
		(SGX_ENCL_PAGE_VA_OFFSET_MASK >> 3) + 1);

	if (!(encl->page_cnt % SGX_VA_SLOT_COUNT)) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return ERR_PTR(-ENOMEM);

		va_page->epc_page = sgx_alloc_va_page();
		if (IS_ERR(va_page->epc_page)) {
			err = ERR_CAST(va_page->epc_page);
			kfree(va_page);
			return err;
		}

		WARN_ON_ONCE(encl->page_cnt % SGX_VA_SLOT_COUNT);
	}
	encl->page_cnt++;
	return va_page;
}
*/

/*
static void sgx_encl_shrink(struct sgx_encl *encl, struct sgx_va_page *va_page)
{
	encl->page_cnt--;

	if (va_page) {
		sgx_free_epc_page(va_page->epc_page);
		list_del(&va_page->list);
		kfree(va_page);
	}
}
*/

static int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
{
	struct sgx_epc_page *secs_epc;
	//struct sgx_va_page *va_page;
	struct sgx_pageinfo *pginfo;
	struct sgx_secinfo *secinfo;
	//unsigned long encl_size;
	//struct file *backing;
	long ret;

	encl->page_cnt++;
	
	/*va_page = sgx_encl_grow(encl);
	if (IS_ERR(va_page))
		return PTR_ERR(va_page);
	else if (va_page)
		list_add(&va_page->list, &encl->va_pages);*/
	/* else the tail page of the VA page list had free slots. */

	/* The extra page goes to SECS. */
	/*
	encl_size = secs->size + PAGE_SIZE;

	backing = shmem_file_setup("SGX backing", encl_size + (encl_size >> 5),
				   VM_NORESERVE);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto err_out_shrink;
	}

	encl->backing = backing;
	*/
	secs_epc = sgx_alloc_epc_page(&encl->secs, true);
	if (IS_ERR(secs_epc)) {
		pr_err("sgx_alloc_epc_page error\n");
		ret = PTR_ERR(secs_epc);
		goto err_out_backing;
	}

	encl->secs.epc_page = secs_epc;
	pginfo = kmalloc(sizeof(struct sgx_pageinfo) ,GFP_KERNEL);
	secinfo = kmalloc(sizeof(struct sgx_secinfo) ,GFP_KERNEL);
	if (!pginfo || !secinfo) {
		ret = -ENOMEM;
		goto err_out_backing;
	}

	pginfo->addr = 0;
	pginfo->contents = (unsigned long)virt_to_phys(secs);
	pginfo->metadata = (unsigned long)virt_to_phys(secinfo);
	pginfo->secs = 0;
	memset(secinfo, 0, sizeof(secinfo));

	ret = __ecreate(virt_to_phys(pginfo), sgx_get_epc_phys_addr(secs_epc));

	kfree(pginfo);
	kfree(secinfo);

	if (ret) {
		ret = -EIO;
		pr_debug("ECREATE returned %ld\n", ret);
		goto err_out;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		set_bit(SGX_ENCL_DEBUG, &encl->flags);

	if 	(secs->attributes & SGX_ATTR_RUNTIME) {
		set_bit(SGX_ENCL_RUNTIME, &encl->flags);
		encl->runtime_base = secs->runtime_base;
		encl->runtime_size = secs->runtime_size;
	}

	encl->secs.encl = encl;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->attributes = secs->attributes;
	//encl->attributes_mask = SGX_ATTR_DEBUG | SGX_ATTR_MODE64BIT | SGX_ATTR_KSS;
	encl->attributes_mask = SGX_ATTR_DEBUG | SGX_ATTR_MODE64BIT | SGX_ATTR_RUNTIME;

	/* Set only after completion, as encl->lock has not been taken. */
	set_bit(SGX_ENCL_CREATED, &encl->flags);

	return 0;

err_out:
	sgx_free_epc_page(encl->secs.epc_page);
	encl->secs.epc_page = NULL;

err_out_backing:
	//fput(encl->backing);
	//encl->backing = NULL;

//err_out_shrink:
	encl->page_cnt--;
	//sgx_encl_shrink(encl, va_page);

	return ret;
}

/**
 * sgx_ioc_enclave_create() - handler for %SGX_IOC_ENCLAVE_CREATE
 * @encl:	An enclave pointer.
 * @arg:	The ioctl argument.
 *
 * Allocate kernel data structures for the enclave and invoke ECREATE.
 *
 * Return:
 * - 0:		Success.
 * - -EIO:	ECREATE failed.
 * - -errno:	POSIX error.
 */
static long sgx_ioc_enclave_create(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_create create_arg;
	void *secs;
	int ret;

	if (test_bit(SGX_ENCL_CREATED, &encl->flags))
		return -EINVAL;

	if (copy_from_user(&create_arg, arg, sizeof(create_arg)))
		return -EFAULT;

	secs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!secs)
		return -ENOMEM;

	if (copy_from_user(secs, (void __user *)create_arg.src, PAGE_SIZE))
		ret = -EFAULT;
	else
		ret = sgx_encl_create(encl, secs);

	kfree(secs);
	return ret;
}

struct sgx_encl_page *sgx_encl_page_alloc(struct sgx_encl *encl,
						 unsigned long dst,
						 u64 secinfo_flags)
{
	struct sgx_encl_page *encl_page;
	unsigned long prot;

	encl_page = kzalloc(sizeof(*encl_page), GFP_KERNEL);
	if (!encl_page)
		return ERR_PTR(-ENOMEM);

	encl_page->desc = dst;
	encl_page->encl = encl;

	prot = _calc_vm_trans(secinfo_flags, SGX_SECINFO_R, PROT_READ)  |
	       _calc_vm_trans(secinfo_flags, SGX_SECINFO_W, PROT_WRITE) |
	       _calc_vm_trans(secinfo_flags, SGX_SECINFO_X, PROT_EXEC);

	/*
	 * TCS pages must always RW set for CPU access while the SECINFO
	 * permissions are *always* zero - the CPU ignores the user provided
	 * values and silently overwrites them with zero permissions.
	 */
	if ((secinfo_flags & SGX_SECINFO_PAGE_TYPE_MASK) == SGX_SECINFO_TCS)
		prot |= PROT_READ | PROT_WRITE;

	/* Calculate maximum of the VM flags for the page. */
	encl_page->vm_max_prot_bits = calc_vm_prot_bits(prot, 0);

	return encl_page;
}

static int sgx_validate_secinfo(struct sgx_secinfo *secinfo)
{
	u64 perm = secinfo->flags & SGX_SECINFO_PERMISSION_MASK;
	u64 pt   = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;

	if (pt != SGX_SECINFO_REG && pt != SGX_SECINFO_TCS)
		return -EINVAL;

	if ((perm & SGX_SECINFO_W) && !(perm & SGX_SECINFO_R))
		return -EINVAL;

	/*
	 * CPU will silently overwrite the permissions as zero, which means
	 * that we need to validate it ourselves.
	 */
	if (pt == SGX_SECINFO_TCS && perm)
		return -EINVAL;

	if (secinfo->flags & SGX_SECINFO_RESERVED_MASK)
		return -EINVAL;

	if (memchr_inv(secinfo->reserved, 0, sizeof(secinfo->reserved)))
		return -EINVAL;

	return 0;
}

static int __sgx_encl_add_page(struct sgx_encl *encl,
			       struct sgx_encl_page *encl_page,
			       struct sgx_epc_page *epc_page,
			       struct sgx_secinfo *secinfo, unsigned long src)
{
	struct sgx_pageinfo *pginfo;
	struct vm_area_struct *vma;
	struct page *src_page;
	int ret;

	/* Deny noexec. */
	vma = find_vma(current->mm, src);
	if (!vma)
		return -EFAULT;

	if (!(vma->vm_flags & VM_MAYEXEC))
		return -EACCES;

	ret = get_user_pages(src, 1, 0, &src_page);
	if (ret < 1)
		return -EFAULT;

	pginfo = kmalloc(sizeof(struct sgx_pageinfo) ,GFP_KERNEL);

	if (!pginfo) {
		return -ENOMEM;
	}

	pginfo->secs = (unsigned long)sgx_get_epc_phys_addr(encl->secs.epc_page);
	pginfo->addr = encl_page->desc & PAGE_MASK;
	pginfo->metadata = virt_to_phys(secinfo);
	pginfo->contents = (unsigned long)page_to_phys(src_page);

	ret = __eadd(virt_to_phys(pginfo), sgx_get_epc_phys_addr(epc_page));
	pr_info("sgx_add_page vaddr:0x%llx, paddr:0x%llx", pginfo->addr, pginfo->contents);
	kfree(pginfo);
	put_page(src_page);

	return ret ? -EIO : 0;
}

/*
 * If the caller requires measurement of the page as a proof for the content,
 * use EEXTEND to add a measurement for 256 bytes of the page. Repeat this
 * operation until the entire page is measured."
 */
static int __sgx_encl_extend(struct sgx_encl *encl,
			     struct sgx_epc_page *epc_page)
{
	unsigned long offset;
	int ret;

	for (offset = 0; offset < PAGE_SIZE; offset += SGX_EEXTEND_BLOCK_SIZE) {
		ret = __eextend(sgx_get_epc_phys_addr(encl->secs.epc_page),
				sgx_get_epc_phys_addr(epc_page) + offset);
		if (ret) {
			//if (encls_failed(ret))
			ENCLS_WARN(ret, "EEXTEND");

			return -EIO;
		}
	}

	return 0;
}

static int sgx_encl_add_page(struct sgx_encl *encl, unsigned long src,
			     unsigned long dst, struct sgx_secinfo *secinfo,
			     unsigned long flags)
{
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	//struct sgx_va_page *va_page;
	int ret;

	encl->page_cnt++;
	encl_page = sgx_encl_page_alloc(encl, dst, secinfo->flags);
	if (IS_ERR(encl_page))
		return PTR_ERR(encl_page);

	epc_page = sgx_alloc_epc_page(encl_page, true);
	if (IS_ERR(epc_page)) {
		kfree(encl_page);
		return PTR_ERR(epc_page);
	}

	/*
	va_page = sgx_encl_grow(encl);
	if (IS_ERR(va_page)) {
		ret = PTR_ERR(va_page);
		goto err_out_free;
	}
	*/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
	mmap_read_lock(current->mm);
#else
	down_read(&current->mm->mmap_sem);
#endif
	mutex_lock(&encl->lock);

	/*
	 * Adding to encl->va_pages must be done under encl->lock.  Ditto for
	 * deleting (via sgx_encl_shrink()) in the error path.
	 */

	//if (va_page)
	//	list_add(&va_page->list, &encl->va_pages);

	/*
	 * Insert prior to EADD in case of OOM.  EADD modifies MRENCLAVE, i.e.
	 * can't be gracefully unwound, while failure on EADD/EXTEND is limited
	 * to userspace errors (or kernel/hardware bugs).
	 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0))
	ret = xa_insert(&encl->page_array, PFN_DOWN(encl_page->desc),
			encl_page, GFP_KERNEL);
#else
	ret = radix_tree_insert(&encl->page_tree, PFN_DOWN(encl_page->desc),
				encl_page);
#endif
	if (ret)
		goto err_out_unlock;

	if (secinfo->flags & SGX_SECINFO_TCS) {
		ret = xa_insert(&encl->tcs_array, PFN_DOWN(encl_page->desc),
			encl_page, GFP_KERNEL);
	}

	if (ret)
		goto err_out_unlock;

	ret = __sgx_encl_add_page(encl, encl_page, epc_page, secinfo,
				  src);
	if (ret)
		goto err_out;

	/*
	 * Complete the "add" before doing the "extend" so that the "add"
	 * isn't in a half-baked state in the extremely unlikely scenario
	 * the enclave will be destroyed in response to EEXTEND failure.
	 */
	encl_page->encl = encl;
	encl_page->epc_page = epc_page;
	encl_page->type = (secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK) >> 8;
	encl->secs_child_cnt++;

	if (flags & SGX_PAGE_MEASURE) {
		ret = __sgx_encl_extend(encl, epc_page);
		if (ret)
			goto err_out;
	}

	//sgx_mark_page_reclaimable(encl_page->epc_page);
	mutex_unlock(&encl->lock);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
	mmap_read_unlock(current->mm);
#else
	up_read(&current->mm->mmap_sem);
#endif
	return ret;

err_out:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0))
	xa_erase(&encl->page_array, PFN_DOWN(encl_page->desc));
	if (secinfo->flags & SGX_SECINFO_TCS)
		xa_erase(&encl->tcs_array, PFN_DOWN(encl_page->desc));
#else
	radix_tree_delete(&encl_page->encl->page_tree,
			  PFN_DOWN(encl_page->desc));
#endif

err_out_unlock:
	//sgx_encl_shrink(encl, va_page);
	encl->page_cnt--;
	mutex_unlock(&encl->lock);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
	mmap_read_unlock(current->mm);
#else
	up_read(&current->mm->mmap_sem);
#endif

//err_out_free:
	sgx_free_epc_page(epc_page);
	kfree(encl_page);

	return ret;
}

/*
 * Ensure user provided offset and length values are valid for
 * an enclave.
 */
static int sgx_validate_offset_length(struct sgx_encl *encl,
				      unsigned long offset,
				      unsigned long length)
{
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return -EINVAL;

	if (!length || !IS_ALIGNED(length, PAGE_SIZE))
		return -EINVAL;

	if (offset + length < offset)
		return -EINVAL;

	if (offset + length - PAGE_SIZE >= encl->size)
		return -EINVAL;

	return 0;
}

/**
 * sgx_ioc_enclave_add_pages() - The handler for %SGX_IOC_ENCLAVE_ADD_PAGES
 * @encl:       an enclave pointer
 * @arg:	a user pointer to a struct sgx_enclave_add_pages instance
 *
 * Add one or more pages to an uninitialized enclave, and optionally extend the
 * measurement with the contents of the page. The SECINFO and measurement mask
 * are applied to all pages.
 *
 * A SECINFO for a TCS is required to always contain zero permissions because
 * CPU silently zeros them. Allowing anything else would cause a mismatch in
 * the measurement.
 *
 * mmap()'s protection bits are capped by the page permissions. For each page
 * address, the maximum protection bits are computed with the following
 * heuristics:
 *
 * 1. A regular page: PROT_R, PROT_W and PROT_X match the SECINFO permissions.
 * 2. A TCS page: PROT_R | PROT_W.
 *
 * mmap() is not allowed to surpass the minimum of the maximum protection bits
 * within the given address range.
 *
 * The function deinitializes kernel data structures for enclave and returns
 * -EIO in any of the following conditions:
 *
 * - Enclave Page Cache (EPC), the physical memory holding enclaves, has
 *   been invalidated. This will cause EADD and EEXTEND to fail.
 * - If the source address is corrupted somehow when executing EADD.
 *
 * Return:
 * - 0:			Success.
 * - -EACCES:		The source page is located in a noexec partition.
 * - -ENOMEM:		Out of EPC pages.
 * - -ERESTARTSYS:	The call was interrupted before data was processed.
 * - -EIO:		Either EADD or EEXTEND failed because invalid source address
 *			or power cycle.
 * - -errno:		POSIX error.
 */
static long sgx_ioc_enclave_add_pages(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_add_pages add_arg;
	
	unsigned long c;
	int ret;

	if (!test_bit(SGX_ENCL_CREATED, &encl->flags) ||
	    test_bit(SGX_ENCL_INITIALIZED, &encl->flags))
		return -EINVAL;

	if (copy_from_user(&add_arg, arg, sizeof(add_arg)))
		return -EFAULT;

	if (!IS_ALIGNED(add_arg.dst, PAGE_SIZE) ||
	    !IS_ALIGNED(add_arg.src, PAGE_SIZE))
		return -EINVAL;

	if (!add_arg.length || add_arg.length & (PAGE_SIZE - 1))
		return -EINVAL;

	add_arg.dst = add_arg.dst + encl->base;
	if (!(((add_arg.dst >= encl->base) && (add_arg.dst + add_arg.length <= encl->base + encl->size))
		|| ((add_arg.dst >= encl->runtime_base) && (add_arg.dst + add_arg.length <= encl->runtime_base + encl->runtime_size))))
		return -EINVAL;
	//if (add_arg.dst + add_arg.length - PAGE_SIZE >= encl->size)
	//	return -EINVAL;

	struct sgx_secinfo *secinfo = kmalloc(sizeof(struct sgx_secinfo), GFP_KERNEL);
	if (copy_from_user(secinfo, (void __user *)add_arg.secinfo,
			   sizeof(struct sgx_secinfo))){
			ret = -EFAULT;
			goto out;
	}

	if (sgx_validate_secinfo(secinfo)) {
		ret = -EINVAL;
		goto out;
	}

	for (c = 0 ; c < add_arg.length; c += PAGE_SIZE) {
		if (signal_pending(current)) {
			if (!c)
				ret = -ERESTARTSYS;

			break;
		}

		if (need_resched())
			cond_resched();
		ret = sgx_encl_add_page(encl, add_arg.src + c, add_arg.dst + c,
					secinfo, add_arg.flags);
		if (ret)
			break;
	}

	add_arg.count = c;

	if (copy_to_user(arg, &add_arg, sizeof(add_arg))) {
		ret = -EFAULT;
	}

out:
	kfree(secinfo);
	return ret;
}

static int __sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus,
			      void *hash)
{
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;

	return crypto_shash_digest(shash, modulus, SGX_MODULUS_SIZE, hash);
}

static int sgx_get_key_hash(const void *modulus, void *hash)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = __sgx_get_key_hash(tfm, modulus, hash);

	crypto_free_shash(tfm);
	return ret;
}

static int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
			 void *token)
{
	u64 mrsigner[4];
	//int i, j;
	u64 addr;
	int ret;

	/*
	 * Deny initializing enclaves with attributes (namely provisioning)
	 * that have not been explicitly allowed.
	 */
	if (encl->attributes & ~encl->attributes_mask)
		return -EACCES;

	/*
	 * Attributes should not be enforced *only* against what's available on
	 * platform (done in sgx_encl_create) but checked and enforced against
	 * the mask for enforcement in sigstruct. For example an enclave could
	 * opt to sign with AVX bit in xfrm, but still be loadable on a platform
	 * without it if the sigstruct->body.attributes_mask does not turn that
	 * bit on.
	 */
	if (sigstruct->body.attributes & sigstruct->body.attributes_mask &
	    sgx_attributes_reserved_mask)
		return -EINVAL;

	if (sigstruct->body.miscselect & sigstruct->body.misc_mask &
	    sgx_misc_reserved_mask)
		return -EINVAL;

	if (sigstruct->body.xfrm & sigstruct->body.xfrm_mask &
	    sgx_xfrm_reserved_mask)
		return -EINVAL;

	ret = sgx_get_key_hash(sigstruct->modulus, mrsigner);
	if (ret)
		return ret;

	mutex_lock(&encl->lock);

	addr = sgx_get_epc_phys_addr(encl->secs.epc_page);
	ret = __einit(virt_to_phys(sigstruct), virt_to_phys(token), addr);

	if (ret) {
		pr_info("EINIT returned %d\n", ret);
		ret = -EPERM;
	} else {
		set_bit(SGX_ENCL_INITIALIZED, &encl->flags);
	}

//err_out:
	mutex_unlock(&encl->lock);
	return ret;
}

/**
 * sgx_ioc_enclave_init() - handler for %SGX_IOC_ENCLAVE_INIT
 * @encl:	an enclave pointer
 * @arg:	userspace pointer to a struct sgx_enclave_init instance
 *
 * Flush any outstanding enqueued EADD operations and perform EINIT.  The
 * Launch Enclave Public Key Hash MSRs are rewritten as necessary to match
 * the enclave's MRSIGNER, which is caculated from the provided sigstruct.
 *
 * Return:
 * - 0:		Success.
 * - -EPERM:	Invalid SIGSTRUCT.
 * - -EIO:	EINIT failed because of a power cycle.
 * - -errno:	POSIX error.
 */
static long sgx_ioc_enclave_init(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_sigstruct *sigstruct;
	struct sgx_enclave_init init_arg;
	struct page *initp_page;
	void *token;
	int ret;

	if (!test_bit(SGX_ENCL_CREATED, &encl->flags) ||
	    test_bit(SGX_ENCL_INITIALIZED, &encl->flags))
		return -EINVAL;

	if (copy_from_user(&init_arg, arg, sizeof(init_arg)))
		return -EFAULT;

	initp_page = alloc_page(GFP_KERNEL);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
	token = (void *)((unsigned long)sigstruct + PAGE_SIZE / 2);
	memset(token, 0, SGX_LAUNCH_TOKEN_SIZE);

	if (copy_from_user(sigstruct, (void __user *)init_arg.sigstruct,
			   sizeof(*sigstruct))) {
		ret = -EFAULT;
		goto out;
	}

	/*
	 * A legacy field used with Intel signed enclaves. These used to mean
	 * regular and architectural enclaves. The CPU only accepts these values
	 * but they do not have any other meaning.
	 *
	 * Thus, reject any other values.
	 */
	if (sigstruct->header.vendor != 0x0000 &&
	    sigstruct->header.vendor != 0x8086) {
		ret = -EINVAL;
		goto out;
	}

	ret = sgx_encl_init(encl, sigstruct, token);

out:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

/**
 * sgx_ioc_enclave_provision() - handler for %SGX_IOC_ENCLAVE_PROVISION
 * @encl:	an enclave pointer
 * @arg:	userspace pointer to a struct sgx_enclave_provision instance
 *
 * Allow ATTRIBUTE.PROVISION_KEY for an enclave by providing a file handle to
 * /dev/sgx_provision.
 *
 * Return:
 * - 0:		Success.
 * - -errno:	Otherwise.
 */
/*
static long sgx_ioc_enclave_provision(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_provision params;
	struct file *file;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	file = fget(params.fd);
	if (!file)
		return -EINVAL;

	if (file->f_op != &sgx_provision_fops) {
		fput(file);
		return -EINVAL;
	}

	encl->attributes_mask |= SGX_ATTR_PROVISIONKEY;

	fput(file);
	return 0;
}
*/

// ETRACK is not necessary in the teevisor, since TLB is flushed by firmware automatically

/**
 * sgx_enclave_restrict_permissions() - Restrict EPCM permissions
 * @encl:	Enclave to which the pages belong.
 * @modp:	Checked parameters from user on which pages need modifying and
 *              their new permissions.
 *
 * Return:
 * - 0:		Success.
 * - -errno:	Otherwise.
 */
static long
sgx_enclave_restrict_permissions(struct sgx_encl *encl,
				 struct sgx_enclave_restrict_permissions *modp)
{
	struct sgx_encl_page *entry;
	struct sgx_secinfo* secinfo;
	unsigned long addr;
	unsigned long c;
	int ret;


	secinfo = kzalloc(sizeof(struct sgx_secinfo), GFP_KERNEL);

	if (!secinfo) {
		return -ENOMEM;
	}

	secinfo->flags = modp->permissions & SGX_SECINFO_PERMISSION_MASK;

	for (c = 0 ; c < modp->length; c += PAGE_SIZE) {
		addr = encl->base + modp->offset + c;

		//sgx_reclaim_direct();

		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page(encl, addr);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry) == -EBUSY ? -EAGAIN : -EFAULT;
			goto out_unlock;
		}

		/*
		 * Changing EPCM permissions is only supported on regular
		 * SGX pages. Attempting this change on other pages will
		 * result in #PF.
		 */
		if (entry->type != SGX_PAGE_TYPE_REG) {
			ret = -EINVAL;
			goto out_unlock;
		}

		/*
		 * Apart from ensuring that read-access remains, do not verify
		 * the permission bits requested. Kernel has no control over
		 * how EPCM permissions can be relaxed from within the enclave.
		 * ENCLS[EMODPR] can only remove existing EPCM permissions,
		 * attempting to set new permissions will be ignored by the
		 * hardware.
		 */

		/* Change EPCM permissions. */
		ret = __emodpr(virt_to_phys(secinfo), sgx_get_epc_phys_addr(entry->epc_page));
		if (encls_faulted(ret)) {
			/*
			 * All possible faults should be avoidable:
			 * parameters have been checked, will only change
			 * permissions of a regular page, and no concurrent
			 * SGX1/SGX2 ENCLS instructions since these
			 * are protected with mutex.
			 */
			pr_err_once("EMODPR encountered exception %d\n",
				    ENCLS_TRAPNR(ret));
			ret = -EFAULT;
			goto out_unlock;
		}
		if (ret) {
			modp->result = ret;
			ret = -EFAULT;
			goto out_unlock;
		}

		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_unlock:
	mutex_unlock(&encl->lock);
out:
	modp->count = c;
	kfree(secinfo);

	return ret;
}

/**
 * sgx_ioc_enclave_restrict_permissions() - handler for
 *                                        %SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS
 * @encl:	an enclave pointer
 * @arg:	userspace pointer to a &struct sgx_enclave_restrict_permissions
 *		instance
 *
 * SGX2 distinguishes between relaxing and restricting the enclave page
 * permissions maintained by the hardware (EPCM permissions) of pages
 * belonging to an initialized enclave (after SGX_IOC_ENCLAVE_INIT).
 *
 * EPCM permissions cannot be restricted from within the enclave, the enclave
 * requires the kernel to run the privileged level 0 instructions ENCLS[EMODPR].
 * An attempt to relax EPCM permissions with this call will be ignored by the hardware.
 *
 * Return:
 * - 0:		Success
 * - -errno:	Otherwise
 */
static long sgx_ioc_enclave_restrict_permissions(struct sgx_encl *encl,
						 void __user *arg)
{
	struct sgx_enclave_restrict_permissions params;
	long ret;

	if (test_bit(SGX_ENCL_RUNTIME, &encl->flags))
		return -EINVAL;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (sgx_validate_offset_length(encl, params.offset, params.length))
		return -EINVAL;

	if (params.permissions & ~SGX_SECINFO_PERMISSION_MASK)
		return -EINVAL;

	/*
	 * Fail early if invalid permissions requested to prevent ENCLS[EMODPR]
	 * from faulting later when the CPU does the same check.
	 */
	if ((params.permissions & SGX_SECINFO_W) &&
	    !(params.permissions & SGX_SECINFO_R))
		return -EINVAL;

	if (params.result || params.count)
		return -EINVAL;

	ret = sgx_enclave_restrict_permissions(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params)))
		return -EFAULT;

	return ret;
}

/**
 * sgx_enclave_modify_types() - Modify type of SGX enclave pages
 * @encl:	Enclave to which the pages belong.
 * @modt:	Checked parameters from user about which pages need modifying
 *              and their new page type.
 *
 * Return:
 * - 0:		Success
 * - -errno:	Otherwise
 */
static long sgx_enclave_modify_types(struct sgx_encl *encl,
				     struct sgx_enclave_modify_types *modt)
{
	unsigned long max_prot_restore;
	enum sgx_page_type page_type;
	struct sgx_encl_page *entry;
	struct sgx_secinfo *secinfo;
	unsigned long prot;
	unsigned long addr;
	unsigned long c;
	u64 epc_phys;
	int ret;

	page_type = modt->page_type & SGX_PAGE_TYPE_MASK;

	/*
	 * The only new page types allowed by hardware are PT_TCS and PT_TRIM.
	 */
	if (page_type != SGX_PAGE_TYPE_TCS && page_type != SGX_PAGE_TYPE_TRIM)
		return -EINVAL;

	secinfo = kzalloc(sizeof(struct sgx_secinfo), GFP_KERNEL);

	if (!secinfo) {
		return -ENOMEM;
	}

	secinfo->flags = page_type << 8;

	for (c = 0 ; c < modt->length; c += PAGE_SIZE) {
		addr = encl->base + modt->offset + c;

		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page(encl, addr);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry) == -EBUSY ? -EAGAIN : -EFAULT;
			goto out_unlock;
		}

		/*
		 * Borrow the logic from the Intel SDM. Regular pages
		 * (SGX_PAGE_TYPE_REG) can change type to SGX_PAGE_TYPE_TCS
		 * or SGX_PAGE_TYPE_TRIM but TCS pages can only be trimmed.
		 * CET pages not supported yet.
		 */
		if (!(entry->type == SGX_PAGE_TYPE_REG ||
		      (entry->type == SGX_PAGE_TYPE_TCS &&
		       page_type == SGX_PAGE_TYPE_TRIM))) {
			ret = -EINVAL;
			goto out_unlock;
		}

		max_prot_restore = entry->vm_max_prot_bits;

		/*
		 * Once a regular page becomes a TCS page it cannot be
		 * changed back. So the maximum allowed protection reflects
		 * the TCS page that is always RW from kernel perspective but
		 * will be inaccessible from within enclave. Before doing
		 * so, do make sure that the new page type continues to
		 * respect the originally vetted page permissions.
		 */
		if (entry->type == SGX_PAGE_TYPE_REG &&
		    page_type == SGX_PAGE_TYPE_TCS) {
			if (~entry->vm_max_prot_bits & (VM_READ | VM_WRITE)) {
				ret = -EPERM;
				goto out_unlock;
			}
			prot = PROT_READ | PROT_WRITE;
			entry->vm_max_prot_bits = calc_vm_prot_bits(prot, 0);

			/*
			 * Prevent page from being reclaimed while mutex
			 * is released.
			 */
			/*
			if (sgx_unmark_page_reclaimable(entry->epc_page)) {
				ret = -EAGAIN;
				goto out_entry_changed;
			}
			*/

			/*
			 * Do not keep encl->lock because of dependency on
			 * mmap_lock acquired in sgx_zap_enclave_ptes().
			 */
			/*
			mutex_unlock(&encl->lock);

			sgx_zap_enclave_ptes(encl, addr);
			
			mutex_lock(&encl->lock);

			sgx_mark_page_reclaimable(entry->epc_page);
			*/
		}

		/* Change EPC type */
		epc_phys = sgx_get_epc_phys_addr(entry->epc_page);
		ret = __emodt(virt_to_phys(secinfo), epc_phys);
		if (encls_faulted(ret)) {
			/*
			 * All possible faults should be avoidable:
			 * parameters have been checked, will only change
			 * valid page types, and no concurrent
			 * SGX1/SGX2 ENCLS instructions since these are
			 * protected with mutex.
			 */
			pr_err_once("EMODT encountered exception %d\n",
				    ENCLS_TRAPNR(ret));
			ret = -EFAULT;
			goto out_entry_changed;
		}
		if (ret) {
			modt->result = ret;
			ret = -EFAULT;
			goto out_entry_changed;
		}

		entry->type = page_type;

		if (page_type == SGX_PAGE_TYPE_TCS) {
			ret = xa_insert(&encl->tcs_array, PFN_DOWN(entry->desc),
			entry, GFP_KERNEL);
		}

		if (ret) {
			// xa_insert failed just return the error of xa_insert
			goto out_entry_changed;
		}
		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_entry_changed:
	entry->vm_max_prot_bits = max_prot_restore;
out_unlock:
	mutex_unlock(&encl->lock);
out:
	modt->count = c;
	kfree(secinfo);
	
	return ret;
}

/**
 * sgx_ioc_enclave_modify_types() - handler for %SGX_IOC_ENCLAVE_MODIFY_TYPES
 * @encl:	an enclave pointer
 * @arg:	userspace pointer to a &struct sgx_enclave_modify_types instance
 *
 * Ability to change the enclave page type supports the following use cases:
 *
 * * It is possible to add TCS pages to an enclave by changing the type of
 *   regular pages (%SGX_PAGE_TYPE_REG) to TCS (%SGX_PAGE_TYPE_TCS) pages.
 *   With this support the number of threads supported by an initialized
 *   enclave can be increased dynamically.
 *
 * * Regular or TCS pages can dynamically be removed from an initialized
 *   enclave by changing the page type to %SGX_PAGE_TYPE_TRIM. Changing the
 *   page type to %SGX_PAGE_TYPE_TRIM marks the page for removal with actual
 *   removal done by handler of %SGX_IOC_ENCLAVE_REMOVE_PAGES ioctl() called
 *   after ENCLU[EACCEPT] is run on %SGX_PAGE_TYPE_TRIM page from within the
 *   enclave.
 *
 * Return:
 * - 0:		Success
 * - -errno:	Otherwise
 */
static long sgx_ioc_enclave_modify_types(struct sgx_encl *encl,
					 void __user *arg)
{
	struct sgx_enclave_modify_types params;
	long ret;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (sgx_validate_offset_length(encl, params.offset, params.length))
		return -EINVAL;

	if (params.page_type & ~SGX_PAGE_TYPE_MASK)
		return -EINVAL;

	if (params.result || params.count)
		return -EINVAL;

	ret = sgx_enclave_modify_types(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params)))
		return -EFAULT;

	return ret;
}

/**
 * sgx_encl_remove_pages() - Remove trimmed pages from SGX enclave
 * @encl:	Enclave to which the pages belong
 * @params:	Checked parameters from user on which pages need to be removed
 *
 * Return:
 * - 0:		Success.
 * - -errno:	Otherwise.
 */
static long sgx_encl_remove_pages(struct sgx_encl *encl,
				  struct sgx_enclave_remove_pages *params)
{
	struct sgx_encl_page *entry;
	struct sgx_secinfo* secinfo;
	unsigned long addr;
	unsigned long c;
	u64 epc_phys;
	int ret;

	secinfo = kzalloc(sizeof(struct sgx_secinfo), GFP_KERNEL);
	if (!secinfo) {
		return -ENOMEM;
	}

	secinfo->flags = SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X;

	for (c = 0 ; c < params->length; c += PAGE_SIZE) {
		addr = encl->base + params->offset + c;

		//sgx_reclaim_direct();

		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page(encl, addr);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry) == -EBUSY ? -EAGAIN : -EFAULT;
			goto out_unlock;
		}

		if (entry->type != SGX_PAGE_TYPE_TRIM) {
			ret = -EPERM;
			goto out_unlock;
		}

		/*
		 * ENCLS[EMODPR] is a no-op instruction used to inform if
		 * ENCLU[EACCEPT] was run from within the enclave. If
		 * ENCLS[EMODPR] is run with RWX on a trimmed page that is
		 * not yet accepted then it will return
		 * %SGX_PAGE_NOT_MODIFIABLE, after the trimmed page is
		 * accepted the instruction will encounter a page fault.
		 */
		epc_phys = sgx_get_epc_phys_addr(entry->epc_page);
		ret = __emodpr(virt_to_phys(secinfo), epc_phys);
		if (!encls_faulted(ret) || ENCLS_TRAPNR(ret) != X86_TRAP_PF) {
			ret = -EPERM;
			goto out_unlock;
		}

		/*
		if (sgx_unmark_page_reclaimable(entry->epc_page)) {
			ret = -EBUSY;
			goto out_unlock;
		}
		*/

		/*
		 * Do not keep encl->lock because of dependency on
		 * mmap_lock acquired in sgx_zap_enclave_ptes().
		 */
		/*
		mutex_unlock(&encl->lock);

		sgx_zap_enclave_ptes(encl, addr);

		mutex_lock(&encl->lock);
		*/

		sgx_free_epc_page(entry->epc_page);
		encl->secs_child_cnt--;
		entry->epc_page = NULL;
		xa_erase(&encl->page_array, PFN_DOWN(entry->desc));
		//sgx_encl_shrink(encl, NULL);
		kfree(entry);

		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_unlock:
	mutex_unlock(&encl->lock);
out:
	params->count = c;
	kfree(secinfo);

	return ret;
}

/**
 * sgx_ioc_enclave_remove_pages() - handler for %SGX_IOC_ENCLAVE_REMOVE_PAGES
 * @encl:	an enclave pointer
 * @arg:	userspace pointer to &struct sgx_enclave_remove_pages instance
 *
 * Final step of the flow removing pages from an initialized enclave. The
 * complete flow is:
 *
 * 1) User changes the type of the pages to be removed to %SGX_PAGE_TYPE_TRIM
 *    using the %SGX_IOC_ENCLAVE_MODIFY_TYPES ioctl().
 * 2) User approves the page removal by running ENCLU[EACCEPT] from within
 *    the enclave.
 * 3) User initiates actual page removal using the
 *    %SGX_IOC_ENCLAVE_REMOVE_PAGES ioctl() that is handled here.
 *
 * First remove any page table entries pointing to the page and then proceed
 * with the actual removal of the enclave page and data in support of it.
 *
 *
 * Return:
 * - 0:		Success
 * - -errno:	Otherwise
 */
static long sgx_ioc_enclave_remove_pages(struct sgx_encl *encl,
					 void __user *arg)
{
	struct sgx_enclave_remove_pages params;
	long ret;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (sgx_validate_offset_length(encl, params.offset, params.length))
		return -EINVAL;

	if (params.count)
		return -EINVAL;

	ret = sgx_encl_remove_pages(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params)))
		return -EFAULT;

	return ret;
}

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct sgx_encl *encl = filep->private_data;
	int ret;

	if (test_and_set_bit(SGX_ENCL_IOCTL, &encl->flags))
		return -EBUSY;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		ret = sgx_ioc_enclave_create(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGES:
		ret = sgx_ioc_enclave_add_pages(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_INIT:
		ret = sgx_ioc_enclave_init(encl, (void __user *)arg);
		break;
	//case SGX_IOC_ENCLAVE_PROVISION:
	//	ret = sgx_ioc_enclave_provision(encl, (void __user *)arg);
	//	break;
	case SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS:
		ret = sgx_ioc_enclave_restrict_permissions(encl,
							   (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_MODIFY_TYPES:
		ret = sgx_ioc_enclave_modify_types(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_REMOVE_PAGES:
		ret = sgx_ioc_enclave_remove_pages(encl, (void __user *)arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	clear_bit(SGX_ENCL_IOCTL, &encl->flags);
	return ret;
}
