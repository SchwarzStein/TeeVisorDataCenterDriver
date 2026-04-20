// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*  Copyright(c) 2016-21 Intel Corporation. */

#include <linux/acpi.h>
#include <linux/miscdevice.h>
#include <linux/mman.h>
#include <linux/security.h>
#include <linux/suspend.h>
#include <asm/traps.h>
#include "driver.h"
#include "encl.h"
#include "dcap.h"

#include "version.h"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Yiliang Dong <dongyiliangsteven@163.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

u64 sgx_attributes_reserved_mask = SGX_ATTR_RESERVED_MASK;
u64 sgx_xfrm_reserved_mask = ~0x3;
u32 sgx_misc_reserved_mask;

static int sgx_open(struct inode *inode, struct file *file)
{
	struct sgx_encl *encl;
	struct xarray *enclave_array;
	int ret;

	enclave_array = kzalloc(sizeof(struct xarray), GFP_KERNEL);
	if (!enclave_array) {
		return -ENOMEM;
	}

	xa_init(enclave_array);
	encl = kzalloc(sizeof(*encl), GFP_KERNEL);
	if (!encl) {
		ret = -ENOMEM;
		goto free_enclave_array;
	}
		

	kref_init(&encl->refcount);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	xa_init(&encl->page_array);
	xa_init(&encl->mm_sync_array);
	xa_init(&encl->tcs_array);
	xa_init(&encl->eaug_retry_array);
#else
	INIT_RADIX_TREE(&encl->page_tree, GFP_KERNEL);
#endif
	mutex_init(&encl->lock);
	mutex_init(&encl->sync_lock);
	//INIT_LIST_HEAD(&encl->va_pages);
	INIT_LIST_HEAD(&encl->mm_list);
	spin_lock_init(&encl->mm_lock);

	ret = init_srcu_struct(&encl->srcu);
	if (ret) 
		goto free_encl;

	encl->enclave_array = enclave_array;
	ret = xa_insert(enclave_array, (unsigned long)current->mm, encl, GFP_KERNEL);
	if (ret) 
		goto free_encl;

	file->private_data = enclave_array;
	pr_info("sgx_open finished\n");
	return 0;


free_encl:
	kfree(encl);
free_enclave_array:
	kfree(enclave_array);
	return ret;
}

static int sgx_release(struct inode *inode, struct file *file)
{
	struct sgx_encl *encl;
	unsigned long index, size_pages;
	struct enclave_cache_block_entry *block_entry;
	
	rcu_read_lock();
	if (xa_empty(file->private_data)) {
		kfree(file->private_data);
	} else {
		xa_for_each(file->private_data, index, encl) {
			// If the device is opened and closed directly without mmap,
			// the previously created enclave instance need to be released
			if (kref_put(&encl->refcount, sgx_encl_release)) {
			} else
			{
				pr_err("enclave with mm 0x%lx not released before fd released!", index);
				pr_err("encl array leaked\n");
			}
			
		}
	}

	xa_for_each(&cache_block_array, index, block_entry) {
		if (!atomic_long_read_acquire(&block_entry->counter) && atomic_long_read_acquire(&block_entry->consumed)) {
			//pr_info("Release free block\n");
			size_pages = (block_entry->end - block_entry->start + PAGE_SIZE) >> PAGE_SHIFT;
			free_pages((unsigned long)phys_to_virt(block_entry->start), fls(size_pages) - 1);
			kfree(block_entry);
			xa_erase(&cache_block_array, index);
		}
	}
	rcu_read_unlock();
	pr_info("device closed\n");
	return 0;
}

static int sgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sgx_encl *encl;
	int ret;
	encl = xa_load(file->private_data, (unsigned long)vma->vm_mm);

	if (!encl) {
		pr_err("Cannot load enclave instance, do not create an enclave in a forked thread with parent device fd, please reopen the device!\n");
		return -ENODEV;
	}

	ret = sgx_encl_may_map(encl, vma->vm_start, vma->vm_end, vma->vm_flags);
	if (ret)
		return ret;

	ret = sgx_encl_mm_add(encl, vma->vm_mm);
	if (ret)
		return ret;

	vma->vm_ops = &sgx_vm_ops;
	vm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO);
	vma->vm_private_data = file->private_data;

	kref_get(&encl->refcount);
	return 0;
}

static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if ((flags & MAP_TYPE) == MAP_PRIVATE)
		return -EINVAL;

	if (flags & MAP_FIXED)
		return addr;

	return mm_get_unmapped_area(current->mm, file, addr, len, pgoff, flags);
}

#ifdef CONFIG_COMPAT
static long sgx_compat_ioctl(struct file *filep, unsigned int cmd,
			      unsigned long arg)
{
	return sgx_ioctl(filep, cmd, arg);
}
#endif

static const struct file_operations sgx_encl_fops = {
	.owner			= THIS_MODULE,
	.open			= sgx_open,
	.release		= sgx_release,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

/*
const struct file_operations sgx_provision_fops = {
	.owner			= THIS_MODULE,
};
*/

static struct miscdevice sgx_dev_enclave = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sgx_enclave",
	.nodename = "sgx_enclave",
	.fops = &sgx_encl_fops,
	.mode = 0666,
};

/*
static struct miscdevice sgx_dev_provision = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sgx_provision",
	.nodename = "sgx_provision",
	.fops = &sgx_provision_fops,
};
*/

int __init sgx_drv_init(void)
{	
	/*
	unsigned int eax, ebx, ecx, edx;
	u64 attr_mask;
	u64 xfrm_mask;
	int ret;

	
	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		pr_info("The public key MSRs are not writable.\n");
		return -ENODEV;
	}
	*/

	/*
	cpuid_count(SGX_CPUID, 0, &eax, &ebx, &ecx, &edx);

	if (!(eax & 1))  {
		pr_err("SGX disabled: SGX1 instruction support not available.\n");
		return -ENODEV;
	}

	sgx_misc_reserved_mask = ~ebx | SGX_MISC_RESERVED_MASK;

	cpuid_count(SGX_CPUID, 1, &eax, &ebx, &ecx, &edx);

	attr_mask = (((u64)ebx) << 32) + (u64)eax;
	sgx_attributes_reserved_mask = ~attr_mask | SGX_ATTR_RESERVED_MASK;
	*/
	sgx_misc_reserved_mask = SGX_MISC_RESERVED_MASK;
	if (boot_cpu_has(X86_FEATURE_OSXSAVE) && boot_cpu_has(X86_FEATURE_AVX)) {
		sgx_xfrm_reserved_mask = ~0x7;
	}

	int ret = misc_register(&sgx_dev_enclave);
	if (ret) {
		pr_err("Creating /dev/sgx_enclave failed with %d.\n", ret);
		return ret;
	}

	/*
	ret = misc_register(&sgx_dev_provision);
	if (ret) {
		pr_err("Creating /dev/sgx_provision failed with %d.\n", ret);
		misc_deregister(&sgx_dev_enclave);
		return ret;
	}
	*/

	return 0;
}

int __exit sgx_drv_exit(void)
{
	misc_deregister(&sgx_dev_enclave);
	//misc_deregister(&sgx_dev_provision);

	return 0;
}

#ifdef CONFIG_ACPI
static struct acpi_device_id sgx_device_ids[] = {
	{"INT0E0C", 0},
	{"", 0},
};
MODULE_DEVICE_TABLE(acpi, sgx_device_ids);
#endif
