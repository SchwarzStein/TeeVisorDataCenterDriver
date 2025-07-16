#define SHELLCODE_EXIT {\
        0xb8, 0x04, 0x00, 0x00, 0x00,       \
        0xbb, 0x00, 0x00, 0x00, 0x00,       \
        0x0f, 0x01, 0xd7                    \
    };

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "sgx_arch.h"
#include "../linux/include/sgx_user.h"

int main(void) {
    const char *dev_path = "/dev/teevisor";

    int fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("Failed to open /dev/teevisor");
        return 1;
    }

    void * ptr = mmap(0 , 0x200000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED_NOREPLACE | MAP_SHARED, fd, 0);

    if (ptr != 0) {
        perror("Failed to map fd to 0");
        return 2;
    }
    
    sgx_arch_secs_t *secs = aligned_alloc(0x1000, 0x1000);
    memset(secs, 0, 0x1000);
    secs->base = 0;
    secs->size = 0x200000;
    secs->ssa_frame_size = 3;
    secs->misc_select = SGX_MISCSELECT_EXINFO;
    secs->attributes.flags = SGX_FLAGS_MODE64BIT;
    secs->attributes.xfrm = SGX_XFRM_LEGACY;

    struct sgx_enclave_create create_param = {
        .src = (uint64_t)secs,
    };

    int ret = ioctl(fd, SGX_IOC_ENCLAVE_CREATE, &create_param);
        
    if (ret) {
        perror("Failed to create enclave");
        return -ret;
    }

    free(secs);

    void * added_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t shellcode_eexit[] = SHELLCODE_EXIT;
    memcpy(added_page, shellcode_eexit, sizeof(shellcode_eexit));
    sgx_arch_sec_info_t secinfo = { 0 };
    secinfo.flags = SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT
                            | SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_X;
    struct sgx_enclave_add_pages add_param = {
        .dst  = (uint64_t)0,
        .src     = (uint64_t)added_page,
        .length  = 0x1000,
        .secinfo = (uint64_t)&secinfo,
        .flags   = SGX_PAGE_MEASURE,
        .count   = 0, /* output parameter, will be checked after IOCTL */
    };

    while (add_param.length > 0) {
        ret = ioctl(fd, SGX_IOC_ENCLAVE_ADD_PAGES, &add_param);
        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            perror("Enclave add-pages IOCTL failed");
            return ret;
        }

        uint64_t added_size = ret > 0 ? (uint64_t)ret : add_param.count;
        if (!added_size) {
            perror("Intel SGX driver did not perform EADD. This may indicate a buggy "
                      "driver, please update to the most recent version.");
            return -EPERM;
        }

        add_param.dst += added_size;
        add_param.src += added_size;
        add_param.length -= added_size;
    }

    close(fd);
    return 0;
}
