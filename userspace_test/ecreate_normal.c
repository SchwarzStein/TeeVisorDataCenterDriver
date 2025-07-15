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

    struct sgx_enclave_create param = {
        .src = (uint64_t)secs,
    };

    int ret = ioctl(fd, SGX_IOC_ENCLAVE_CREATE, &param);
        
    if (ret) {
        perror("Failed to create enclave");
        return -ret;
    }

    free(secs);
    close(fd);
    return 0;
}
