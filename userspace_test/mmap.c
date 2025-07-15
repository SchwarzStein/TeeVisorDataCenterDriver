#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

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
    
    printf("fd is mapped to 0x0 - 0x200000");
    close(fd);
    return 0;
}
