#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
    const char *dev_path = "/dev/teevisor";

    int fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/teevisor");
        return 1;
    }
    
    
    printf("Successfully opened %s with fd = %d\n", dev_path, fd);
    close(fd);
    return 0;
}
