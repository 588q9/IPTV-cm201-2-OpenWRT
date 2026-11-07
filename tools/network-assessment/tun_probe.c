#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main(void) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    unsigned int features = 0;
    struct ifreq req;
    if (fd < 0) { perror("open tun"); return 1; }
    if (ioctl(fd, TUNGETFEATURES, &features) < 0) { perror("TUNGETFEATURES"); close(fd); return 2; }
    printf("TUN_FEATURES=0x%x\n", features);
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, "tsprobe0");
    req.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
    if (ioctl(fd, TUNSETIFF, &req) < 0) { perror("TUNSETIFF"); close(fd); return 3; }
    printf("CREATED=%s flags=0x%x\n", req.ifr_name, req.ifr_flags);
    if (ioctl(fd, TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6) < 0)
        perror("OPTIONAL_TUNSETOFFLOAD");
    else puts("TUN_CSUM_TSO4_TSO6=OK");
    close(fd);
    puts("CLOSED_NONPERSISTENT_TUN");
    return 0;
}
