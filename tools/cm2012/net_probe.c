#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/mii.h>

/* 只读诊断 eth0；不写 PHY、不重启接口。 */
int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    struct ifreq req = {0}; strcpy(req.ifr_name, "eth0");
    struct ethtool_cmd settings = {.cmd=ETHTOOL_GSET};
    req.ifr_data = (void *)&settings;
    if (!ioctl(fd, SIOCETHTOOL, &req))
        printf("speed=%u duplex=%u autoneg=%u phy=%u supported=%08x advertising=%08x\n",
               ethtool_cmd_speed(&settings), settings.duplex, settings.autoneg,
               settings.phy_address, settings.supported, settings.advertising);
    else perror("ETHTOOL_GSET");
    struct ethtool_value link = {.cmd=ETHTOOL_GLINK}; req.ifr_data=(void *)&link;
    if (!ioctl(fd, SIOCETHTOOL, &req)) printf("link=%u\n", link.data);
    else perror("ETHTOOL_GLINK");
    struct mii_ioctl_data *mii = (void *)&req.ifr_ifru;
    if (!ioctl(fd, SIOCGMIIPHY, &req)) {
        printf("mii_phy=%u\n", mii->phy_id);
        for (int i=0; i<7; ++i) {
            mii->reg_num=i;
            if (!ioctl(fd, SIOCGMIIREG, &req)) printf("reg%d=%04x\n", i, mii->val_out);
            else perror("SIOCGMIIREG");
        }
    } else perror("SIOCGMIIPHY");
    close(fd); return 0;
}
