#include "../../../../inc/core/xdp_validate.h"

#include <ctype.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int ne_xdp_ifname_valid(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *)ifname; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

int ne_xdp_iface_kernel_exists(const char *ifname)
{
    if (!ne_xdp_ifname_valid(ifname))
        return 0;
    return if_nametoindex(ifname) != 0;
}

int ne_xdp_iface_kernel_up(const char *ifname)
{
    int fd;
    struct ifreq ifr;

    if (!ne_xdp_ifname_valid(ifname))
        return 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return (ifr.ifr_flags & IFF_UP) != 0;
}

int ne_xdp_iface_is_bridge_slave(const char *ifname)
{
    char path[256];

    if (!ne_xdp_ifname_valid(ifname))
        return 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s/master", ifname);
    return access(path, F_OK) == 0;
}

static const char *ne_xdp_log_tag(const char *log_tag)
{
    if (log_tag && log_tag[0])
        return log_tag;
    return "XDP";
}

int ne_xdp_iface_preflight(const char *ifname, const char *log_tag)
{
    const char *tag = ne_xdp_log_tag(log_tag);

    if (!ne_xdp_ifname_valid(ifname)) {
        fprintf(stderr, "[%s] invalid interface name\n", tag);
        fflush(stderr);
        return -1;
    }
    if (!ne_xdp_iface_kernel_exists(ifname)) {
        fprintf(stderr,
                "[%s] %s: interface not found in kernel (will not auto-create)\n",
                tag, ifname);
        fflush(stderr);
        return -1;
    }
    if (!ne_xdp_iface_kernel_up(ifname)) {
        fprintf(stderr, "[%s] %s: link is DOWN\n", tag, ifname);
        fflush(stderr);
        return -1;
    }
    if (ne_xdp_iface_is_bridge_slave(ifname)) {
        fprintf(stderr,
                "[%s] %s: bridge-slave (expected for BR topology)\n",
                tag, ifname);
        fflush(stderr);
    }
    return 0;
}
