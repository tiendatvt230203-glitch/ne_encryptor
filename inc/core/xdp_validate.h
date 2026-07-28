#ifndef XDP_VALIDATE_H
#define XDP_VALIDATE_H

int ne_xdp_ifname_valid(const char *ifname);

int ne_xdp_iface_kernel_exists(const char *ifname);

int ne_xdp_iface_kernel_up(const char *ifname);

int ne_xdp_iface_is_bridge_slave(const char *ifname);

int ne_xdp_iface_preflight(const char *ifname, const char *log_tag);

#endif
