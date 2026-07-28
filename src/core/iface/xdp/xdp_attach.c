#include "../../../../inc/core/xdp_attach.h"
#include "../../../../inc/core/xdp_validate.h"
#include "../../../../inc/core/interface.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void xdp_link_off(const char *ifname)
{
    char cmd[160];
    static const char *const modes[] = { "xdp", "xdpgeneric", "xdpoffload" };

    if (!ne_xdp_ifname_valid(ifname))
        return;
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        snprintf(cmd, sizeof(cmd), "/sbin/ip link set dev %s %s off", ifname, modes[i]);
        if (system(cmd) != 0)
            fprintf(stderr, "[XDP-ATTACH] warning: failed to run: %s\n", cmd);
    }
}

void ne_xdp_attach_detach_ifname(const char *ifname)
{
    if (!ifname || !ifname[0])
        return;
    xdp_link_off(ifname);
}

void ne_xdp_attach_detach_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        ne_xdp_attach_detach_ifname(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        ne_xdp_attach_detach_ifname(cfg->wans[i].ifname);
}

void ne_xdp_attach_detach_local(struct ne_pair *p, int pair_li)
{
    if (!p || pair_li < 0 || pair_li >= MAX_INTERFACES)
        return;
    if (!p->xdp_local_on[pair_li] && !p->bpf_locals[pair_li])
        return;

    fprintf(stderr, "[XDP-ATTACH] DETACH LAN %s (slot %d)\n",
            p->locals[pair_li].ifname, pair_li);
    fflush(stderr);
    xdp_link_off(p->locals[pair_li].ifname);
    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
    }
    p->xdp_local_on[pair_li] = 0;
}

void ne_xdp_attach_detach_wan(struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= MAX_INTERFACES)
        return;
    if (!p->xdp_wan_on[dp_slot] && !p->bpf_wans[dp_slot])
        return;

    fprintf(stderr, "[XDP-ATTACH] DETACH WAN %s (dp slot %d)\n",
            p->wans[dp_slot].ifname, dp_slot);
    fflush(stderr);
    xdp_link_off(p->wans[dp_slot].ifname);
    if (p->bpf_wans[dp_slot]) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
    }
    p->xdp_wan_on[dp_slot] = 0;
}

void ne_xdp_attach_prepare_init(const struct app_config *cfg)
{
    if (!cfg)
        return;
    fprintf(stderr, "[XDP-ATTACH] prepare: detach xdp on configured LAN/WAN\n");
    fflush(stderr);
    ne_xdp_attach_detach_config(cfg);
    interface_reset_redirect_maps();
}

static int iface_ifindex(const char *ifname, const char *role)
{
    unsigned int idx;

    if (!ifname || !ifname[0]) {
        fprintf(stderr, "[XDP-ATTACH] %s: missing interface name\n", role);
        return -1;
    }
    idx = if_nametoindex(ifname);
    if (idx == 0) {
        fprintf(stderr, "[XDP-ATTACH] %s %s: interface not found\n", role, ifname);
        return -1;
    }
    return (int)idx;
}

static int xdp_attach_prog(int ifindex, int prog_fd, uint32_t flags,
                           const char *ifname, const char *role)
{
    uint32_t mode = flags ? flags : XDP_FLAGS_DRV_MODE;
    int rc = bpf_xdp_attach(ifindex, prog_fd, mode, NULL);

    if (rc) {
        fprintf(stderr, "[XDP-ATTACH] attach failed %s %s mode=0x%x: %s\n",
                role, ifname, mode, strerror(rc < 0 ? -rc : rc));
        fflush(stderr);
        return -1;
    }
    fprintf(stderr, "[XDP-ATTACH] attach OK %s %s (mode=0x%x)\n", role, ifname, mode);
    fflush(stderr);
    return 0;
}

static const char *resolve_bpf_object_path(const char *path, char resolved[PATH_MAX])
{
    char exe_path[PATH_MAX];
    ssize_t n;
    char *slash;

    if (!path || path[0] == '/' || access(path, R_OK) == 0)
        return path;

    n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n <= 0)
        return path;
    exe_path[n] = '\0';

    slash = strrchr(exe_path, '/');
    if (!slash)
        return path;
    *slash = '\0';

    if (snprintf(resolved, PATH_MAX, "%s/%s", exe_path, path) >= PATH_MAX)
        return path;
    return resolved;
}

static int open_bpf_object(const char *path, struct bpf_object **obj_out,
                           const char *prog_name, struct bpf_program **prog_out,
                           const char *map_name, struct bpf_map **map_out)
{
    char resolved_path[PATH_MAX];
    const char *open_path;
    struct bpf_object *obj;

    open_path = resolve_bpf_object_path(path, resolved_path);

    obj = bpf_object__open_file(open_path, NULL);

    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[XDP-ATTACH] bpf open failed: %s\n", open_path);
        return -1;
    }
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "[XDP-ATTACH] bpf load failed: %s\n", open_path);
        bpf_object__close(obj);
        return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[XDP-ATTACH] bpf object %s missing prog/map\n", open_path);
        bpf_object__close(obj);
        return -1;
    }
    *obj_out = obj;
    *prog_out = prog;
    *map_out = map;
    return 0;
}

static int update_xsk_map_queue(struct xsk_socket *xsk, int map_fd, int queue_id)
{
    int key = queue_id;
    int fd = xsk_socket__fd(xsk);

    if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
        return 0;
    return bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY);
}

static int update_xsk_map_iface(struct ne_iface *iface, int map_fd)
{
    for (int q = 0; q < iface->queue_count; q++) {
        if (!iface->queues[q].xsk)
            return -1;
        if (update_xsk_map_queue(iface->queues[q].xsk, map_fd, q) != 0)
            return -1;
    }
    return 0;
}

static void update_wan_fake_ethertype(struct bpf_object *obj, uint16_t fake_ethertype_ipv4)
{
    if (!obj || fake_ethertype_ipv4 == 0)
        return;
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "wan_config_map");
    if (!map)
        return;
    int key = 0;
    (void)bpf_map_update_elem(bpf_map__fd(map), &key, &fake_ethertype_ipv4, BPF_ANY);
}

int ne_xdp_attach_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    const char *ifname;

    if (!p || !cfg || pair_li < 0 || pair_li >= p->local_count)
        return -1;

    ifname = p->locals[pair_li].ifname;
    if (iface_ifindex(ifname, "LAN") < 0)
        return -1;

    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        p->xdp_local_on[pair_li] = 0;
    }

    if (open_bpf_object(cfg->bpf_file, &p->bpf_locals[pair_li],
                        "xdp_redirect_prog", &prog, "xsks_map", &map) != 0)
        return -1;
    xdp_link_off(ifname);
    if (xdp_attach_prog(p->locals[pair_li].ifindex, bpf_program__fd(prog),
                        p->locals[pair_li].xdp_flags ? p->locals[pair_li].xdp_flags
                                                     : p->xdp_flags,
                        ifname, "LAN") != 0) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        return -1;
    }
    p->xdp_local_on[pair_li] = 1;
    return update_xsk_map_iface(&p->locals[pair_li], bpf_map__fd(map));
}

int ne_xdp_attach_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                           uint16_t fake_ethertype_ipv4)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;

    if (!p || !cfg || dp_slot < 0 || dp_slot >= p->wan_count)
        return -1;
    if (iface_ifindex(p->wans[dp_slot].ifname, "WAN") < 0)
        return -1;
    if (open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[dp_slot],
                        "xdp_wan_redirect_prog", &prog, "wan_xsks_map", &map) != 0)
        return -1;
    update_wan_fake_ethertype(p->bpf_wans[dp_slot], fake_ethertype_ipv4);
    xdp_link_off(p->wans[dp_slot].ifname);
    if (xdp_attach_prog(p->wans[dp_slot].ifindex, bpf_program__fd(prog),
                        p->wans[dp_slot].xdp_flags ? p->wans[dp_slot].xdp_flags
                                                   : p->xdp_flags,
                        p->wans[dp_slot].ifname, "WAN") != 0) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
        return -1;
    }
    p->xdp_wan_on[dp_slot] = 1;
    return update_xsk_map_iface(&p->wans[dp_slot], bpf_map__fd(map));
}

int ne_xdp_attach_attach_init(struct ne_pair *p, const struct app_config *cfg)
{
    if (!p || !cfg)
        return -1;

    fprintf(stderr, "[XDP-ATTACH] cold attach: %d LAN, %d WAN(dp)\n",
            p->local_count, p->wan_count);
    fflush(stderr);

    for (int i = 0; i < p->local_count; i++) {
        if (ne_xdp_attach_bind_local(p, cfg, i) != 0) {
            fprintf(stderr, "[XDP-ATTACH] cold attach failed LAN %s (slot %d)\n",
                    p->locals[i].ifname, i);
            fflush(stderr);
            return -1;
        }
    }
    for (int di = 0; di < p->wan_count; di++) {
        if (ne_xdp_attach_bind_wan(p, cfg, di, cfg->fake_ethertype_ipv4) != 0) {
            fprintf(stderr, "[XDP-ATTACH] cold attach failed WAN %s (dp %d)\n",
                    p->wans[di].ifname, di);
            fflush(stderr);
            return -1;
        }
    }
    return 0;
}
