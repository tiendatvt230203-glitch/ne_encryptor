#include "../../inc/core/profile_iface_xdp.h"

#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/interface.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int profile_iface_ifname_safe(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const char *p = ifname; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
            return 0;
    }
    return 1;
}

static void profile_iface_xdp_link_off(const char *ifname)
{
    char cmd[128];

    if (!profile_iface_ifname_safe(ifname))
        return;
    snprintf(cmd, sizeof(cmd), "/sbin/ip link set dev %s xdp off", ifname);
    if (system(cmd) != 0)
        fprintf(stderr, "[PROFILE-XDP] warning: failed to run: %s\n", cmd);
}

void profile_iface_xdp_detach_ifname(const char *ifname)
{
    if (!ifname || !ifname[0])
        return;
    profile_iface_xdp_link_off(ifname);
}

void profile_iface_xdp_detach_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        profile_iface_xdp_detach_ifname(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        profile_iface_xdp_detach_ifname(cfg->wans[i].ifname);
}

void profile_iface_xdp_detach_local(struct ne_pair *p, int pair_li)
{
    if (!p || pair_li < 0 || pair_li >= MAX_INTERFACES)
        return;
    if (!p->xdp_local_on[pair_li] && !p->bpf_locals[pair_li])
        return;

    fprintf(stderr, "[PROFILE-XDP] DETACH LAN %s (slot %d)\n",
            p->locals[pair_li].ifname, pair_li);
    fflush(stderr);
    profile_iface_xdp_link_off(p->locals[pair_li].ifname);
    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
    }
    p->xdp_local_on[pair_li] = 0;
}

void profile_iface_xdp_detach_wan(struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= MAX_INTERFACES)
        return;
    if (!p->xdp_wan_on[dp_slot] && !p->bpf_wans[dp_slot])
        return;

    fprintf(stderr, "[PROFILE-XDP] DETACH WAN %s (dp slot %d)\n",
            p->wans[dp_slot].ifname, dp_slot);
    fflush(stderr);
    profile_iface_xdp_link_off(p->wans[dp_slot].ifname);
    if (p->bpf_wans[dp_slot]) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
    }
    p->xdp_wan_on[dp_slot] = 0;
}

void profile_iface_xdp_prepare_init(const struct app_config *cfg)
{
    if (!cfg)
        return;
    fprintf(stderr, "[PROFILE-XDP] prepare: detach xdp on configured LAN/WAN\n");
    fflush(stderr);
    profile_iface_xdp_detach_config(cfg);
    interface_reset_redirect_maps();
}

static int cfg_has_wan_ifname(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

static int cfg_locals_subset(const struct app_config *sub, const struct app_config *sup)
{
    for (int i = 0; i < sub->local_count; i++) {
        if (!config_local_ifname_in_cfg(sup, sub->locals[i].ifname))
            return 0;
    }
    return 1;
}

static int cfg_wans_subset(const struct app_config *sub, const struct app_config *sup)
{
    for (int i = 0; i < sub->wan_count; i++) {
        if (!cfg_has_wan_ifname(sup, sub->wans[i].ifname))
            return 0;
    }
    return 1;
}

static int cfg_has_lan_row_addition(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < new->local_count; i++) {
        if (!config_local_ifname_in_cfg(old, new->locals[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_wan_row_addition(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < new->wan_count; i++) {
        if (!cfg_has_wan_ifname(old, new->wans[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_lan_row_removal(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->local_count; i++) {
        if (!config_local_ifname_in_cfg(new, old->locals[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_wan_row_removal(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->wan_count; i++) {
        if (!cfg_has_wan_ifname(new, old->wans[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_iface_addition(const struct app_config *old, const struct app_config *new)
{
    return cfg_has_lan_row_addition(old, new) || cfg_has_wan_row_addition(old, new);
}

static int cfg_has_iface_removal(const struct app_config *old, const struct app_config *new)
{
    return cfg_has_lan_row_removal(old, new) || cfg_has_wan_row_removal(old, new);
}

static const struct local_config *local_by_ifname(const struct app_config *cfg,
                                                  const char *ifname)
{
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return &cfg->locals[i];
    }
    return NULL;
}

static const struct wan_config *wan_by_ifname(const struct app_config *cfg, const char *ifname)
{
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return &cfg->wans[i];
    }
    return NULL;
}

static const struct profile_config *profile_by_id(const struct app_config *cfg, int profile_id)
{
    if (!cfg || profile_id <= 0)
        return NULL;
    for (int i = 0; i < cfg->profile_count; i++) {
        if (cfg->profiles[i].id == profile_id)
            return &cfg->profiles[i];
    }
    return NULL;
}

static int pair_local_slot_live(const struct forwarder *fwd, const char *ifname)
{
    if (!fwd || !ifname)
        return -1;
    for (int li = 0; li < fwd->pair.local_count; li++) {
        if (!ne_pair_local_live(&fwd->pair, li))
            continue;
        if (strcmp(fwd->pair.locals[li].ifname, ifname) == 0)
            return li;
    }
    return -1;
}

static int pair_wan_dp_slot_live(const struct forwarder *fwd, const char *ifname)
{
    if (!fwd || !ifname)
        return -1;
    for (int di = 0; di < fwd->pair.wan_count; di++) {
        if (!ne_pair_wan_live(&fwd->pair, di))
            continue;
        if (strcmp(fwd->pair.wans[di].ifname, ifname) == 0)
            return di;
    }
    return -1;
}

/* Prefer free slots after delete/edit so ADD reuses holes instead of growing. */
static int fwd_alloc_local_slot(struct forwarder *fwd)
{
    int n;

    if (!fwd)
        return -1;
    n = fwd->pair.local_count;
    for (int i = 0; i < n; i++) {
        if (!ne_pair_local_live(&fwd->pair, i))
            return i;
    }
    if (n < MAX_INTERFACES)
        return n;
    return -1;
}

static int fwd_alloc_wan_slot(struct forwarder *fwd)
{
    int n;

    if (!fwd)
        return -1;
    n = fwd->pair.wan_count;
    for (int i = 0; i < n; i++) {
        if (!ne_pair_wan_live(&fwd->pair, i))
            return i;
    }
    if (n < MAX_INTERFACES)
        return n;
    return -1;
}

static int local_db_equal(const struct local_config *a, const struct local_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0;
}

static int wan_db_equal(const struct wan_config *a, const struct wan_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0 &&
           a->dst_ip == b->dst_ip &&
           a->window_size == b->window_size &&
           a->dataplane == b->dataplane;
}

static int cfg_shared_ifaces_unchanged(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->local_count; i++) {
        const char *ifn = old->locals[i].ifname;
        const struct local_config *nl = local_by_ifname(new, ifn);
        if (nl && !local_db_equal(&old->locals[i], nl))
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        const char *ifn = old->wans[i].ifname;
        const struct wan_config *nw = wan_by_ifname(new, ifn);
        if (nw && !wan_db_equal(&old->wans[i], nw))
            return 0;
    }
    return 1;
}

int profile_iface_xdp_can_add(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new || !old->profile_count)
        return 0;
    if (!cfg_locals_subset(old, new) || !cfg_wans_subset(old, new))
        return 0;
    return cfg_has_iface_addition(old, new);
}

int profile_iface_xdp_can_remove(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new)
        return 0;
    if (!cfg_locals_subset(new, old) || !cfg_wans_subset(new, old))
        return 0;
    return cfg_has_iface_removal(old, new);
}

int profile_iface_xdp_can_delta(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new || !old->profile_count)
        return 0;
    if (!cfg_has_iface_addition(old, new) && !cfg_has_iface_removal(old, new))
        return 0;
    if (!cfg_shared_ifaces_unchanged(old, new))
        return 0;
    return 1;
}

int profile_iface_xdp_is_add_only(const struct app_config *old, const struct app_config *new)
{
    if (!profile_iface_xdp_can_add(old, new))
        return 0;
    return cfg_has_iface_addition(old, new) && !cfg_has_iface_removal(old, new);
}

/* --- BPF / XDP bind --- */

static int profile_iface_ifindex(const char *ifname, const char *role)
{
    unsigned int idx;

    if (!ifname || !ifname[0]) {
        fprintf(stderr, "[PROFILE-XDP] %s: missing interface name\n", role);
        return -1;
    }
    idx = if_nametoindex(ifname);
    if (idx == 0) {
        fprintf(stderr, "[PROFILE-XDP] %s %s: interface not found\n", role, ifname);
        return -1;
    }
    return (int)idx;
}

static int xdp_attach_prog(int ifindex, int prog_fd, uint32_t flags,
                           const char *ifname, const char *role)
{   

    int rc = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);

    if (rc) {
        fprintf(stderr, "[PROFILE-XDP] attach failed %s %s: %s\n",
                role, ifname, strerror(-rc));
        fflush(stderr);
        return -1;
    }
    fprintf(stderr, "[PROFILE-XDP] attach OK %s %s\n", role, ifname);
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
        fprintf(stderr, "[PROFILE-XDP] bpf open failed: %s\n", open_path);
        return -1;
    }
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "[PROFILE-XDP] bpf load failed: %s\n", open_path);
        bpf_object__close(obj);
        return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[PROFILE-XDP] bpf object %s missing prog/map\n", open_path);
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

int profile_iface_xdp_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    const char *ifname;

    if (!p || !cfg || pair_li < 0 || pair_li >= p->local_count)
        return -1;

    ifname = p->locals[pair_li].ifname;
    if (profile_iface_ifindex(ifname, "LAN") < 0)
        return -1;

    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        p->xdp_local_on[pair_li] = 0;
    }

    if (open_bpf_object(cfg->bpf_file, &p->bpf_locals[pair_li],
                        "xdp_redirect_prog", &prog, "xsks_map", &map) != 0)
        return -1;
    profile_iface_xdp_link_off(ifname);
    if (xdp_attach_prog(p->locals[pair_li].ifindex, bpf_program__fd(prog),
                        p->xdp_flags, ifname, "LAN") != 0) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
        return -1;
    }
    p->xdp_local_on[pair_li] = 1;
    return update_xsk_map_iface(&p->locals[pair_li], bpf_map__fd(map));
}

int profile_iface_xdp_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                               uint16_t fake_ethertype_ipv4)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;

    if (!p || !cfg || dp_slot < 0 || dp_slot >= p->wan_count)
        return -1;
    if (profile_iface_ifindex(p->wans[dp_slot].ifname, "WAN") < 0)
        return -1;
    if (open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[dp_slot],
                        "xdp_wan_redirect_prog", &prog, "wan_xsks_map", &map) != 0)
        return -1;
    update_wan_fake_ethertype(p->bpf_wans[dp_slot], fake_ethertype_ipv4);
    profile_iface_xdp_link_off(p->wans[dp_slot].ifname);
    if (xdp_attach_prog(p->wans[dp_slot].ifindex, bpf_program__fd(prog),
                        p->xdp_flags, p->wans[dp_slot].ifname, "WAN") != 0) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
        return -1;
    }
    p->xdp_wan_on[dp_slot] = 1;
    return update_xsk_map_iface(&p->wans[dp_slot], bpf_map__fd(map));
}

int profile_iface_xdp_attach_init(struct ne_pair *p, const struct app_config *cfg)
{
    if (!p || !cfg)
        return -1;

    fprintf(stderr, "[PROFILE-XDP] cold attach: %d LAN, %d WAN(dp)\n",
            p->local_count, p->wan_count);
    fflush(stderr);

    for (int i = 0; i < p->local_count; i++) {
        if (profile_iface_xdp_bind_local(p, cfg, i) != 0) {
            fprintf(stderr, "[PROFILE-XDP] cold attach failed LAN %s (slot %d)\n",
                    p->locals[i].ifname, i);
            fflush(stderr);
            return -1;
        }
    }
    for (int di = 0; di < p->wan_count; di++) {
        if (profile_iface_xdp_bind_wan(p, cfg, di, cfg->fake_ethertype_ipv4) != 0) {
            fprintf(stderr, "[PROFILE-XDP] cold attach failed WAN %s (dp %d)\n",
                    p->wans[di].ifname, di);
            fflush(stderr);
            return -1;
        }
    }
    return 0;
}

/* --- forwarder slot helpers --- */

static void init_fwd_local_meta(struct forwarder *fwd, int li,
                                const struct app_config *cfg, int cfg_local_idx)
{
    memset(&fwd->locals[li], 0, sizeof(fwd->locals[li]));
    fwd->locals[li].ifindex = (int)if_nametoindex(cfg->locals[cfg_local_idx].ifname);
    strncpy(fwd->locals[li].ifname, cfg->locals[cfg_local_idx].ifname,
            sizeof(fwd->locals[li].ifname) - 1);
}

static void init_fwd_wan_meta(struct forwarder *fwd, int di,
                              const struct app_config *cfg, int cfg_wan_idx)
{
    memset(&fwd->wans[di], 0, sizeof(fwd->wans[di]));
    fwd->wans[di].ifindex = (int)if_nametoindex(cfg->wans[cfg_wan_idx].ifname);
    strncpy(fwd->wans[di].ifname, cfg->wans[cfg_wan_idx].ifname, sizeof(fwd->wans[di].ifname) - 1);
}

struct profile_attach_sess {
    int validate_failed;
    int lan_added[MAX_INTERFACES];
    int lan_n;
    int wan_added[MAX_INTERFACES];
    int wan_n;
};

static void fwd_reconcile_iface_counts(struct forwarder *fwd);

static int detach_profile_lan_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                                   const struct app_config *old_cfg, int trigger_profile_id)
{
    const struct profile_config *old_prof = profile_by_id(old_cfg, trigger_profile_id);

    if (!old_prof)
        return 0;

    for (int pi = 0; pi < old_prof->local_count; pi++) {
        int oci = old_prof->local_indices[pi];
        const char *ifname;
        int li;

        if (oci < 0 || oci >= old_cfg->local_count)
            continue;
        ifname = old_cfg->locals[oci].ifname;
        if (config_local_ifname_in_cfg(new_cfg, ifname))
            continue;
        li = pair_local_slot_live(fwd, ifname);
        if (li < 0)
            continue;
        fprintf(stderr,
                "[PROFILE-XDP] profile %d REMOVE LAN %s — detach xdp/id\n",
                trigger_profile_id, ifname);
        ne_pair_unplumb_local(&fwd->pair, li);
    }
    return 0;
}

static int detach_profile_wan_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                                   const struct app_config *old_cfg, int trigger_profile_id)
{
    const struct profile_config *old_prof = profile_by_id(old_cfg, trigger_profile_id);

    if (!old_prof)
        return 0;

    for (int pi = 0; pi < old_prof->wan_count; pi++) {
        int oci = old_prof->wan_indices[pi];
        const char *ifname;
        int di;

        if (oci < 0 || oci >= old_cfg->wan_count)
            continue;
        if (!old_cfg->wans[oci].dataplane)
            continue;
        ifname = old_cfg->wans[oci].ifname;
        if (fwd_wan_ifname_dataplane_in_cfg(new_cfg, ifname))
            continue;
        di = pair_wan_dp_slot_live(fwd, ifname);
        if (di < 0)
            continue;
        (void)fwd_wan_flush_queue(fwd, di);
        fprintf(stderr,
                "[PROFILE-XDP] profile %d REMOVE WAN %s — detach xdp/id\n",
                trigger_profile_id, ifname);
        ne_pair_unplumb_wan_dp(&fwd->pair, di);
        fwd->wan_cfg_idx[di] = -1;
        fwd_wan_mark_stopped(di);
    }
    return 0;
}

static void profile_attach_sess_rollback(struct forwarder *fwd, struct profile_attach_sess *sess)
{
    if (!fwd || !sess)
        return;
    for (int i = sess->lan_n - 1; i >= 0; i--)
        ne_pair_unplumb_local(&fwd->pair, sess->lan_added[i]);
    for (int i = sess->wan_n - 1; i >= 0; i--) {
        ne_pair_unplumb_wan_dp(&fwd->pair, sess->wan_added[i]);
        fwd->wan_cfg_idx[sess->wan_added[i]] = -1;
        fwd_wan_mark_stopped(sess->wan_added[i]);
    }
    sess->lan_n = 0;
    sess->wan_n = 0;
    fwd_reconcile_iface_counts(fwd);
}

/* ADD: LAN rows from trigger profile only (one profile per interface). */
static void attach_profile_lan_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                                    int trigger_profile_id, struct profile_attach_sess *sess)
{
    const struct profile_config *prof = profile_by_id(new_cfg, trigger_profile_id);

    if (!prof || !sess)
        return;

    for (int pi = 0; pi < prof->local_count; pi++) {
        int ci = prof->local_indices[pi];
        const char *ifname;
        int li;
        int owner;

        if (sess->validate_failed)
            break;
        if (ci < 0 || ci >= new_cfg->local_count)
            continue;
        ifname = new_cfg->locals[ci].ifname;
        if (if_nametoindex(ifname) == 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip LAN %s (interface not found)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        owner = config_local_owner_profile(new_cfg, ci, trigger_profile_id);
        if (owner > 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip LAN %s (already used by profile %d)\n",
                    trigger_profile_id, ifname, owner);
            sess->validate_failed = 1;
            continue;
        }
        if (pair_local_slot_live(fwd, ifname) >= 0) {
            continue;
        }

        li = fwd_alloc_local_slot(fwd);
        if (li < 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip LAN %s (MAX_INTERFACES)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        fprintf(stderr, "[PROFILE-XDP] profile %d ADD LAN %s (slot %d)\n",
                trigger_profile_id, ifname, li);
        fflush(stderr);
        if (ne_pair_plumb_local(&fwd->pair, new_cfg, ci, li) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip LAN %s (plumb/XSK failed)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        if (profile_iface_xdp_bind_local(&fwd->pair, new_cfg, li) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip LAN %s (xdp attach/xsk map failed)\n",
                    trigger_profile_id, ifname);
            ne_pair_unplumb_local(&fwd->pair, li);
            sess->validate_failed = 1;
            continue;
        }
        init_fwd_local_meta(fwd, li, new_cfg, ci);
        fwd->local_count = fwd->pair.local_count;
        sess->lan_added[sess->lan_n++] = li;
    }
}

/* ADD: dataplane WAN rows from trigger profile only. */
static void attach_profile_wan_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                                    int trigger_profile_id, struct profile_attach_sess *sess)
{
    const struct profile_config *prof = profile_by_id(new_cfg, trigger_profile_id);

    if (!prof || !sess)
        return;

    for (int pi = 0; pi < prof->wan_count; pi++) {
        int ci = prof->wan_indices[pi];
        const char *ifname;
        int di;
        int owner;

        if (sess->validate_failed)
            break;
        if (ci < 0 || ci >= new_cfg->wan_count)
            continue;
        if (!config_wan_live(new_cfg, ci)) {
            continue;
        }
        ifname = new_cfg->wans[ci].ifname;
        if (if_nametoindex(ifname) == 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (interface not found)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        owner = config_wan_owner_profile(new_cfg, ci, trigger_profile_id);
        if (owner > 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (already used by profile %d)\n",
                    trigger_profile_id, ifname, owner);
            sess->validate_failed = 1;
            continue;
        }
        if (pair_wan_dp_slot_live(fwd, ifname) >= 0) {
            continue;
        }

        di = fwd_alloc_wan_slot(fwd);
        if (di < 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (MAX_INTERFACES)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        fprintf(stderr, "[PROFILE-XDP] profile %d ADD WAN %s (dp slot %d)\n",
                trigger_profile_id, ifname, di);
        fflush(stderr);
        if (ne_pair_plumb_wan_dp(&fwd->pair, new_cfg, ci, di) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (plumb/XSK failed)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        if (profile_iface_xdp_bind_wan(&fwd->pair, new_cfg, di, new_cfg->fake_ethertype_ipv4) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (xdp attach/xsk map failed)\n",
                    trigger_profile_id, ifname);
            ne_pair_unplumb_wan_dp(&fwd->pair, di);
            sess->validate_failed = 1;
            continue;
        }
        fwd->pair.xdp_wan_on[di] = 1;
        init_fwd_wan_meta(fwd, di, new_cfg, ci);
        fwd->wan_cfg_idx[di] = ci;
        fwd->wan_count = fwd->pair.wan_count;
        sess->wan_added[sess->wan_n++] = di;
    }
}

static int attach_profile_iface_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                                     int trigger_profile_id)
{
    struct profile_attach_sess sess;

    memset(&sess, 0, sizeof(sess));
    attach_profile_lan_rows(fwd, new_cfg, trigger_profile_id, &sess);
    attach_profile_wan_rows(fwd, new_cfg, trigger_profile_id, &sess);
    if (!sess.validate_failed)
        return 0;

    profile_attach_sess_rollback(fwd, &sess);
    fprintf(stderr,
            "[VALIDATE] profile %d: skip all policies (LAN/WAN validation failed)\n",
            trigger_profile_id);
    return -1;
}

static int crypto_finish_reload(struct forwarder *fwd, struct app_config *cfg,
                                const struct app_config *old)
{
    fwd_wan_weight_blend_begin(old, cfg, fwd_crypto_profile_slot_for_id);
    if (fwd_crypto_ensure_profile_slots(cfg) != 0) {
        fprintf(stderr, "[PROFILE-XDP] crypto reload failed: ensure_profile_slots\n");
        return -1;
    }
    fwd_crypto_snapshot_active_to_prev();
    int rc = fwd_crypto_rebuild(cfg);
    if (rc != 0) {
        fprintf(stderr, "[PROFILE-XDP] crypto reload failed: fwd_crypto_rebuild\n");
        fwd_crypto_clear_grace();
    }
    fwd_crypto_sync_flow_table_windows(fwd);
    fwd_crypto_cleanup_stale_profile_slots(cfg);
    fwd_wan_reset_on_init(fwd);
    return forwarder_should_stop() ? -1 : rc;
}

static void fwd_reconcile_iface_counts(struct forwarder *fwd)
{
    int max_li = 0;
    int max_di = 0;

    if (!fwd)
        return;
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (ne_pair_local_live(&fwd->pair, i) && i + 1 > max_li)
            max_li = i + 1;
        if (ne_pair_wan_live(&fwd->pair, i) && i + 1 > max_di)
            max_di = i + 1;
    }
    fwd->local_count = max_li;
    fwd->pair.local_count = max_li;
    fwd->wan_count = max_di;
    fwd->pair.wan_count = max_di;
}

int profile_iface_xdp_sync_wan_live(struct forwarder *fwd, const struct app_config *new_cfg,
                                    const struct app_config *old_cfg)
{
    if (!fwd || !new_cfg || !old_cfg || forwarder_should_stop())
        return -1;

    for (int pi = 0; pi < new_cfg->profile_count; pi++) {
        const struct profile_config *prof = &new_cfg->profiles[pi];
        struct profile_attach_sess sess;
        int need_attach = 0;

        for (int wi = 0; wi < prof->wan_count; wi++) {
            int ci = prof->wan_indices[wi];

            if (ci < 0 || ci >= new_cfg->wan_count)
                continue;
            if (!config_wan_live(new_cfg, ci))
                continue;
            if (pair_wan_dp_slot_live(fwd, new_cfg->wans[ci].ifname) >= 0)
                continue;
            need_attach = 1;
            break;
        }
        if (!need_attach)
            continue;

        memset(&sess, 0, sizeof(sess));
        attach_profile_wan_rows(fwd, new_cfg, prof->id, &sess);
        if (sess.validate_failed) {
            profile_attach_sess_rollback(fwd, &sess);
            fprintf(stderr,
                    "[PROFILE-XDP] profile %d: WAN live attach failed\n",
                    prof->id);
            return -1;
        }
        if (sess.wan_n > 0)
            fwd_reconcile_iface_counts(fwd);
    }
    return 0;
}

int profile_iface_xdp_reload_impl(struct forwarder *fwd, struct app_config *cfg,
                                  enum profile_iface_xdp_reload_mode mode,
                                  int trigger_profile_id)
{
    const struct app_config *old = fwd->cfg;

    if (!fwd || !cfg || !old || forwarder_should_stop())
        return -1;
    if (trigger_profile_id <= 0) {
        fprintf(stderr, "[PROFILE-XDP] reload missing trigger profile id\n");
        return -1;
    }

    switch (mode) {
    case PROFILE_IFACE_XDP_REMOVE:
        if (!profile_iface_xdp_can_remove(old, cfg))
            return -1;
        detach_profile_lan_rows(fwd, cfg, old, trigger_profile_id);
        detach_profile_wan_rows(fwd, cfg, old, trigger_profile_id);
        break;
    case PROFILE_IFACE_XDP_ADD:
        if (!profile_iface_xdp_can_add(old, cfg))
            return -1;
        if (attach_profile_iface_rows(fwd, cfg, trigger_profile_id) != 0)
            return -1;
        break;
    case PROFILE_IFACE_XDP_DELTA:
        if (!profile_iface_xdp_can_delta(old, cfg))
            return -1;
        detach_profile_lan_rows(fwd, cfg, old, trigger_profile_id);
        detach_profile_wan_rows(fwd, cfg, old, trigger_profile_id);
        if (attach_profile_iface_rows(fwd, cfg, trigger_profile_id) != 0)
            return -1;
        break;
    default:
        return -1;
    }

    fwd_reconcile_iface_counts(fwd);
    fwd->cfg = cfg;
    return crypto_finish_reload(fwd, cfg, old);
}

int profile_iface_xdp_apply_add(struct forwarder *fwd, struct app_config *cfg,
                                int trigger_profile_id)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!profile_iface_xdp_can_add(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, PROFILE_IFACE_XDP_ADD,
                                           trigger_profile_id);
}

int profile_iface_xdp_apply_remove(struct forwarder *fwd, struct app_config *cfg,
                                   int trigger_profile_id)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!profile_iface_xdp_can_remove(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, PROFILE_IFACE_XDP_REMOVE,
                                           trigger_profile_id);
}

int profile_iface_xdp_apply_delta(struct forwarder *fwd, struct app_config *cfg,
                                    int trigger_profile_id)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!profile_iface_xdp_can_delta(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, PROFILE_IFACE_XDP_DELTA,
                                             trigger_profile_id);
}