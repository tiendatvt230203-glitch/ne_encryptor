#include "../../../inc/core/iface/profile_iface_lifecycle.h"

#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/iface/interface.h"
#include "../../../inc/core/iface/profile_iface_xdp.h"
#include "../../../inc/core/flow/mac_learn.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>

static int fwd_ensure_mid_local_rings(struct forwarder *fwd, int li)
{
    if (!fwd || li < 0 || li >= MAX_INTERFACES)
        return -1;
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (fwd->mid_to_local[li][w].cap != 0)
            continue;
        if (ne_ring_init(&fwd->mid_to_local[li][w], NE_RING, 1) != 0) {
            fprintf(stderr,
                    "[PROFILE-LIFE] mid_to_local ring init failed slot %d worker %d\n",
                    li, w);
            return -1;
        }
    }
    return 0;
}

static int fwd_ensure_mid_wan_rings(struct forwarder *fwd, int di)
{
    if (!fwd || di < 0 || di >= MAX_INTERFACES)
        return -1;
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (fwd->mid_to_wan[di][w].cap != 0)
            continue;
        if (ne_ring_init(&fwd->mid_to_wan[di][w], NE_RING, 1) != 0) {
            fprintf(stderr,
                    "[PROFILE-LIFE] mid_to_wan ring init failed slot %d worker %d\n",
                    di, w);
            return -1;
        }
    }
    return 0;
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


static int fwd_alloc_local_slot(struct forwarder *fwd)
{
    int n;
    int umem_li;

    if (!fwd)
        return -1;
    n = fwd->pair.local_count;
    umem_li = fwd->pair.umem_fq_li;

    for (int i = 0; i < n; i++) {
        if (i == umem_li)
            continue;
        if (!ne_pair_local_live(&fwd->pair, i))
            return i;
    }
    if (n < MAX_INTERFACES)
        return n;
    if (umem_li >= 0 && umem_li < n && !ne_pair_local_live(&fwd->pair, umem_li))
        return umem_li;
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
    strncpy(fwd->wans[di].ifname, cfg->wans[cfg_wan_idx].ifname,
            sizeof(fwd->wans[di].ifname) - 1);
}

static int profile_lists_local_ifname(const struct profile_config *prof,
                                      const struct app_config *cfg,
                                      const char *ifname)
{
    if (!prof || !cfg || !ifname)
        return 0;
    for (int pi = 0; pi < prof->local_count; pi++) {
        int ci = prof->local_indices[pi];

        if (ci < 0 || ci >= cfg->local_count)
            continue;
        if (strcmp(cfg->locals[ci].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

static int profile_lists_wan_ifname(const struct profile_config *prof,
                                    const struct app_config *cfg,
                                    const char *ifname)
{
    if (!prof || !cfg || !ifname)
        return 0;
    for (int pi = 0; pi < prof->wan_count; pi++) {
        int ci = prof->wan_indices[pi];

        if (ci < 0 || ci >= cfg->wan_count)
            continue;
        if (strcmp(cfg->wans[ci].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

void profile_iface_life_reconcile_counts(struct forwarder *fwd)
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

int profile_iface_life_detach_lan(struct forwarder *fwd, const char *ifname, int profile_id)
{
    int li;

    if (!fwd || !ifname)
        return -1;
    li = pair_local_slot_live(fwd, ifname);
    if (li < 0)
        return 0;
    fprintf(stderr,
            "[PROFILE-LIFE] profile %d REMOVE LAN %s — detach xdp/xsk (slot %d)\n",
            profile_id, ifname, li);
    fflush(stderr);
    ne_pair_unplumb_local(&fwd->pair, li);
    memset(&fwd->locals[li], 0, sizeof(fwd->locals[li]));
    return 0;
}

int profile_iface_life_detach_wan(struct forwarder *fwd, const char *ifname, int profile_id)
{
    int di;

    if (!fwd || !ifname)
        return -1;
    di = pair_wan_dp_slot_live(fwd, ifname);
    if (di < 0)
        return 0;
    (void)fwd_wan_flush_queue(fwd, di);
    fprintf(stderr,
            "[PROFILE-LIFE] profile %d REMOVE WAN %s — detach xdp/xsk (dp slot %d)\n",
            profile_id, ifname, di);
    fflush(stderr);
    ne_pair_unplumb_wan_dp(&fwd->pair, di);
    memset(&fwd->wans[di], 0, sizeof(fwd->wans[di]));
    fwd->wan_cfg_idx[di] = -1;
    fwd_wan_mark_stopped(di);
    profile_iface_life_reconcile_counts(fwd);
    fwd_wan_refresh_active(fwd);
    return 0;
}

int profile_iface_life_attach_wan_ifname(struct forwarder *fwd,
                                        const struct app_config *cfg,
                                        const char *ifname,
                                        int profile_id)
{
    int ci = -1;
    int di;
    int owner;

    if (!fwd || !cfg || !ifname || !ifname[0])
        return -1;

    if (pair_wan_dp_slot_live(fwd, ifname) >= 0) {
        fprintf(stderr, "[PROFILE-LIFE] ADD WAN %s — already live, skip\n", ifname);
        fflush(stderr);
        return 0;
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) != 0)
            continue;
        if (!config_wan_live(cfg, i)) {
            fprintf(stderr,
                    "[PROFILE-LIFE] ADD WAN %s — not dataplane in cfg (dst_ip set?)\n",
                    ifname);
            fflush(stderr);
            return -1;
        }
        ci = i;
        break;
    }
    if (ci < 0) {
        fprintf(stderr, "[PROFILE-LIFE] ADD WAN %s — not found in active config\n", ifname);
        fflush(stderr);
        return -1;
    }

    if (if_nametoindex(ifname) == 0) {
        fprintf(stderr, "[PROFILE-LIFE] ADD WAN %s — kernel interface missing\n", ifname);
        fflush(stderr);
        return -1;
    }

    owner = config_wan_owner_profile(cfg, ci, -1);
    if (profile_id <= 0)
        profile_id = owner > 0 ? owner : 0;

    di = fwd_alloc_wan_slot(fwd);
    if (di < 0) {
        fprintf(stderr, "[PROFILE-LIFE] ADD WAN %s — no free dp slot\n", ifname);
        fflush(stderr);
        return -1;
    }

    fprintf(stderr, "[PROFILE-LIFE] profile %d ADD WAN %s (dp slot %d)\n",
            profile_id, ifname, di);
    fflush(stderr);

    if (fwd_ensure_mid_wan_rings(fwd, di) != 0) {
        fprintf(stderr, "[PROFILE-LIFE] ADD WAN %s — egress ring init failed\n", ifname);
        return -1;
    }
    if (ne_pair_plumb_wan_dp(&fwd->pair, cfg, ci, di) != 0) {
        fprintf(stderr, "[PROFILE-LIFE] ADD WAN %s — plumb/XSK failed\n", ifname);
        return -1;
    }
    if (profile_iface_xdp_bind_wan(&fwd->pair, cfg, di, cfg->fake_ethertype_ipv4) != 0) {
        fprintf(stderr, "[PROFILE-LIFE] ADD WAN %s — xdp attach failed\n", ifname);
        ne_pair_unplumb_wan_dp(&fwd->pair, di);
        return -1;
    }
    fwd->pair.xdp_wan_on[di] = 1;
    init_fwd_wan_meta(fwd, di, cfg, ci);
    fwd->wan_cfg_idx[di] = ci;
    fwd_wan_mark_live(di);
    profile_iface_life_reconcile_counts(fwd);
    fwd_wan_refresh_active(fwd);
    fprintf(stderr,
            "[PROFILE-LIFE] profile %d ADD WAN %s OK (dp=%d wan_count=%d)\n",
            profile_id, ifname, di, fwd->wan_count);
    fflush(stderr);
    return 0;
}

int profile_iface_life_detach_profile_rows(struct forwarder *fwd,
                                          const struct app_config *new_cfg,
                                          const struct app_config *old_cfg,
                                          int trigger_profile_id)
{
    const struct profile_config *old_prof;
    const struct profile_config *new_prof;

    if (!fwd || !new_cfg || !old_cfg)
        return -1;

    old_prof = profile_by_id(old_cfg, trigger_profile_id);
    if (!old_prof)
        return 0;
    new_prof = profile_by_id(new_cfg, trigger_profile_id);

    for (int pi = 0; pi < old_prof->wan_count; pi++) {
        int oci = old_prof->wan_indices[pi];
        const char *ifname;
        int di;

        if (oci < 0 || oci >= old_cfg->wan_count)
            continue;
        ifname = old_cfg->wans[oci].ifname;

        if (new_prof && profile_lists_wan_ifname(new_prof, new_cfg, ifname) &&
            config_wan_live_in_cfg(new_cfg, ifname)) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip WAN %s (still_in_new profile)\n",
                    trigger_profile_id, ifname);
            continue;
        }
        if (config_wan_live_in_cfg(new_cfg, ifname)) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip WAN %s (still_in_new dataplane)\n",
                    trigger_profile_id, ifname);
            continue;
        }
        di = pair_wan_dp_slot_live(fwd, ifname);
        if (di < 0) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip WAN %s (not_live)%s\n",
                    trigger_profile_id, ifname,
                    old_cfg->wans[oci].dataplane ? "" : " old_not_dataplane");
            continue;
        }
        /* Detach live WAN even if old row lost the dataplane flag. */
        (void)profile_iface_life_detach_wan(fwd, ifname, trigger_profile_id);
    }

    for (int pi = 0; pi < old_prof->local_count; pi++) {
        int oci = old_prof->local_indices[pi];
        const char *ifname;
        int li;

        if (oci < 0 || oci >= old_cfg->local_count)
            continue;
        ifname = old_cfg->locals[oci].ifname;

        if (new_prof && profile_lists_local_ifname(new_prof, new_cfg, ifname)) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip LAN %s (still_in_new profile)\n",
                    trigger_profile_id, ifname);
            continue;
        }
        if (config_local_ifname_in_cfg(new_cfg, ifname)) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip LAN %s (still_in_new cfg)\n",
                    trigger_profile_id, ifname);
            continue;
        }
        li = pair_local_slot_live(fwd, ifname);
        if (li < 0) {
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip LAN %s (not_live)\n",
                    trigger_profile_id, ifname);
            continue;
        }
        (void)profile_iface_life_detach_lan(fwd, ifname, trigger_profile_id);
    }

    profile_iface_life_reconcile_counts(fwd);
    return 0;
}

void profile_iface_life_attach_rollback(struct forwarder *fwd,
                                       struct profile_attach_sess *sess)
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
    profile_iface_life_reconcile_counts(fwd);
}

void profile_iface_life_attach_lan_rows(struct forwarder *fwd,
                                       const struct app_config *new_cfg,
                                       int trigger_profile_id,
                                       struct profile_attach_sess *sess)
{
    const struct profile_config *prof = profile_by_id(new_cfg, trigger_profile_id);

    if (!prof || !sess || !fwd || !new_cfg)
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
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip LAN %s (already_live)\n",
                    trigger_profile_id, ifname);
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
        fprintf(stderr, "[PROFILE-LIFE] profile %d ADD LAN %s (slot %d)\n",
                trigger_profile_id, ifname, li);
        fflush(stderr);
        if (fwd_ensure_mid_local_rings(fwd, li) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip LAN %s (egress ring init failed)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
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

void profile_iface_life_attach_wan_rows(struct forwarder *fwd,
                                       const struct app_config *new_cfg,
                                       int trigger_profile_id,
                                       struct profile_attach_sess *sess)
{
    const struct profile_config *prof = profile_by_id(new_cfg, trigger_profile_id);

    if (!prof || !sess || !fwd || !new_cfg)
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
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip WAN %s (not_dataplane)\n",
                    trigger_profile_id, new_cfg->wans[ci].ifname);
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
            fprintf(stderr,
                    "[PROFILE-LIFE] profile %d skip WAN %s (already_live)\n",
                    trigger_profile_id, ifname);
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
        fprintf(stderr, "[PROFILE-LIFE] profile %d ADD WAN %s (dp slot %d)\n",
                trigger_profile_id, ifname, di);
        fflush(stderr);
        if (fwd_ensure_mid_wan_rings(fwd, di) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (egress ring init failed)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        if (ne_pair_plumb_wan_dp(&fwd->pair, new_cfg, ci, di) != 0) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: skip WAN %s (plumb/XSK failed)\n",
                    trigger_profile_id, ifname);
            sess->validate_failed = 1;
            continue;
        }
        if (profile_iface_xdp_bind_wan(&fwd->pair, new_cfg, di,
                                       new_cfg->fake_ethertype_ipv4) != 0) {
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
        fwd_wan_mark_live(di);
        fwd->wan_count = fwd->pair.wan_count;
        sess->wan_added[sess->wan_n++] = di;
    }
}

int profile_iface_life_attach_profile_rows(struct forwarder *fwd,
                                          const struct app_config *new_cfg,
                                          int trigger_profile_id)
{
    struct profile_attach_sess sess;

    memset(&sess, 0, sizeof(sess));
    profile_iface_life_attach_lan_rows(fwd, new_cfg, trigger_profile_id, &sess);
    profile_iface_life_attach_wan_rows(fwd, new_cfg, trigger_profile_id, &sess);
    if (!sess.validate_failed)
        return 0;

    profile_iface_life_attach_rollback(fwd, &sess);
    fprintf(stderr,
            "[VALIDATE] profile %d: skip all policies (LAN/WAN validation failed)\n",
            trigger_profile_id);
    return -1;
}

int profile_iface_life_rebuild_from_cfg(struct forwarder *fwd,
                                        const struct app_config *new_cfg,
                                        int trigger_profile_id)
{
    if (!fwd || !new_cfg || trigger_profile_id <= 0)
        return -1;

    fprintf(stderr,
            "[PROFILE-LIFE] profile %d: full UMEM rebuild (teardown → fresh plumb)\n",
            trigger_profile_id);
    fflush(stderr);

    for (int di = 0; di < MAX_INTERFACES; di++) {
        if (ne_pair_wan_live(&fwd->pair, di))
            (void)fwd_wan_flush_queue(fwd, di);
    }

    if (ne_pair_teardown_live(&fwd->pair) != 0) {
        fprintf(stderr, "[PROFILE-LIFE] profile %d: teardown failed\n",
                trigger_profile_id);
        return -1;
    }

    for (int i = 0; i < MAX_INTERFACES; i++) {
        memset(&fwd->locals[i], 0, sizeof(fwd->locals[i]));
        memset(&fwd->wans[i], 0, sizeof(fwd->wans[i]));
        fwd->wan_cfg_idx[i] = -1;
        fwd_wan_mark_stopped(i);
    }
    fwd->local_count = 0;
    fwd->wan_count = 0;

    if (!profile_by_id(new_cfg, trigger_profile_id)) {
        profile_iface_life_reconcile_counts(fwd);
        return 0;
    }

    if (profile_iface_life_attach_profile_rows(fwd, new_cfg, trigger_profile_id) != 0)
        return -1;

    profile_iface_life_reconcile_counts(fwd);
    mac_learn_restore(fwd);
    fprintf(stderr,
            "[PROFILE-LIFE] profile %d: rebuild done (lan=%d wan=%d umem_slot=%d)\n",
            trigger_profile_id, fwd->local_count, fwd->wan_count,
            fwd->pair.umem_fq_li);
    fflush(stderr);
    return 0;
}
