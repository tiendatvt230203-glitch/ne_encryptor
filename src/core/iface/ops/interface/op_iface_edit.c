#include "../../../../../inc/core/iface_ops.h"
#include "../../../../../inc/core/iface_reload.h"
#include "../../../../../inc/core/profile_iface_lifecycle.h"
#include "../../../../../inc/core/interface.h"

#include <stdio.h>
#include <string.h>

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
    for (int di = 0; di < fwd->pair.wan_count; di++) {
        if (!ne_pair_wan_live(&fwd->pair, di))
            continue;
        if (strcmp(fwd->pair.wans[di].ifname, ifname) == 0)
            return di;
    }
    return -1;
}

static int lan_needs_replumb(const struct forwarder *fwd, const char *ifname)
{
    int li = pair_local_slot_live(fwd, ifname);
    int want;

    if (li < 0)
        return 0;
    want = ne_pair_iface_want_queues(ifname);
    return fwd->pair.locals[li].queue_count != want;
}

static int wan_needs_replumb(const struct forwarder *fwd,
                             const struct wan_config *old,
                             const struct wan_config *nw)
{
    int di;
    int want;

    if (!old || !nw)
        return 0;
    if (old->dataplane != nw->dataplane)
        return 1;
    di = pair_wan_dp_slot_live(fwd, nw->ifname);
    if (di < 0)
        return 0;
    want = ne_pair_iface_want_queues(nw->ifname);
    return fwd->pair.wans[di].queue_count != want;
}

static int edit_replumb_lan(struct forwarder *fwd, const struct app_config *new_cfg,
                            int trigger_profile_id, const char *ifname)
{
    struct profile_attach_sess sess;

    if (profile_iface_life_detach_lan(fwd, ifname, trigger_profile_id) != 0)
        return -1;
    memset(&sess, 0, sizeof(sess));
    profile_iface_life_attach_lan_rows(fwd, new_cfg, trigger_profile_id, &sess);
    if (sess.validate_failed) {
        profile_iface_life_attach_rollback(fwd, &sess);
        return -1;
    }
    if (sess.lan_n > 0)
        profile_iface_life_reconcile_counts(fwd);
    return 0;
}

static int edit_replumb_wan(struct forwarder *fwd, const struct app_config *new_cfg,
                            int trigger_profile_id, const char *ifname)
{
    struct profile_attach_sess sess;

    if (profile_iface_life_detach_wan(fwd, ifname, trigger_profile_id) != 0)
        return -1;
    memset(&sess, 0, sizeof(sess));
    profile_iface_life_attach_wan_rows(fwd, new_cfg, trigger_profile_id, &sess);
    if (sess.validate_failed) {
        profile_iface_life_attach_rollback(fwd, &sess);
        return -1;
    }
    if (sess.wan_n > 0)
        profile_iface_life_reconcile_counts(fwd);
    return 0;
}

int ne_iface_reload_edit_impl(struct forwarder *fwd, struct app_config *cfg,
                              int trigger_profile_id)
{
    const struct app_config *old = fwd->cfg;
    const struct profile_config *prof;
    int replumbed = 0;

    if (!fwd || !cfg || !old || trigger_profile_id <= 0 || forwarder_should_stop())
        return -1;
    if (!ne_iface_reload_is_edit_only(old, cfg))
        return -1;

    prof = profile_by_id(old, trigger_profile_id);
    if (!prof)
        prof = profile_by_id(cfg, trigger_profile_id);
    if (!prof)
        return -1;

    fprintf(stderr, "[OPS] iface_edit profile=%d\n", trigger_profile_id);
    fflush(stderr);

    for (int pi = 0; pi < prof->local_count; pi++) {
        int ci = prof->local_indices[pi];
        const char *ifname;

        if (ci < 0 || ci >= old->local_count)
            continue;
        ifname = old->locals[ci].ifname;
        if (!lan_needs_replumb(fwd, ifname))
            continue;
        if (edit_replumb_lan(fwd, cfg, trigger_profile_id, ifname) != 0) {
            fprintf(stderr, "[OPS] iface_edit: LAN %s replumb failed\n", ifname);
            return -1;
        }
        replumbed = 1;
    }

    for (int pi = 0; pi < prof->wan_count; pi++) {
        int ci = prof->wan_indices[pi];
        const struct wan_config *ow;
        const struct wan_config *nw;
        const char *ifname;

        if (ci < 0 || ci >= old->wan_count || ci >= cfg->wan_count)
            continue;
        ow = &old->wans[ci];
        nw = &cfg->wans[ci];
        ifname = nw->ifname;
        if (!config_wan_live(cfg, ci))
            continue;
        if (!wan_needs_replumb(fwd, ow, nw))
            continue;
        if (edit_replumb_wan(fwd, cfg, trigger_profile_id, ifname) != 0) {
            fprintf(stderr, "[OPS] iface_edit: WAN %s replumb failed\n", ifname);
            return -1;
        }
        replumbed = 1;
    }

    (void)replumbed;
    fwd->cfg = cfg;
    return ne_iface_reload_finish_crypto(fwd, cfg, old);
}

int ne_iface_op_iface_edit(struct ne_iface_op_ctx *ctx)
{
    if (!ctx || !ctx->fwd || !ctx->new_cfg || ctx->profile_id <= 0)
        return -1;

    return ne_iface_reload_apply_edit(ctx->fwd, ctx->new_cfg, ctx->profile_id);
}
