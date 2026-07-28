#include "../../../../inc/core/iface_reload.h"
#include "../../../../inc/core/iface_route_classifier.h"
#include "../../../../inc/core/profile_iface_lifecycle.h"
#include "../../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../../inc/core/forwarder_reload.h"
#include "../../../../inc/core/forwarder_wan.h"
#include "../../../../inc/core/interface.h"
#include "../../../../inc/core/xdp_attach.h"

#include <stdio.h>
#include <string.h>

int ne_iface_reload_try_incremental(struct ne_iface_op_ctx *ctx,
                                    enum ne_iface_reload_path path)
{
    if (!ctx)
        return -1;
    switch (path) {
    case NE_IFACE_RELOAD_PATH_ADD_ONLY:
    case NE_IFACE_RELOAD_PATH_ADD:
        return ne_iface_op_iface_add(ctx);
    case NE_IFACE_RELOAD_PATH_DELTA:
        return ne_iface_op_iface_delta(ctx);
    case NE_IFACE_RELOAD_PATH_REMOVE:
        return ne_iface_op_iface_remove(ctx);
    case NE_IFACE_RELOAD_PATH_EDIT:
        return ne_iface_op_iface_edit(ctx);
    default:
        return -1;
    }
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

int ne_iface_reload_finish_crypto(struct forwarder *fwd, struct app_config *cfg,
                                  const struct app_config *old)
{
    fwd_wan_weight_blend_begin(old, cfg, fwd_crypto_profile_slot_for_id);
    if (fwd_crypto_ensure_profile_slots(cfg) != 0) {
        fprintf(stderr, "[IFACE-RELOAD] crypto reload failed: ensure_profile_slots\n");
        return -1;
    }
    fwd_crypto_snapshot_active_to_prev();
    int rc = fwd_crypto_rebuild(cfg);
    if (rc != 0) {
        fprintf(stderr, "[IFACE-RELOAD] crypto reload failed: fwd_crypto_rebuild\n");
        fwd_crypto_clear_grace();
    }
    fwd_crypto_sync_flow_table_windows(fwd);
    fwd_crypto_cleanup_stale_profile_slots(cfg);
    fwd_wan_reset_on_init(fwd);
    return forwarder_should_stop() ? -1 : rc;
}

int ne_iface_reload_sync_wan_live(struct forwarder *fwd, const struct app_config *new_cfg,
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
        profile_iface_life_attach_wan_rows(fwd, new_cfg, prof->id, &sess);
        if (sess.validate_failed) {
            profile_iface_life_attach_rollback(fwd, &sess);
            fprintf(stderr,
                    "[IFACE-RELOAD] profile %d: WAN live attach failed\n",
                    prof->id);
            return -1;
        }
        if (sess.wan_n > 0)
            profile_iface_life_reconcile_counts(fwd);
    }
    return 0;
}

int ne_iface_reload_impl(struct forwarder *fwd, struct app_config *cfg,
                         enum ne_iface_reload_mode mode, int trigger_profile_id)
{
    if (!fwd || !cfg || trigger_profile_id <= 0 || forwarder_should_stop())
        return -1;

    switch (mode) {
    case NE_IFACE_RELOAD_REMOVE:
        return ne_iface_op_iface_remove_impl(fwd, cfg, trigger_profile_id);
    case NE_IFACE_RELOAD_ADD:
        return ne_iface_op_iface_add_impl(fwd, cfg, trigger_profile_id);
    case NE_IFACE_RELOAD_DELTA:
        return ne_iface_op_iface_delta_impl(fwd, cfg, trigger_profile_id);
    default:
        return -1;
    }
}

int ne_iface_reload_apply_add(struct forwarder *fwd, struct app_config *cfg,
                              int trigger_profile_id)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!ne_iface_reload_can_add(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, NE_IFACE_RELOAD_ADD,
                                             trigger_profile_id);
}

int ne_iface_reload_apply_remove(struct forwarder *fwd, struct app_config *cfg,
                                 int trigger_profile_id)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!ne_iface_reload_can_remove(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, NE_IFACE_RELOAD_REMOVE,
                                             trigger_profile_id);
}

int ne_iface_reload_apply_delta(struct forwarder *fwd, struct app_config *cfg,
                                int trigger_profile_id)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!ne_iface_reload_can_delta(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, NE_IFACE_RELOAD_DELTA,
                                             trigger_profile_id);
}

int ne_iface_reload_apply_edit(struct forwarder *fwd, struct app_config *cfg,
                               int trigger_profile_id)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!ne_iface_reload_is_edit_only(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, NE_IFACE_RELOAD_EDIT,
                                             trigger_profile_id);
}
