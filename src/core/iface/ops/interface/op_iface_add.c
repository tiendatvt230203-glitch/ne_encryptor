#include "../../../../../inc/core/iface_ops.h"

#include "../../../../../inc/core/iface_reload.h"
#include "../../../../../inc/core/profile_iface_lifecycle.h"
#include "../../../../../inc/core/forwarder_reload.h"

#include <stdio.h>

int ne_iface_op_iface_add_impl(struct forwarder *fwd, struct app_config *cfg,
                               int trigger_profile_id)
{
    const struct app_config *old;

    if (!fwd || !cfg || trigger_profile_id <= 0 || forwarder_should_stop())
        return -1;
    old = fwd->cfg;
    if (!old || !ne_iface_reload_can_add(old, cfg))
        return -1;
    if (profile_iface_life_attach_profile_rows(fwd, cfg, trigger_profile_id) != 0)
        return -1;

    profile_iface_life_reconcile_counts(fwd);
    fwd->cfg = cfg;
    return ne_iface_reload_finish_crypto(fwd, cfg, old);
}

int ne_iface_op_iface_delta_impl(struct forwarder *fwd, struct app_config *cfg,
                                 int trigger_profile_id)
{
    const struct app_config *old;

    if (!fwd || !cfg || trigger_profile_id <= 0 || forwarder_should_stop())
        return -1;
    old = fwd->cfg;
    if (!old || !ne_iface_reload_can_delta(old, cfg))
        return -1;

    (void)profile_iface_life_detach_profile_rows(fwd, cfg, old, trigger_profile_id);
    if (profile_iface_life_attach_profile_rows(fwd, cfg, trigger_profile_id) != 0)
        return -1;

    profile_iface_life_reconcile_counts(fwd);
    fwd->cfg = cfg;
    return ne_iface_reload_finish_crypto(fwd, cfg, old);
}

int ne_iface_op_iface_add(struct ne_iface_op_ctx *ctx)
{
    if (!ctx || !ctx->fwd || !ctx->new_cfg || ctx->profile_id <= 0)
        return -1;

    fprintf(stderr, "[OPS] iface_add profile=%d\n", ctx->profile_id);
    fflush(stderr);
    return ne_iface_reload_apply_add(ctx->fwd, ctx->new_cfg, ctx->profile_id);
}

int ne_iface_op_iface_delta(struct ne_iface_op_ctx *ctx)
{
    if (!ctx || !ctx->fwd || !ctx->new_cfg || ctx->profile_id <= 0)
        return -1;

    fprintf(stderr, "[OPS] iface_delta profile=%d\n", ctx->profile_id);
    fflush(stderr);
    return ne_iface_reload_apply_delta(ctx->fwd, ctx->new_cfg, ctx->profile_id);
}
