#include "../../../../../inc/core/iface_ops.h"

#include "../../../../../inc/core/iface_reload.h"
#include "../../../../../inc/core/profile_iface_lifecycle.h"
#include "../../../../../inc/core/forwarder_reload.h"

#include <stdio.h>

int ne_iface_op_iface_remove_impl(struct forwarder *fwd, struct app_config *cfg,
                                  int trigger_profile_id)
{
    const struct app_config *old;

    if (!fwd || !cfg || trigger_profile_id <= 0 || forwarder_should_stop())
        return -1;
    old = fwd->cfg;
    if (!old || !ne_iface_reload_can_remove(old, cfg))
        return -1;

    (void)profile_iface_life_detach_profile_rows(fwd, cfg, old, trigger_profile_id);
    profile_iface_life_reconcile_counts(fwd);
    fwd->cfg = cfg;
    return ne_iface_reload_finish_crypto(fwd, cfg, old);
}

int ne_iface_op_iface_remove(struct ne_iface_op_ctx *ctx)
{
    if (!ctx || !ctx->fwd || !ctx->new_cfg || ctx->profile_id <= 0)
        return -1;

    fprintf(stderr, "[OPS] iface_remove profile=%d\n", ctx->profile_id);
    fflush(stderr);
    return ne_iface_reload_apply_remove(ctx->fwd, ctx->new_cfg, ctx->profile_id);
}
