#include "../../../../../inc/core/iface_ops.h"

#include "../../../../../inc/core/iface_reload.h"

#include <stdio.h>

int ne_iface_op_profile_was_removed(const struct app_config *old_cfg,
                                    const struct app_config *new_cfg,
                                    int profile_id)
{
    int in_old = 0;
    int in_new = 0;

    if (!old_cfg || profile_id <= 0)
        return 0;
    for (int i = 0; i < old_cfg->profile_count; i++) {
        if (old_cfg->profiles[i].id == profile_id)
            in_old = 1;
    }
    if (new_cfg) {
        for (int i = 0; i < new_cfg->profile_count; i++) {
            if (new_cfg->profiles[i].id == profile_id)
                in_new = 1;
        }
    }
    return in_old && !in_new;
}

int ne_iface_op_profile_remove(struct ne_iface_op_ctx *ctx)
{
    if (!ctx || !ctx->fwd || !ctx->new_cfg || ctx->profile_id <= 0)
        return -1;

    fprintf(stderr, "[OPS] profile_remove id=%d\n", ctx->profile_id);
    fflush(stderr);
    return ne_iface_op_iface_remove(ctx);
}
