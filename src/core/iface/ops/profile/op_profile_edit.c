#include "../../../../../inc/core/iface_ops.h"

#include "../../../../../inc/core/forwarder_reload.h"

#include <stdio.h>

int ne_iface_op_profile_edit(struct ne_iface_op_ctx *ctx)
{
    if (!ctx || !ctx->fwd || !ctx->new_cfg)
        return -1;

    fprintf(stderr, "[OPS] profile_edit id=%d (policy/metadata hot reload)\n",
            ctx->profile_id);
    fflush(stderr);
    return forwarder_reload_config(ctx->fwd, ctx->new_cfg);
}
