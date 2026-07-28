#ifndef IFACE_OPS_H
#define IFACE_OPS_H

#include "config.h"
#include "forwarder.h"

struct ne_iface_op_ctx {
    struct forwarder *fwd;
    struct app_config *new_cfg;
    const struct app_config *old_cfg;
    int profile_id;
};

int ne_iface_op_profile_is_new(const struct app_config *old_cfg,
                               const struct app_config *new_cfg,
                               int profile_id);
int ne_iface_op_profile_was_removed(const struct app_config *old_cfg,
                                    const struct app_config *new_cfg,
                                    int profile_id);

int ne_iface_op_profile_add(struct ne_iface_op_ctx *ctx);
int ne_iface_op_profile_edit(struct ne_iface_op_ctx *ctx);
int ne_iface_op_profile_remove(struct ne_iface_op_ctx *ctx);

int ne_iface_op_iface_add(struct ne_iface_op_ctx *ctx);
int ne_iface_op_iface_remove(struct ne_iface_op_ctx *ctx);
int ne_iface_op_iface_delta(struct ne_iface_op_ctx *ctx);
int ne_iface_op_iface_edit(struct ne_iface_op_ctx *ctx);

int ne_iface_op_iface_add_impl(struct forwarder *fwd, struct app_config *cfg,
                               int trigger_profile_id);
int ne_iface_op_iface_remove_impl(struct forwarder *fwd, struct app_config *cfg,
                                  int trigger_profile_id);
int ne_iface_op_iface_delta_impl(struct forwarder *fwd, struct app_config *cfg,
                                 int trigger_profile_id);

#endif
