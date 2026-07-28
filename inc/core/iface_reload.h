#ifndef IFACE_RELOAD_H
#define IFACE_RELOAD_H

#include "config.h"
#include "forwarder.h"
#include "iface_ops.h"

enum ne_iface_reload_mode {
    NE_IFACE_RELOAD_ADD = 10,
    NE_IFACE_RELOAD_REMOVE = 11,
    NE_IFACE_RELOAD_DELTA = 12,
    NE_IFACE_RELOAD_EDIT = 13,
};

enum ne_iface_reload_path {
    NE_IFACE_RELOAD_PATH_NONE = 0,
    NE_IFACE_RELOAD_PATH_ADD_ONLY,
    NE_IFACE_RELOAD_PATH_DELTA,
    NE_IFACE_RELOAD_PATH_ADD,
    NE_IFACE_RELOAD_PATH_REMOVE,
    NE_IFACE_RELOAD_PATH_EDIT,
};

#include "iface_route_classifier.h"

int ne_iface_reload_apply_add(struct forwarder *fwd, struct app_config *cfg,
                              int trigger_profile_id);
int ne_iface_reload_apply_remove(struct forwarder *fwd, struct app_config *cfg,
                                 int trigger_profile_id);
int ne_iface_reload_apply_delta(struct forwarder *fwd, struct app_config *cfg,
                                int trigger_profile_id);
int ne_iface_reload_apply_edit(struct forwarder *fwd, struct app_config *cfg,
                               int trigger_profile_id);

int ne_iface_reload_impl(struct forwarder *fwd, struct app_config *cfg,
                         enum ne_iface_reload_mode mode, int trigger_profile_id);

int ne_iface_reload_edit_impl(struct forwarder *fwd, struct app_config *cfg,
                              int trigger_profile_id);

int ne_iface_reload_finish_crypto(struct forwarder *fwd, struct app_config *cfg,
                                  const struct app_config *old);

int ne_iface_reload_sync_wan_live(struct forwarder *fwd, const struct app_config *new_cfg,
                                  const struct app_config *old_cfg);

int ne_iface_reload_try_incremental(struct ne_iface_op_ctx *ctx,
                                    enum ne_iface_reload_path path);

#endif
