#ifndef FORWARDER_RELOAD_H
#define FORWARDER_RELOAD_H

#include "config.h"
#include "forwarder.h"
#include "iface_reload.h"

int forwarder_same_topology(const struct app_config *a, const struct app_config *b);
int forwarder_is_wan_only_removal(const struct app_config *old, const struct app_config *new);

int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg);
int forwarder_reload_wan_removal(struct forwarder *fwd, struct app_config *cfg);
int forwarder_queue_profile_iface_xdp(struct forwarder *fwd, struct app_config *cfg,
                                      enum ne_iface_reload_mode mode,
                                      int trigger_profile_id);

int fwd_reload_apply_if_pending(void);

void fwd_reload_shutdown(void);

#endif
