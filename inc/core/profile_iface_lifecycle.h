#ifndef PROFILE_IFACE_LIFECYCLE_H
#define PROFILE_IFACE_LIFECYCLE_H

#include "config.h"
#include "forwarder.h"

struct profile_attach_sess {
    int validate_failed;
    int lan_added[MAX_INTERFACES];
    int lan_n;
    int wan_added[MAX_INTERFACES];
    int wan_n;
};

int profile_iface_life_detach_lan(struct forwarder *fwd, const char *ifname, int profile_id);
int profile_iface_life_detach_wan(struct forwarder *fwd, const char *ifname, int profile_id);

int profile_iface_life_detach_profile_rows(struct forwarder *fwd,
                                          const struct app_config *new_cfg,
                                          const struct app_config *old_cfg,
                                          int trigger_profile_id);

void profile_iface_life_attach_lan_rows(struct forwarder *fwd,
                                       const struct app_config *new_cfg,
                                       int trigger_profile_id,
                                       struct profile_attach_sess *sess);
void profile_iface_life_attach_wan_rows(struct forwarder *fwd,
                                       const struct app_config *new_cfg,
                                       int trigger_profile_id,
                                       struct profile_attach_sess *sess);
int profile_iface_life_attach_profile_rows(struct forwarder *fwd,
                                          const struct app_config *new_cfg,
                                          int trigger_profile_id);
void profile_iface_life_attach_rollback(struct forwarder *fwd,
                                       struct profile_attach_sess *sess);

void profile_iface_life_reconcile_counts(struct forwarder *fwd);

#endif
