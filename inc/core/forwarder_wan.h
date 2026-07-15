#ifndef FORWARDER_WAN_H
#define FORWARDER_WAN_H

#include "config.h"
#include "forwarder.h"

void fwd_wan_reset_on_init(struct forwarder *fwd);

void fwd_wan_drain_tick(struct forwarder *fwd);
void fwd_wan_weight_blend_tick(void);

void fwd_wan_weight_blend_begin(const struct app_config *old, const struct app_config *new,
                                int (*profile_slot_for_id)(int profile_id));

void fwd_wan_configure_removal_drains(struct forwarder *fwd,
                                      const struct app_config *old,
                                      const struct app_config *cfg);

void fwd_wan_configure_live_drains(struct forwarder *fwd,
                                   const struct app_config *old,
                                   const struct app_config *cfg);

int fwd_wan_ifname_dataplane_in_cfg(const struct app_config *cfg, const char *ifname);

int fwd_wan_dp_ok_for_new_traffic(int dp);
int fwd_wan_is_stopped(int dp);
void fwd_wan_mark_stopped(int dp);

uint32_t fwd_wan_flush_queue(struct forwarder *fwd, int wan_idx);
int fwd_wan_has_tx_room(struct forwarder *fwd, int wan_idx);

int fwd_wan_build_profile_pool(struct forwarder *fwd, const struct profile_config *p,
                               int *allowed_wans, int *allowed_weights, int max_n);

int fwd_wan_dp_for_legacy_cfg(struct forwarder *fwd, int legacy_cfg_wan);

int fwd_wan_pick_for_local(struct forwarder *fwd, int profile_idx, int flow_ok,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint8_t proto, uint32_t pkt_len);

#endif
