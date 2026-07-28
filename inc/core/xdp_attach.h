#ifndef XDP_ATTACH_H
#define XDP_ATTACH_H

#include "config.h"
#include "forwarder.h"

void ne_xdp_attach_prepare_init(const struct app_config *cfg);

int ne_xdp_attach_attach_init(struct ne_pair *p, const struct app_config *cfg);

int ne_xdp_attach_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li);
int ne_xdp_attach_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                           uint16_t fake_ethertype_ipv4);

void ne_xdp_attach_detach_local(struct ne_pair *p, int pair_li);
void ne_xdp_attach_detach_wan(struct ne_pair *p, int dp_slot);
void ne_xdp_attach_detach_ifname(const char *ifname);
void ne_xdp_attach_detach_config(const struct app_config *cfg);

#endif
