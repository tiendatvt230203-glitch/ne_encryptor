#ifndef ARP_BRIDGE_H
#define ARP_BRIDGE_H

#include "forwarder.h"

struct profile_config;

void arp_bridge_reload_policies(struct app_config *cfg);

/* Bridge 1:1 — paired fwd local slot for wan dataplane index. */
int bridge_fwd_local_for_wan_dp(struct forwarder *fwd,
                                const struct profile_config *prof,
                                int wan_dp);

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE]);
int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE]);

#endif
