#ifndef ARP_BRIDGE_H
#define ARP_BRIDGE_H

#include "forwarder.h"

/* Bridge ARP across paired LAN<->WAN (kernel bridge discovery + index fallback). */
int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li);
int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp);

#endif
