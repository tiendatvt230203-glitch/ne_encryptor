#ifndef ARP_BRIDGE_H
#define ARP_BRIDGE_H

#include "forwarder.h"

/* Bridge ARP across paired LAN<->WAN (kernel bridge discovery + index fallback).
 * egress_ifname optional — filled with paired egress interface on success. */
int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE]);
int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE]);

#endif
