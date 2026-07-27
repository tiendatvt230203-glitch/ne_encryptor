#ifndef ARP_BRIDGE_H
#define ARP_BRIDGE_H

#include "forwarder.h"

/* Rebuild cache of L2 + PQC + protocol=any policies (implicit ARP encrypt). */
void arp_bridge_reload_policies(struct app_config *cfg);

/* Bridge ARP across LAN<->WAN pairs loaded from BE (profile bridges[]).
 * Local→WAN: encrypt when SPA/TPA match a cached L2+PQC+any policy.
 * WAN→Local: decrypt L2-marker ARP via wire policy_id when still in cache. */
int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE]);
int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE]);

/* Decrypt L2-marker ARP in-place for logging/bridge. Returns 1 decrypted,
 * 0 plain ARP, -1 not ARP wire or decrypt failed. */
int arp_try_decrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job, uint8_t *pkt);

#endif
