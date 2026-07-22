#ifndef DATAPLANE_UTIL_H
#define DATAPLANE_UTIL_H

#include "forwarder.h"

int dp_parse_flow(void *pkt, uint32_t len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto);

int dp_pkt_is_arp(const uint8_t *pkt, uint32_t len);

/* Parse SPA/TPA from Ethernet+IPv4 ARP. Returns 0 on success. */
int dp_parse_arp_ips(const uint8_t *pkt, uint32_t len,
                     uint32_t *spa, uint32_t *tpa);

/* Standard monitor line for every ARP frame reaching userspace. */
void dp_log_arp_userspace(const char *dir, const char *iface,
                          const uint8_t *pkt, uint32_t len,
                          const char *bridge_to);

/* Log before L2 ARP encrypt (pkt still plain 0x0806). */
void dp_log_arp_encrypt(const char *dir, const char *iface,
                        const uint8_t *pkt, uint32_t len,
                        int policy_db_id, int policy_pkt_tag,
                        const char *egress_ifname);

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt);

#endif
