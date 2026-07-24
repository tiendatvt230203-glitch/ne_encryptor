#ifndef ARP_L2_OVERHEAD_H
#define ARP_L2_OVERHEAD_H

#include <stdint.h>

/*
 * ARP L2 wire without cipher (non-GCM256 modes).
 *
 * Attach:  [MACs|0x88B6|policy_id|core_id|nonce12|ARP body]
 * Detach:  restore plain Ethernet ARP (0x0806).
 * No orig_et trailer — 0x88B6 already means ARP.
 */

int arp_l2_overhead_attach(uint8_t *pkt, uint32_t *pkt_len, uint8_t policy_pkt_tag);
int arp_l2_overhead_detach(uint8_t *pkt, uint32_t *pkt_len);
int arp_l2_overhead_read_policy_id(const uint8_t *pkt, uint32_t pkt_len, uint8_t *policy_id_out);

#endif
