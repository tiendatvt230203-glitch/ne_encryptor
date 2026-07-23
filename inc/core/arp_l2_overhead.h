#ifndef ARP_L2_OVERHEAD_H
#define ARP_L2_OVERHEAD_H

#include <stdint.h>

/*
 * Independent ARP L2 wire overhead (no crypto_option / no cipher).
 *
 * Attach:  [MACs|0x88B5|policy_id|core_id|nonce12|ARP body|orig_et 0x0806]
 * Detach:  restore plain Ethernet ARP (0x0806).
 */

int arp_l2_overhead_attach(uint8_t *pkt, uint32_t *pkt_len, uint8_t policy_pkt_tag);
int arp_l2_overhead_detach(uint8_t *pkt, uint32_t *pkt_len);
int arp_l2_overhead_read_policy_id(const uint8_t *pkt, uint32_t pkt_len, uint8_t *policy_id_out);

#endif
