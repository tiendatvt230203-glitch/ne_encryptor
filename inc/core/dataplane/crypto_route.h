#ifndef CRYPTO_ROUTE_H
#define CRYPTO_ROUTE_H

#include "core/iface/interface.h"
#include <stdint.h>

struct forwarder;

int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len);

int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id);

void dp_crypto_worker_bind(int worker_idx);
int dp_crypto_current_worker_idx(void);

/* Bypass TX affinity: hash → TX slot (RX/TX cores only). Not a crypto worker. */
int dp_pick_tx_slot(const uint8_t *pkt, uint32_t len);
void dp_out_ring_bind(int ring_idx);
int dp_out_ring_idx(void);

#endif
