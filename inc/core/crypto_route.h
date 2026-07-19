#ifndef CRYPTO_ROUTE_H
#define CRYPTO_ROUTE_H

#include "interface.h"
#include <stdint.h>

struct forwarder;

/* WAN pick: encrypted → sticky crypto worker; plain → DP_CRYPTO_WAN_PLAIN (-2). */
#define DP_CRYPTO_WAN_PLAIN (-2)

int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len);
int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);
int dp_bypass_pick_worker(const uint8_t *pkt, uint32_t len);

int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id);

void dp_crypto_worker_bind(int worker_idx);
int dp_crypto_current_worker_idx(void);

void dp_bypass_worker_bind(int worker_idx);
int dp_bypass_current_worker_idx(void);

#endif
