#ifndef L4PQC_CRYPTO_H
#define L4PQC_CRYPTO_H

#include "l4pqc_rss.h"
#include "../../../inc/core/config.h"
#include "../../../inc/crypto/packet_crypto.h"

void l4pqc_crypto_set_static_key(const uint8_t *key, int len);
int  l4pqc_crypto_init_ctx(struct packet_crypto_ctx *ctx,
                           const struct l4pqc_config *cfg);
void l4pqc_stub_set_key(const uint8_t *key, int len);
void l4pqc_stub_cfg_init(uint8_t wire_id);
const struct app_config *l4pqc_stub_cfg(void);

#endif
