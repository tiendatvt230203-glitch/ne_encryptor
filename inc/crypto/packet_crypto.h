#ifndef PACKET_CRYPTO_H
#define PACKET_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "aes_crypto.h"

#define ETH_HEADER_SIZE            14
#define PROTO_FLAG_IPV4            0
#define PACKET_CRYPTO_NONCE_BYTES  12
#define CRYPTO_PQC_NONCE_BYTES     PACKET_CRYPTO_NONCE_BYTES

#define KEY_SLOT_PREV         0
#define KEY_SLOT_CURRENT      1
#define KEY_SLOT_NEXT         2
#define KEY_SLOT_COUNT        3

struct packet_crypto_ctx {
    uint8_t master_key[AES_MAX_KEY_SIZE];
    uint8_t keys[KEY_SLOT_COUNT][AES_MAX_KEY_SIZE];
    bool initialized;
    int crypto_mode;
    int policy_id;   /* PQC diversify / internal; may be db_id */
    uint8_t wire_id; /* policy wire id written into packet headers */
    int profile_id;
    int aes_bits;
};

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t master_key[AES_MAX_KEY_SIZE],
                       int aes_bits);
void packet_crypto_cleanup(struct packet_crypto_ctx *ctx);

void packet_crypto_update_keys(struct packet_crypto_ctx *ctx);
void packet_crypto_refresh_pqc_keys(struct packet_crypto_ctx *ctx);

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot);

uint32_t packet_crypto_next_counter(void);
void packet_crypto_reset_counter(void);

void crypto_generate_nonce(uint32_t counter, uint8_t proto_flag,
                           uint8_t *out_nonce, int *out_nonce_len);
void crypto_nonce_to_iv(const uint8_t *nonce, int nonce_size,
                        uint8_t iv[AES128_IV_SIZE]);

#endif
