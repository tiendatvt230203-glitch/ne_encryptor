#ifndef CRYPTO_LAYER3_H
#define CRYPTO_LAYER3_H

#include "packet_crypto.h"

#define CRYPTO_L3_FRAG_MAGIC     0x5C
#define CRYPTO_L3_FRAG_TAG_SIZE  4

int crypto_layer3_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer3_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

int crypto_layer3_frag_meta_len(void);

int crypto_layer3_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);

/* Cut+encrypt frag0 on the original UMEM frame (after frag1 was carved out). */
int crypto_layer3_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len);

int crypto_layer3_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);

#endif
