#ifndef CRYPTO_LAYER2_INTERNAL_H
#define CRYPTO_LAYER2_INTERNAL_H

#include "crypto_layer2.h"
#include <string.h>

#define L2_FRAG_MAGIC      0x5B
#define MIN_ETH_PKT        (ETH_HEADER_SIZE + 8)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

void l2_write_wire_header(uint8_t *packet, int et_off, uint8_t policy_id,
                          const uint8_t *nonce, int nonce_size);
int l2_restore_plain_packet(uint8_t *packet, size_t pkt_len,
                            const uint8_t *payload, size_t payload_len);
void l2_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index);
void l2_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index);
int l2_wire_nonce_size(void);
int l2_verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len);

int crypto_layer2_ctr_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int et_off, size_t payload_len);
int crypto_layer2_ctr_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer2_ctr_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, int et_off);
int crypto_layer2_ctr_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len, int et_off, int l3_off);
int crypto_layer2_ctr_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);

int crypto_layer2_gcm_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int et_off, size_t payload_len);
int crypto_layer2_gcm_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer2_gcm_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, int et_off);
int crypto_layer2_gcm_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len, int et_off, int l3_off);
int crypto_layer2_gcm_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);

int crypto_layer2_pqc_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int et_off, size_t payload_len);
int crypto_layer2_pqc_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer2_pqc_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, int et_off);
int crypto_layer2_pqc_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len, int et_off, int l3_off);
int crypto_layer2_pqc_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);


#endif
