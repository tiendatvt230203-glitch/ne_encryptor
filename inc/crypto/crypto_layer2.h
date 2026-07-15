#ifndef CRYPTO_LAYER2_H
#define CRYPTO_LAYER2_H

#include "packet_crypto.h"
#include "eth_parse.h"

#define NE_L2_FAKE_ETHERTYPE     0x88B5u

#define CRYPTO_L2_FRAG_TAG_SIZE  4
#define CRYPTO_L2_FRAG_MAGIC     0x5B

/* Byte 12-13: NE_L2_FAKE_ETHERTYPE; byte 14: policy_id; byte 15: core_id; then nonce. */
#define CRYPTO_L2_POLICY_OFF     ETH_HEADER_SIZE
#define CRYPTO_L2_POLICY_LEN     1
#define CRYPTO_L2_CORE_ID_OFF    (CRYPTO_L2_POLICY_OFF + CRYPTO_L2_POLICY_LEN)
#define CRYPTO_L2_CORE_ID_LEN    1
#define CRYPTO_L2_NONCE_OFF      (CRYPTO_L2_CORE_ID_OFF + CRYPTO_L2_CORE_ID_LEN)

void crypto_layer2_bind_worker_idx(uint8_t worker_idx);
uint8_t crypto_layer2_worker_idx(void);

int crypto_layer2_read_worker_idx(const uint8_t *packet, uint32_t pkt_len, uint8_t *worker_idx_out);

int crypto_layer2_policy_off(const uint8_t *packet, size_t pkt_len);
int crypto_layer2_core_id_off(const uint8_t *packet, size_t pkt_len);
int crypto_layer2_nonce_off(const uint8_t *packet, size_t pkt_len);
int crypto_layer2_enc_start_off(const uint8_t *packet, size_t pkt_len, int nonce_size);
int crypto_layer2_frag_magic_off(const uint8_t *packet, size_t pkt_len, int nonce_size);
int crypto_layer2_has_fake_ethertype(const uint8_t *packet, size_t pkt_len);
int crypto_layer2_read_policy_id(const uint8_t *packet, size_t pkt_len, uint8_t *policy_id_out);
int crypto_layer2_wire_prefix_len(const uint8_t *packet, size_t pkt_len);

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

int crypto_layer2_wire_eth_len(void);
int crypto_layer2_frag_meta_len(void);

int crypto_layer2_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);

/* Cut+encrypt frag0 on the original UMEM frame (after frag1 was carved out). */
int crypto_layer2_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len);

int crypto_layer2_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);

#endif