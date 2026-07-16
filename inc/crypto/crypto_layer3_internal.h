#ifndef CRYPTO_LAYER3_INTERNAL_H
#define CRYPTO_LAYER3_INTERNAL_H

#include "crypto_layer3.h"
#include <string.h>

#define MIN_ETH_PKT        (ETH_HEADER_SIZE + 8)
#define IPV4_HDR_SIZE      20
#define IPV4_PROTO_OFF     (ETH_HEADER_SIZE + 9)
#define IPV4_TOTLEN_OFF    (ETH_HEADER_SIZE + 2)

int l3_pkt_is_ipv4(const uint8_t *packet, size_t pkt_len);
int l3_ipv4_hdr_len_at(const uint8_t *packet, size_t pkt_len, int l3_off);
void l3_patch_ipv4_fast(uint8_t *ip, uint16_t new_totlen, uint8_t new_proto);
void l3_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size);
int l3_is_frag_tunnel(const uint8_t *tunnel, int nonce_size);
void l3_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index);
void l3_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index);
int l3_verify_decrypted_payload(const uint8_t *payload, size_t len, uint8_t orig_proto);

int crypto_layer3_ctr_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, uint8_t *ip,
                                     uint16_t old_totlen, uint8_t fake_proto);
int crypto_layer3_ctr_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, int tunnel_hdr_size,
                                     int nonce_size, uint8_t *ip, uint16_t old_totlen);
int crypto_layer3_ctr_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, uint8_t fake_proto);
int crypto_layer3_ctr_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, int tunnel_off, int enc_off, int tunnel_hdr_size, uint8_t fake_proto);
int crypto_layer3_ctr_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int tunnel_off, int enc_off, int nonce_size);

int crypto_layer3_gcm_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, uint8_t *ip,
                                     uint16_t old_totlen, uint8_t fake_proto);
int crypto_layer3_gcm_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, int tunnel_hdr_size,
                                     int nonce_size, uint8_t *ip, uint16_t old_totlen);
int crypto_layer3_gcm_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, uint8_t fake_proto);
int crypto_layer3_gcm_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, int tunnel_off, int enc_off, int tunnel_hdr_size, uint8_t fake_proto);
int crypto_layer3_gcm_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int tunnel_off, int enc_off, int nonce_size);

int crypto_layer3_pqc_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, uint8_t *ip,
                                     uint16_t old_totlen, uint8_t fake_proto);
int crypto_layer3_pqc_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, int tunnel_hdr_size,
                                     uint8_t *ip, uint16_t old_totlen);
int crypto_layer3_pqc_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, uint8_t fake_proto);
int crypto_layer3_pqc_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, int tunnel_off, int enc_off, int tunnel_hdr_size, uint8_t fake_proto);
int crypto_layer3_pqc_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int tunnel_off, int enc_off);


#endif
