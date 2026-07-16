#ifndef CRYPTO_LAYER4_INTERNAL_H
#define CRYPTO_LAYER4_INTERNAL_H

#include "crypto_layer4.h"
#include "fragment.h"
#include <string.h>

#define L4_WIRE_PORT_LEN   4

void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size);
void l4_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size);
int l4_is_tunnel_header(const uint8_t *buf, int nonce_size);
int l4_get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto, size_t remaining);
void l4_fix_ipv4_totlen_and_cksum(uint8_t *packet, int l3_off, int ip_hdr_len, size_t ip_payload_len);
void l4_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index);
void l4_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index);

int crypto_layer4_ctr_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int plain_off, size_t plain_len);
int crypto_layer4_ctr_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int transport_off, int tunnel_off, int tunnel_hdr_size,
                                     int nonce_size);
int crypto_layer4_ctr_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);
int crypto_layer4_ctr_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, const uint8_t wire_ports[L4_WIRE_PORT_LEN],
    int tunnel_off, int enc_off, int tunnel_hdr_size);
int crypto_layer4_ctr_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int transport_off,
    int tunnel_off, int tunnel_hdr_size, int nonce_size);

int crypto_layer4_gcm_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int plain_off, size_t plain_len);
int crypto_layer4_gcm_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int transport_off, int tunnel_off, int tunnel_hdr_size,
                                     int nonce_size);
int crypto_layer4_gcm_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);
int crypto_layer4_gcm_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, const uint8_t wire_ports[L4_WIRE_PORT_LEN],
    int tunnel_off, int enc_off, int tunnel_hdr_size);
int crypto_layer4_gcm_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int transport_off,
    int tunnel_off, int tunnel_hdr_size, int nonce_size);

int crypto_layer4_pqc_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int plain_off, size_t plain_len);
int crypto_layer4_pqc_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int transport_off, int tunnel_off, int tunnel_hdr_size);
int crypto_layer4_pqc_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);
int crypto_layer4_pqc_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, const uint8_t wire_ports[L4_WIRE_PORT_LEN],
    int tunnel_off, int enc_off, int tunnel_hdr_size);
int crypto_layer4_pqc_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int transport_off,
    int tunnel_off, int tunnel_hdr_size);


#endif
