#ifndef CRYPTO_LAYER4_H
#define CRYPTO_LAYER4_H

#include "packet_crypto.h"

#define CRYPTO_L4_TUNNEL_MAGIC  0xA5
#define CRYPTO_L4_FRAG_MAGIC    0x5A

int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len);

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

int crypto_layer4_fixup_packet(uint8_t *packet, size_t pkt_len);

int crypto_layer4_get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto,
                                         size_t remaining);

int crypto_layer4_wire_port_len(void);

int crypto_layer4_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);

/* Cut+encrypt frag0 on the original UMEM frame (after frag1 was carved out). */
int crypto_layer4_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len);

int crypto_layer4_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);
int crypto_layer4_frag_meta_len(void);
#endif
