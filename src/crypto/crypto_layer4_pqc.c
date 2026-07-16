#include "../../inc/crypto/crypto_layer4_internal.h"
#include "../../inc/core/config.h"
#include "../../inc/crypto/crypto_pqc_layer.h"

/* ---------- PQC ---------- */

int crypto_layer4_pqc_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int plain_off, size_t plain_len)
{
    const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    int tunnel_off = plain_off;
    int enc_off = tunnel_off + tunnel_hdr_size;
    int total_overhead;
    size_t ip_payload_len;

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    memmove(packet + enc_off, packet + plain_off, plain_len);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off, (int)plain_len, &new_len) != 0)
        return -1;

    l4_write_tunnel_header(packet + tunnel_off, nonce, pqc_nonce_size);

    total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
    ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len;
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
    return (int)(pkt_len + (size_t)total_overhead);
}

int crypto_layer4_pqc_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int transport_off, int tunnel_off, int tunnel_hdr_size)
{
    const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;
    int enc_off = tunnel_off + tunnel_hdr_size;
    int total_overhead;
    int new_len;
    size_t ip_payload_len;

    memcpy(nonce, packet + tunnel_off, pqc_nonce_size);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
        return -1;

    memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
    total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
    new_len = (int)(pkt_len - (size_t)total_overhead);
    ip_payload_len = (size_t)(new_len - l3_off - ip_hdr_len);
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
    return new_len;
}

int crypto_layer4_pqc_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len)
{
    int nonce_size = CRYPTO_PQC_NONCE_BYTES;
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + AES_GCM_TAG_SIZE;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    size_t need = (size_t)(14 + ip_hdr_len + L4_WIRE_PORT_LEN + total_overhead + enc_plain_len);
    int offset;
    int tunnel_off;
    int enc_off;
    size_t ip_payload_len;

    if (need > out_max)
        return -1;

    offset = 0;
    memcpy(out_buf, eth_hdr, 14);
    offset += 14;
    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;
    memcpy(out_buf + offset, wire_ports, L4_WIRE_PORT_LEN);
    offset += L4_WIRE_PORT_LEN;

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    tunnel_off = offset;
    enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    memmove(out_buf + enc_off, enc_plain, enc_plain_len);

    l4_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
    l4_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

    if (crypto_pqc_encrypt_payload(&pqc, nonce, out_buf + enc_off, (int)enc_plain_len, &new_len) != 0)
        return -1;

    ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len;
    l4_fix_ipv4_totlen_and_cksum(out_buf, 14, ip_hdr_len, ip_payload_len);
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

int crypto_layer4_pqc_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, const uint8_t *wire_ports, int tunnel_off, int enc_off, int tunnel_hdr_size)
{
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + AES_GCM_TAG_SIZE;
    size_t need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;

    if (need > out_max)
        return -1;

    memmove(packet + enc_off, ip, frag0_plain_len);
    memcpy(packet + 14 + ip_hdr_len, wire_ports, L4_WIRE_PORT_LEN);

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    l4_write_tunnel_header_frag(packet + tunnel_off, nonce, CRYPTO_PQC_NONCE_BYTES);
    l4_write_frag_tag(packet + tunnel_off + tunnel_hdr_size, pkt_id, 0);

    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)frag0_plain_len, &new_len) != 0)
        return -1;

    l4_fix_ipv4_totlen_and_cksum(packet, 14, ip_hdr_len,
                                    L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len);
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

int crypto_layer4_pqc_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int transport_off, int tunnel_off, int tunnel_hdr_size)
{
    int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;

    memcpy(nonce, packet + tunnel_off, pqc_nonce_size);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
        return -1;
    memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
    return (int)(transport_off + L4_WIRE_PORT_LEN + dec_len);
}
