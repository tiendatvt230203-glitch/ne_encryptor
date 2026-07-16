#include "../../inc/crypto/crypto_layer3_internal.h"
#include "../../inc/core/config.h"
#include "../../inc/crypto/crypto_pqc_layer.h"

/* ---------- PQC ---------- */

int crypto_layer3_pqc_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, uint8_t *ip,
                                     uint16_t old_totlen, uint8_t fake_proto)
{
    const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
    const int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    uint8_t orig_proto = packet[IPV4_PROTO_OFF];
    size_t payload_len = pkt_len - (size_t)tunnel_off;
    int new_len = 0;
    int enc_off = tunnel_off + tunnel_hdr_size;
    int total_overhead;

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    memmove(packet + enc_off, packet + tunnel_off, payload_len);
    crypto_write_l3_tunnel_header(packet + tunnel_off, nonce, pqc_nonce_size,
                                  packet_crypto_get_policy_id(), orig_proto);

    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)payload_len, &new_len) != 0)
        return -1;

    total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
    l3_patch_ipv4_fast(ip, old_totlen + (uint16_t)total_overhead, fake_proto);
    return (int)(pkt_len + (size_t)total_overhead);
}

int crypto_layer3_pqc_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, int tunnel_hdr_size,
                                     uint8_t *ip, uint16_t old_totlen)
{
    const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    uint8_t orig_proto;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;
    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t total_after_tunnel = pkt_len - (size_t)enc_off;

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    crypto_read_l3_tunnel_header(packet + tunnel_off, pqc_nonce_size,
                                 nonce, NULL, NULL, &orig_proto);

    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)total_after_tunnel, &dec_len) != 0)
        return -1;

    memmove(packet + tunnel_off, packet + enc_off, (size_t)dec_len);
    l3_patch_ipv4_fast(ip, old_totlen - (uint16_t)(tunnel_hdr_size + AES_GCM_TAG_SIZE),
                       orig_proto);
    return (int)(pkt_len - (size_t)(tunnel_hdr_size + AES_GCM_TAG_SIZE));
}

int crypto_layer3_pqc_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, uint8_t fake_proto)
{
    int nonce_size = CRYPTO_PQC_NONCE_BYTES;
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    size_t need = (size_t)enc_off + enc_plain_len + AES_GCM_TAG_SIZE;
    size_t ip_payload_len;

    if (need > out_max)
        return -1;

    memcpy(out_buf, eth_hdr, ETH_HEADER_SIZE);
    memcpy(out_buf + ETH_HEADER_SIZE, ip_hdr, (size_t)ip_hdr_len);

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    memmove(out_buf + enc_off, enc_plain, enc_plain_len);
    l3_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
    l3_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

    if (crypto_pqc_encrypt_payload(&pqc, nonce, out_buf + enc_off, (int)enc_plain_len, &new_len) != 0)
        return -1;

    ip_payload_len = (size_t)(tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE + new_len);
    l3_patch_ipv4_fast(out_buf + ETH_HEADER_SIZE,
                       (uint16_t)(ip_hdr_len + ip_payload_len), fake_proto);
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

int crypto_layer3_pqc_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, int tunnel_off, int enc_off, int tunnel_hdr_size, uint8_t fake_proto)
{
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    size_t need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;

    if (need > out_max)
        return -1;

    memmove(packet + enc_off, ip, frag0_plain_len);

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    l3_write_tunnel_header_frag(packet + tunnel_off, nonce, CRYPTO_PQC_NONCE_BYTES);
    l3_write_frag_tag(packet + tunnel_off + tunnel_hdr_size, pkt_id, 0);

    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)frag0_plain_len, &new_len) != 0)
        return -1;

    l3_patch_ipv4_fast(ip,
                       (uint16_t)(ip_hdr_len + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE +
                                  new_len),
                       fake_proto);
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

int crypto_layer3_pqc_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int tunnel_off, int enc_off)
{
    int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;

    memcpy(nonce, packet + tunnel_off, pqc_nonce_size);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
        return -1;
    memmove(packet + tunnel_off, packet + enc_off, (size_t)dec_len);
    return (int)(tunnel_off + dec_len);
}
