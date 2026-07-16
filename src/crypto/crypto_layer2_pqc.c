#include "../../inc/crypto/crypto_layer2_internal.h"
#include "../../inc/core/config.h"
#include "../../inc/crypto/crypto_pqc_layer.h"

/* ---------- PQC ---------- */

int crypto_layer2_pqc_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int et_off, size_t payload_len)
{
    const int nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    int enc_start;

    enc_start = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size;
    if (pkt_len < (size_t)enc_start)
        return -1;

    memmove(packet + enc_start, packet + l3_off, payload_len);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    l2_write_wire_header(packet, et_off, packet_crypto_get_policy_id(), nonce, nonce_size);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_start, (int)payload_len, &new_len) != 0)
        return -1;
    return enc_start + new_len;
}

int crypto_layer2_pqc_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;
    int pqc_enc_start;

    pqc_enc_start = crypto_layer2_enc_start_off(packet, pkt_len, pqc_nonce_size);
    if (pqc_enc_start < 0)
        return -1;

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + crypto_layer2_nonce_off(packet, pkt_len), (size_t)pqc_nonce_size);

    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + pqc_enc_start,
                                   (int)(pkt_len - (size_t)pqc_enc_start), &dec_len) != 0)
        return -1;

    return l2_restore_plain_packet(packet, pkt_len, packet + pqc_enc_start, (size_t)dec_len);
}

int crypto_layer2_pqc_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, int et_off)
{
    int nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    size_t need;
    int enc_off;
    int frag_magic_off;

    enc_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size +
              1 + CRYPTO_L2_FRAG_TAG_SIZE;
    need = (size_t)enc_off + enc_plain_len + AES_GCM_TAG_SIZE;
    if (need > out_max)
        return -1;

    memcpy(out_buf, eth_hdr, (size_t)et_off);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    memmove(out_buf + enc_off, enc_plain, enc_plain_len);
    l2_write_wire_header(out_buf, et_off, packet_crypto_get_policy_id(), nonce, nonce_size);
    frag_magic_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size;
    out_buf[frag_magic_off] = L2_FRAG_MAGIC;
    l2_write_frag_tag(out_buf + frag_magic_off + 1, pkt_id, frag_index);

    if (crypto_pqc_encrypt_payload(&pqc, nonce, out_buf + enc_off, (int)enc_plain_len, &new_len) != 0)
        return -1;

    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

int crypto_layer2_pqc_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len, int et_off, int l3_off)
{
    int nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int new_len = 0;
    int enc_off;
    int frag_magic_off;
    size_t need;

    (void)pkt_len;
    enc_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size +
              1 + CRYPTO_L2_FRAG_TAG_SIZE;
    need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;
    if (need > out_max)
        return -1;

    memmove(packet + enc_off, packet + l3_off, frag0_plain_len);

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;

    l2_write_wire_header(packet, et_off, packet_crypto_get_policy_id(), nonce, nonce_size);
    frag_magic_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size;
    packet[frag_magic_off] = L2_FRAG_MAGIC;
    l2_write_frag_tag(packet + frag_magic_off + 1, pkt_id, 0);

    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)frag0_plain_len, &new_len) != 0)
        return -1;

    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}

int crypto_layer2_pqc_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index)
{
    int nonce_size = CRYPTO_PQC_NONCE_BYTES;
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int dec_len = 0;
    int enc_off;
    int frag_magic_off;
    int l3_off;

    frag_magic_off = crypto_layer2_frag_magic_off(packet, pkt_len, nonce_size);
    if (frag_magic_off < 0 || packet[frag_magic_off] != L2_FRAG_MAGIC)
        return -1;
    enc_off = frag_magic_off + 1 + CRYPTO_L2_FRAG_TAG_SIZE;
    if (pkt_len < (size_t)enc_off)
        return -1;

    l2_read_frag_tag(packet + frag_magic_off + 1, out_pkt_id, out_frag_index);

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + crypto_layer2_nonce_off(packet, pkt_len), (size_t)nonce_size);

    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
        return -1;

    l3_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    if (l3_off < 0)
        return -1;
    l3_off += 2;
    memmove(packet + l3_off, packet + enc_off, (size_t)dec_len);
    return l3_off + dec_len;
}
