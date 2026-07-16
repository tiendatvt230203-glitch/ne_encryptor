#include "../../inc/crypto/crypto_layer2_internal.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/config.h"
#include <string.h>

static __thread uint8_t tls_l2_worker_idx;

void crypto_layer2_bind_worker_idx(uint8_t worker_idx)
{
    tls_l2_worker_idx = worker_idx;
}

uint8_t crypto_layer2_worker_idx(void)
{
    return tls_l2_worker_idx;
}

int crypto_layer2_policy_off(const uint8_t *packet, size_t pkt_len)
{
    int et_off = crypto_eth_inner_et_off(packet, pkt_len);

    if (et_off < 0)
        return -1;
    if (pkt_len < (size_t)(et_off + 2 + CRYPTO_L2_POLICY_LEN))
        return -1;
    return et_off + 2;
}

int crypto_layer2_core_id_off(const uint8_t *packet, size_t pkt_len)
{
    int off = crypto_layer2_policy_off(packet, pkt_len);

    if (off < 0)
        return -1;
    return off + CRYPTO_L2_POLICY_LEN;
}

int crypto_layer2_nonce_off(const uint8_t *packet, size_t pkt_len)
{
    int off = crypto_layer2_core_id_off(packet, pkt_len);

    if (off < 0)
        return -1;
    return off + CRYPTO_L2_CORE_ID_LEN;
}

int crypto_layer2_enc_start_off(const uint8_t *packet, size_t pkt_len, int nonce_size)
{
    int off = crypto_layer2_nonce_off(packet, pkt_len);

    if (off < 0 || nonce_size < 0)
        return -1;
    if (pkt_len < (size_t)(off + nonce_size))
        return -1;
    return off + nonce_size;
}

int crypto_layer2_frag_magic_off(const uint8_t *packet, size_t pkt_len, int nonce_size)
{
    return crypto_layer2_enc_start_off(packet, pkt_len, nonce_size);
}

int crypto_layer2_has_fake_ethertype(const uint8_t *packet, size_t pkt_len)
{
    int et_off = crypto_eth_inner_et_off(packet, pkt_len);
    uint16_t fake;
    uint16_t et;

    if (et_off < 0)
        return 0;
    fake = packet_crypto_get_fake_ethertype_ipv4();
    if (!fake)
        return 0;
    et = (uint16_t)(((uint16_t)packet[et_off] << 8) | packet[et_off + 1]);
    return et == fake;
}

int crypto_layer2_read_policy_id(const uint8_t *packet, size_t pkt_len, uint8_t *policy_id_out)
{
    int off = crypto_layer2_policy_off(packet, pkt_len);

    if (off < 0 || !policy_id_out)
        return -1;
    *policy_id_out = packet[off];
    return 0;
}

int crypto_layer2_wire_prefix_len(const uint8_t *packet, size_t pkt_len)
{
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);

    if (et_off < 0)
        return -1;
    return et_off + 2;
}

void l2_write_wire_header(uint8_t *packet, int et_off, uint8_t policy_id,
                                 const uint8_t *nonce, int nonce_size)
{
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();

    packet[et_off] = (uint8_t)(fake >> 8);
    packet[et_off + 1] = (uint8_t)(fake & 0xFF);
    packet[et_off + 2] = policy_id;
    packet[et_off + 3] = crypto_layer2_worker_idx();
    memcpy(packet + et_off + 4, nonce, (size_t)nonce_size);
}

int crypto_layer2_read_worker_idx(const uint8_t *packet, uint32_t pkt_len, uint8_t *worker_idx_out)
{
    int core_off;

    if (!packet || !worker_idx_out)
        return -1;
    if (!crypto_layer2_has_fake_ethertype(packet, pkt_len))
        return -1;
    core_off = crypto_layer2_core_id_off(packet, pkt_len);
    if (core_off < 0)
        return -1;
    *worker_idx_out = packet[core_off];
    return 0;
}

int l2_wire_nonce_size(void)
{
    return PACKET_CRYPTO_NONCE_BYTES;
}

int l2_verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len)
{
    if (unlikely(len < 20))
        return 0;
    uint8_t ttl   = ip_payload[8];
    uint8_t proto = ip_payload[9];
    if (unlikely(ttl == 0))
        return 0;
    if (proto == 1 || proto == 2 || proto == 6 || proto == 17 ||
        proto == 47 || proto == 50 || proto == 51 || proto == 58 ||
        proto == 89 || proto == 132)
        return 1;
    return 0;
}

int crypto_layer2_wire_eth_len(void)
{
    return ETH_HEADER_SIZE;
}

int crypto_layer2_frag_meta_len(void)
{
    int mode = packet_crypto_get_mode();
    int nonce_size;
    int meta;

    if (mode == CRYPTO_MODE_PQC)
        nonce_size = CRYPTO_PQC_NONCE_BYTES;
    else
        nonce_size = PACKET_CRYPTO_NONCE_BYTES;

    meta = CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size + 1 + CRYPTO_L2_FRAG_TAG_SIZE;
    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC)
        meta += AES_GCM_TAG_SIZE;
    return meta;
}

int l2_restore_plain_packet(uint8_t *packet, size_t pkt_len,
                                   const uint8_t *payload, size_t payload_len)
{
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    int l3_off;

    if (et_off < 0)
        return -1;
    l3_off = et_off + 2;
    if (payload_len >= 2 && payload[0] == 0x08 && payload[1] == 0x00) {
        crypto_eth_set_ipv4_et(packet, et_off);
        memmove(packet + l3_off, payload + 2, payload_len - 2);
        return l3_off + (int)payload_len - 2;
    }
    crypto_eth_set_ipv4_et(packet, et_off);
    memmove(packet + l3_off, payload, payload_len);
    return l3_off + (int)payload_len;
}

void l2_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index)
{
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

void l2_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index)
{
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

/* ---------- Public dispatchers ---------- */

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int l3_off;
    int et_off;
    size_t payload_len;

    if (unlikely(!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(packet, pkt_len))
        return (int)pkt_len;
    if (!packet_crypto_get_fake_ethertype_ipv4())
        return (int)pkt_len;

    l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    if (l3_off < 0 || et_off < 0)
        return -1;

    payload_len = pkt_len - (size_t)l3_off;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer2_ctr_encrypt(ctx, packet, pkt_len, l3_off, et_off, payload_len);
    case CRYPTO_MODE_GCM:
        return crypto_layer2_gcm_encrypt(ctx, packet, pkt_len, l3_off, et_off, payload_len);
    case CRYPTO_MODE_PQC:
        return crypto_layer2_pqc_encrypt(ctx, packet, pkt_len, l3_off, et_off, payload_len);
    default:
        return -1;
    }
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    if (unlikely(!ctx || !ctx->initialized || !packet))
        return -1;
    if (!crypto_layer2_has_fake_ethertype(packet, pkt_len))
        return (int)pkt_len;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer2_ctr_decrypt(ctx, packet, pkt_len);
    case CRYPTO_MODE_GCM:
        return crypto_layer2_gcm_decrypt(ctx, packet, pkt_len);
    case CRYPTO_MODE_PQC:
        return crypto_layer2_pqc_decrypt(ctx, packet, pkt_len);
    default:
        return -1;
    }
}

int crypto_layer2_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len)
{
    int et_off;

    if (!ctx || !ctx->initialized || !eth_hdr || !enc_plain || !out_buf || !out_len)
        return -1;
    if (enc_plain_len == 0)
        return -1;
    if (!packet_crypto_get_fake_ethertype_ipv4())
        return -1;

    et_off = crypto_eth_l2_prefix_len(eth_hdr, ETH_L2_HDR_MAX);
    if (et_off < 0)
        return -1;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer2_ctr_encrypt_fragment_single(ctx, eth_hdr, enc_plain, enc_plain_len,
                                                         pkt_id, frag_index, out_buf, out_max,
                                                         out_len, et_off);
    case CRYPTO_MODE_GCM:
        return crypto_layer2_gcm_encrypt_fragment_single(ctx, eth_hdr, enc_plain, enc_plain_len,
                                                         pkt_id, frag_index, out_buf, out_max,
                                                         out_len, et_off);
    case CRYPTO_MODE_PQC:
        return crypto_layer2_pqc_encrypt_fragment_single(ctx, eth_hdr, enc_plain, enc_plain_len,
                                                         pkt_id, frag_index, out_buf, out_max,
                                                         out_len, et_off);
    default:
        return -1;
    }
}

int crypto_layer2_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len)
{
    int et_off;
    int l3_off;

    if (!ctx || !ctx->initialized || !packet || !out_len || frag0_plain_len == 0)
        return -1;
    if (!packet_crypto_get_fake_ethertype_ipv4())
        return -1;

    et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (et_off < 0 || l3_off < 0)
        return -1;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer2_ctr_encrypt_fragment0_inplace(ctx, packet, pkt_len, frag0_plain_len,
                                                           pkt_id, out_max, out_len, et_off, l3_off);
    case CRYPTO_MODE_GCM:
        return crypto_layer2_gcm_encrypt_fragment0_inplace(ctx, packet, pkt_len, frag0_plain_len,
                                                           pkt_id, out_max, out_len, et_off, l3_off);
    case CRYPTO_MODE_PQC:
        return crypto_layer2_pqc_encrypt_fragment0_inplace(ctx, packet, pkt_len, frag0_plain_len,
                                                           pkt_id, out_max, out_len, et_off, l3_off);
    default:
        return -1;
    }
}

int crypto_layer2_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index)
{
    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;
    if (!crypto_layer2_has_fake_ethertype(packet, pkt_len))
        return -1;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer2_ctr_decrypt_fragment(ctx, packet, pkt_len, out_pkt_id, out_frag_index);
    case CRYPTO_MODE_GCM:
        return crypto_layer2_gcm_decrypt_fragment(ctx, packet, pkt_len, out_pkt_id, out_frag_index);
    case CRYPTO_MODE_PQC:
        return crypto_layer2_pqc_decrypt_fragment(ctx, packet, pkt_len, out_pkt_id, out_frag_index);
    default:
        return -1;
    }
}
