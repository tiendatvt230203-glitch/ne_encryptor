#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/config.h"
#include "../../inc/crypto/crypto_pqc_layer.h"
#include <string.h>

#define L2_FRAG_MAGIC      0x5B
#define MIN_ETH_PKT        (ETH_HEADER_SIZE + 8)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

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

static void l2_write_wire_header(uint8_t *packet, int et_off, uint8_t policy_id,
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

static inline int l2_wire_nonce_size(void)
{
    return PACKET_CRYPTO_NONCE_BYTES;
}

static inline int verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len)
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
    int nonce_size = packet_crypto_get_nonce_size();
    int meta = CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size + 1 + CRYPTO_L2_FRAG_TAG_SIZE;
    if (crypto_mode_uses_gcm_tag())
        meta += AES_GCM_TAG_SIZE;
    return meta;
}

static int l2_restore_plain_packet(uint8_t *packet, size_t pkt_len,
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

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int l3_off;
    int et_off;
    int enc_start;
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

    if (crypto_mode_is_pqc()) {
        const int nonce_size = CRYPTO_PQC_NONCE_BYTES;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;

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

    {
        const int nonce_size = packet_crypto_get_nonce_size();
        uint32_t counter = packet_crypto_next_counter();
        uint8_t nonce[16];
        int nonce_len;
        const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
        const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);

        enc_start = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size;
        if (pkt_len < (size_t)enc_start)
            return -1;

        crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
        memmove(packet + enc_start, packet + l3_off, payload_len);
        l2_write_wire_header(packet, et_off, packet_crypto_get_policy_id(), nonce, nonce_size);

        if (likely(is_gcm)) {
            uint8_t tag[AES_GCM_TAG_SIZE];
            if (unlikely(crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                                packet + enc_start, (int)payload_len, tag) != 0))
                return -1;
            memcpy(packet + enc_start + payload_len, tag, AES_GCM_TAG_SIZE);
            return enc_start + (int)payload_len + AES_GCM_TAG_SIZE;
        }

        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (unlikely(crypto_aes_ctr_with_key(key, iv, packet + enc_start, (int)payload_len) != 0))
            return -1;
        return enc_start + (int)payload_len;
    }
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int enc_start;
    int wire_ns = l2_wire_nonce_size();

    if (unlikely(!ctx || !ctx->initialized || !packet))
        return -1;
    if (!crypto_layer2_has_fake_ethertype(packet, pkt_len))
        return (int)pkt_len;

    enc_start = crypto_layer2_enc_start_off(packet, pkt_len, wire_ns);
    if (enc_start < 0)
        return -1;

    /*
     * Do not treat ciphertext[0]==L2_FRAG_MAGIC as a fragment here: that byte is the
     * first ciphertext byte on non-frag frames (~1/256 false positive). Fragments are
     * handled by crypto_layer2_decrypt_fragment(); if a frag lands here GCM fails and
     * the dataplane falls back to the fragment path.
     */

    if (crypto_mode_is_pqc()) {
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

    {
        int nonce_off = crypto_layer2_nonce_off(packet, pkt_len);
        uint8_t nonce[16];
        const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
        const int nonce_len = is_gcm ? wire_ns : AES128_IV_SIZE;
        size_t enc_len = pkt_len - (size_t)enc_start;
        uint8_t tag[AES_GCM_TAG_SIZE];
        const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
        uint8_t *work_ptr = packet + enc_start;

        if (nonce_off < 0)
            return -1;
        memcpy(nonce, packet + nonce_off, (size_t)wire_ns);

        if (is_gcm) {
            if (unlikely(pkt_len < (size_t)(enc_start + AES_GCM_TAG_SIZE)))
                return -1;
            enc_len -= AES_GCM_TAG_SIZE;
            memcpy(tag, packet + enc_start + enc_len, AES_GCM_TAG_SIZE);
        }

        if (likely(is_gcm)) {
            if (unlikely(crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0))
                return -1;
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, wire_ns, iv);
            if (unlikely(crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0))
                return -1;
            if (unlikely(!verify_ipv4_after_decrypt(work_ptr, enc_len)))
                return -1;
        }

        return l2_restore_plain_packet(packet, pkt_len, work_ptr, enc_len);
    }
}

static void l2_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index)
{
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

static void l2_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index)
{
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int crypto_layer2_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len)
{
    int et_off;
    int enc_off;
    int frag_magic_off;

    if (!ctx || !ctx->initialized || !eth_hdr || !enc_plain || !out_buf || !out_len)
        return -1;
    if (enc_plain_len == 0)
        return -1;
    if (!packet_crypto_get_fake_ethertype_ipv4())
        return -1;

    et_off = crypto_eth_l2_prefix_len(eth_hdr, ETH_L2_HDR_MAX);
    if (et_off < 0)
        return -1;

    if (crypto_mode_is_pqc()) {
        int nonce_size = CRYPTO_PQC_NONCE_BYTES;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;
        size_t need;

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

    {
        int nonce_size = packet_crypto_get_nonce_size();
        int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
        size_t need;
        uint32_t counter;
        uint8_t nonce[16];
        int nonce_len;
        const uint8_t *key;

        enc_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size +
                  1 + CRYPTO_L2_FRAG_TAG_SIZE;
        need = (size_t)enc_off + enc_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0);
        if (need > out_max)
            return -1;

        memcpy(out_buf, eth_hdr, (size_t)et_off);
        counter = packet_crypto_next_counter();
        crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

        packet_crypto_update_keys(ctx);
        key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
        if (!key)
            return -1;

        memmove(out_buf + enc_off, enc_plain, enc_plain_len);
        l2_write_wire_header(out_buf, et_off, packet_crypto_get_policy_id(), nonce, nonce_size);
        frag_magic_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size;
        out_buf[frag_magic_off] = L2_FRAG_MAGIC;
        l2_write_frag_tag(out_buf + frag_magic_off + 1, pkt_id, frag_index);

        if (is_gcm) {
            uint8_t tag[AES_GCM_TAG_SIZE];
            if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, out_buf + enc_off, (int)enc_plain_len,
                                       tag) != 0)
                return -1;
            memcpy(out_buf + enc_off + enc_plain_len, tag, AES_GCM_TAG_SIZE);
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, out_buf + enc_off, (int)enc_plain_len) != 0)
                return -1;
        }

        *out_len = (uint32_t)(enc_off + enc_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0));
        return 0;
    }
}

int crypto_layer2_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len)
{
    int et_off;
    int l3_off;
    int enc_off;
    int frag_magic_off;
    size_t need;

    if (!ctx || !ctx->initialized || !packet || !out_len || frag0_plain_len == 0)
        return -1;
    if (!packet_crypto_get_fake_ethertype_ipv4())
        return -1;

    et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (et_off < 0 || l3_off < 0)
        return -1;

    if (crypto_mode_is_pqc()) {
        int nonce_size = CRYPTO_PQC_NONCE_BYTES;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;

        enc_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size +
                  1 + CRYPTO_L2_FRAG_TAG_SIZE;
        need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;
        if (need > out_max)
            return -1;

        /* Eth stays; slide IP||… forward to make room for L2 frag wire meta. */
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

    {
        int nonce_size = packet_crypto_get_nonce_size();
        int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
        uint32_t counter;
        uint8_t nonce[16];
        int nonce_len;
        const uint8_t *key;

        enc_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size +
                  1 + CRYPTO_L2_FRAG_TAG_SIZE;
        need = (size_t)enc_off + frag0_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0);
        if (need > out_max)
            return -1;

        memmove(packet + enc_off, packet + l3_off, frag0_plain_len);

        counter = packet_crypto_next_counter();
        crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
        packet_crypto_update_keys(ctx);
        key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
        if (!key)
            return -1;

        l2_write_wire_header(packet, et_off, packet_crypto_get_policy_id(), nonce, nonce_size);
        frag_magic_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size;
        packet[frag_magic_off] = L2_FRAG_MAGIC;
        l2_write_frag_tag(packet + frag_magic_off + 1, pkt_id, 0);

        if (is_gcm) {
            uint8_t tag[AES_GCM_TAG_SIZE];
            if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off,
                                       (int)frag0_plain_len, tag) != 0)
                return -1;
            memcpy(packet + enc_off + frag0_plain_len, tag, AES_GCM_TAG_SIZE);
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)frag0_plain_len) != 0)
                return -1;
        }

        *out_len = (uint32_t)need;
        return 0;
    }
}

int crypto_layer2_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index)
{
    int enc_off;
    int frag_magic_off;
    int l3_off;

    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;
    if (!crypto_layer2_has_fake_ethertype(packet, pkt_len))
        return -1;

    if (crypto_mode_is_pqc()) {
        int nonce_size = CRYPTO_PQC_NONCE_BYTES;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int dec_len = 0;

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

    {
        int wire_ns = l2_wire_nonce_size();
        int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
        int nonce_len = is_gcm ? wire_ns : AES128_IV_SIZE;
        size_t total_after;
        size_t enc_len;
        uint8_t tag[AES_GCM_TAG_SIZE];
        uint8_t backup[2048];
        int has_backup;
        int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
        int nonce_off;

        frag_magic_off = crypto_layer2_frag_magic_off(packet, pkt_len, wire_ns);
        if (frag_magic_off < 0 || packet[frag_magic_off] != L2_FRAG_MAGIC)
            return -1;
        enc_off = frag_magic_off + 1 + CRYPTO_L2_FRAG_TAG_SIZE;
        if (pkt_len < (size_t)enc_off)
            return -1;

        l2_read_frag_tag(packet + frag_magic_off + 1, out_pkt_id, out_frag_index);

        nonce_off = crypto_layer2_nonce_off(packet, pkt_len);
        if (nonce_off < 0)
            return -1;

        total_after = pkt_len - (size_t)enc_off;
        if (is_gcm) {
            if (total_after < AES_GCM_TAG_SIZE)
                return -1;
            enc_len = total_after - AES_GCM_TAG_SIZE;
            memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);
        } else {
            enc_len = total_after;
        }

        has_backup = (enc_len <= sizeof(backup));
        if (has_backup)
            memcpy(backup, packet + enc_off, enc_len);

        l3_off = crypto_eth_l2_prefix_len(packet, pkt_len);
        if (l3_off < 0)
            return -1;
        l3_off += 2;

        for (int k = 0; k < KEY_SLOT_COUNT; k++) {
            const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
            uint8_t nonce[16];
            uint8_t *work = packet + enc_off;

            if (!key)
                continue;
            if (k > 0 && has_backup)
                memcpy(work, backup, enc_len);

            memcpy(nonce, packet + nonce_off, (size_t)wire_ns);

            if (is_gcm) {
                if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work, (int)enc_len, tag) != 0)
                    continue;
            } else {
                uint8_t iv[AES128_IV_SIZE];
                crypto_nonce_to_iv(nonce, wire_ns, iv);
                if (crypto_aes_ctr_with_key(key, iv, work, (int)enc_len) != 0)
                    continue;
            }

            memmove(packet + l3_off, packet + enc_off, enc_len);
            return l3_off + (int)enc_len;
        }
    }
    return -1;
}