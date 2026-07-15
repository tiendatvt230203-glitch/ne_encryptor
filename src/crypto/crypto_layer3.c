#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/core/config.h"
#include "../../inc/crypto/crypto_pqc_layer.h"
#include <string.h>

#define MIN_ETH_PKT        (ETH_HEADER_SIZE + 8)
#define IPV4_HDR_SIZE      20
#define IPV4_PROTO_OFF     (ETH_HEADER_SIZE + 9)
#define IPV4_TOTLEN_OFF    (ETH_HEADER_SIZE + 2)

static int pkt_is_ipv4(const uint8_t *packet, size_t pkt_len) {
    if (pkt_len < ETH_HEADER_SIZE + IPV4_HDR_SIZE)
        return 0;
    return ((((uint16_t)packet[12] << 8) | packet[13]) == 0x0800);
}

static int ipv4_hdr_len_at(const uint8_t *packet, size_t pkt_len, int l3_off) {
    if (pkt_len < (size_t)l3_off + 20)
        return -1;
    int ihl = (packet[l3_off] & 0x0F) * 4;
    if (ihl < 20 || pkt_len < (size_t)(l3_off + ihl))
        return -1;
    return ihl;
}

/* Patch totlen and/or protocol with RFC 1624 incremental checksum (no full header walk). */
static void l3_patch_ipv4_fast(uint8_t *ip, uint16_t new_totlen, uint8_t new_proto) {
    uint16_t old_totlen = ((uint16_t)ip[2] << 8) | ip[3];
    uint8_t old_proto = ip[9];
    uint16_t old_ttl_proto = ((uint16_t)ip[8] << 8) | old_proto;
    uint16_t new_ttl_proto = ((uint16_t)ip[8] << 8) | new_proto;

    if (old_totlen != new_totlen) {
        ip[2] = (uint8_t)(new_totlen >> 8);
        ip[3] = (uint8_t)(new_totlen & 0xFF);
        crypto_ipv4_checksum_replace_word(ip, old_totlen, new_totlen);
    }
    if (old_proto != new_proto) {
        ip[9] = new_proto;
        crypto_ipv4_checksum_replace_word(ip, old_ttl_proto, new_ttl_proto);
    }
}

static void l3_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L3_FRAG_MAGIC;
}

static int l3_is_frag_tunnel(const uint8_t *tunnel, int nonce_size) {
    return tunnel[nonce_size + 1] == CRYPTO_L3_FRAG_MAGIC;
}

static void l3_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

static void l3_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

static int verify_decrypted_payload(const uint8_t *payload, size_t len, uint8_t orig_proto) {
    if (orig_proto == 6 || orig_proto == 17) {
        if (len < 4)
            return 0;
        uint16_t src_port = ((uint16_t)payload[0] << 8) | payload[1];
        uint16_t dst_port = ((uint16_t)payload[2] << 8) | payload[3];
        if (src_port == 0 && dst_port == 0)
            return 0;
    }
    return 1;
}

int crypto_layer3_frag_meta_len(void) {
    int meta = packet_crypto_get_tunnel_hdr_size() + CRYPTO_L3_FRAG_TAG_SIZE;
    if (crypto_mode_uses_gcm_tag())
        meta += AES_GCM_TAG_SIZE;
    return meta;
}

int crypto_layer3_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT)
        return -1;
    if (!pkt_is_ipv4(packet, pkt_len))
        return (int)pkt_len;

    int ip_hdr_len = ipv4_hdr_len_at(packet, pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return -1;

    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int nonce_size = packet_crypto_get_nonce_size();
    /* Only skip already-wrapped L3 frags (fake IP proto). Plain UDP/TCP can
     * accidentally match FRAG_MAGIC at tunnel_off+nonce_size+1 (~1/256). */
    if (packet[IPV4_PROTO_OFF] == packet_crypto_get_fake_protocol() &&
        pkt_len >= (size_t)(tunnel_off + nonce_size + 2) &&
        l3_is_frag_tunnel(packet + tunnel_off, nonce_size))
        return (int)pkt_len;

    uint8_t *ip = packet + ETH_HEADER_SIZE;
    uint16_t old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];
    uint8_t fake_proto = packet_crypto_get_fake_protocol();

    if (crypto_mode_is_pqc()) {
        const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
        const int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        uint8_t orig_proto = packet[IPV4_PROTO_OFF];
        size_t payload_len = pkt_len - (size_t)tunnel_off;
        int new_len = 0;
        int enc_off = tunnel_off + tunnel_hdr_size;

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

        int total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
        l3_patch_ipv4_fast(ip, old_totlen + (uint16_t)total_overhead, fake_proto);
        return (int)(pkt_len + (size_t)total_overhead);
    }

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    uint8_t orig_proto = packet[IPV4_PROTO_OFF];
    size_t payload_len = pkt_len - (size_t)tunnel_off;
    int enc_off = tunnel_off + tunnel_hdr_size;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);

    /* Memmove once to make room for tunnel, then encrypt (same order as L2). */
    memmove(packet + enc_off, packet + tunnel_off, payload_len);
    crypto_write_l3_tunnel_header(packet + tunnel_off, nonce, nonce_size,
                                  packet_crypto_get_policy_id(), orig_proto);

    if (is_gcm) {
        uint8_t tag[AES_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off, (int)payload_len,
                                   tag) != 0)
            return -1;
        memcpy(packet + enc_off + payload_len, tag, AES_GCM_TAG_SIZE);
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)payload_len) != 0)
            return -1;
    }

    int total_overhead = tunnel_hdr_size + (is_gcm ? AES_GCM_TAG_SIZE : 0);
    l3_patch_ipv4_fast(ip, old_totlen + (uint16_t)total_overhead, fake_proto);

    return (int)(pkt_len + (size_t)total_overhead);
}

int crypto_layer3_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT)
        return -1;
    if (!pkt_is_ipv4(packet, pkt_len))
        return (int)pkt_len;

    int ip_hdr_len = ipv4_hdr_len_at(packet, pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return (int)pkt_len;

    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int nonce_size = packet_crypto_get_nonce_size();
    uint8_t *ip = packet + ETH_HEADER_SIZE;
    uint16_t old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size))
        return (int)pkt_len;

    if (packet[tunnel_off + nonce_size + 1] == CRYPTO_L3_FRAG_MAGIC)
        return (int)pkt_len;

    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    if (packet[IPV4_PROTO_OFF] != fake_proto)
        return (int)pkt_len;

    if (crypto_mode_is_pqc()) {
        const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
        crypto_pqc_sess_t pqc;
        uint8_t orig_proto;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int dec_len = 0;

        if (crypto_pqc_sess_load(ctx, &pqc) != 0)
            return -1;
        crypto_read_l3_tunnel_header(packet + tunnel_off, pqc_nonce_size,
                                     nonce, NULL, NULL, &orig_proto);

        int enc_off = tunnel_off + tunnel_hdr_size;
        size_t total_after_tunnel = pkt_len - (size_t)enc_off;
        if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                       (int)total_after_tunnel, &dec_len) != 0)
            return -1;

        memmove(packet + tunnel_off, packet + enc_off, (size_t)dec_len);
        l3_patch_ipv4_fast(ip, old_totlen - (uint16_t)(tunnel_hdr_size + AES_GCM_TAG_SIZE),
                           orig_proto);
        return (int)(pkt_len - (size_t)(tunnel_hdr_size + AES_GCM_TAG_SIZE));
    }

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    uint8_t orig_proto;
    uint8_t nonce[16];
    crypto_read_l3_tunnel_header(packet + tunnel_off, nonce_size,
                                 nonce, NULL, NULL, &orig_proto);

    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;
    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t total_after_tunnel = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];

    if (is_gcm) {
        if (total_after_tunnel < AES_GCM_TAG_SIZE)
            return -1;
        enc_len = total_after_tunnel - AES_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);
    } else {
        enc_len = total_after_tunnel;
    }

    int total_overhead = tunnel_hdr_size + (is_gcm ? AES_GCM_TAG_SIZE : 0);
    uint8_t *work_ptr = packet + enc_off;

    if (is_gcm) {
        /* Match L2 hot path: AEAD authenticates; try CURRENT only (no backup copy). */
        const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
        if (!key)
            return -1;
        if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0)
            return -1;
        memmove(packet + tunnel_off, work_ptr, enc_len);
        l3_patch_ipv4_fast(ip, old_totlen - (uint16_t)total_overhead, orig_proto);
        return (int)(pkt_len - (size_t)total_overhead);
    }

    /* CTR: trial PREV/NEXT needs a ciphertext snapshot. */
    {
        uint8_t backup[2048];
        int has_backup = (enc_len <= sizeof(backup));
        int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

        if (has_backup)
            memcpy(backup, work_ptr, enc_len);

        for (int k = 0; k < KEY_SLOT_COUNT; k++) {
            const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
            uint8_t iv[AES128_IV_SIZE];

            if (!key)
                continue;
            if (k > 0 && has_backup)
                memcpy(work_ptr, backup, enc_len);

            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0)
                continue;
            if (!verify_decrypted_payload(work_ptr, enc_len, orig_proto))
                continue;

            memmove(packet + tunnel_off, work_ptr, enc_len);
            l3_patch_ipv4_fast(ip, old_totlen - (uint16_t)total_overhead, orig_proto);
            return (int)(pkt_len - (size_t)total_overhead);
        }
    }
    return -1;
}

int crypto_layer3_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len) {
    if (!ctx || !ctx->initialized || !eth_hdr || !ip_hdr || !enc_plain || !out_buf || !out_len)
        return -1;
    if (enc_plain_len == 0 || ip_hdr_len < 20)
        return -1;

    uint8_t fake_proto = packet_crypto_get_fake_protocol();

    if (crypto_mode_is_pqc()) {
        int nonce_size = CRYPTO_PQC_NONCE_BYTES;
        int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
        int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
        int enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;
        size_t need = (size_t)enc_off + enc_plain_len + AES_GCM_TAG_SIZE;

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

        size_t ip_payload_len = (size_t)(tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE + new_len);
        l3_patch_ipv4_fast(out_buf + ETH_HEADER_SIZE,
                           (uint16_t)(ip_hdr_len + ip_payload_len), fake_proto);
        *out_len = (uint32_t)(enc_off + new_len);
        return 0;
    }

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;
    size_t need = (size_t)enc_off + enc_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0);

    if (need > out_max)
        return -1;

    memcpy(out_buf, eth_hdr, ETH_HEADER_SIZE);
    memcpy(out_buf + ETH_HEADER_SIZE, ip_hdr, (size_t)ip_hdr_len);

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    packet_crypto_update_keys(ctx);
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    memmove(out_buf + enc_off, enc_plain, enc_plain_len);
    l3_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
    l3_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

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

    size_t ip_payload_len = (size_t)(tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE + enc_plain_len +
                                     (is_gcm ? AES_GCM_TAG_SIZE : 0));
    l3_patch_ipv4_fast(out_buf + ETH_HEADER_SIZE,
                       (uint16_t)(ip_hdr_len + ip_payload_len), fake_proto);

    *out_len = (uint32_t)need;
    return 0;
}

int crypto_layer3_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len)
{
    uint8_t *ip;
    int tunnel_off;
    int enc_off;
    int tunnel_hdr_size;
    uint8_t fake_proto;
    size_t need;

    if (!ctx || !ctx->initialized || !packet || !out_len || ip_hdr_len < 20 ||
        frag0_plain_len < (uint32_t)ip_hdr_len)
        return -1;

    ip = packet + ETH_HEADER_SIZE;
    fake_proto = packet_crypto_get_fake_protocol();
    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;

    if (crypto_mode_is_pqc()) {
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;

        need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;
        if (need > out_max)
            return -1;

        /* Slide IP||L4||half1 forward; clear IP at [Eth..] stays put. */
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

    {
        int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
        int nonce_size = packet_crypto_get_nonce_size();
        uint32_t counter;
        uint8_t nonce[16];
        int nonce_len;
        const uint8_t *key;

        need = (size_t)enc_off + frag0_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0);
        if (need > out_max)
            return -1;

        memmove(packet + enc_off, ip, frag0_plain_len);

        counter = packet_crypto_next_counter();
        crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
        packet_crypto_update_keys(ctx);
        key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
        if (!key)
            return -1;

        l3_write_tunnel_header_frag(packet + tunnel_off, nonce, nonce_size);
        l3_write_frag_tag(packet + tunnel_off + tunnel_hdr_size, pkt_id, 0);

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

        l3_patch_ipv4_fast(ip,
                           (uint16_t)(ip_hdr_len + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE +
                                      frag0_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0)),
                           fake_proto);
        *out_len = (uint32_t)need;
        return 0;
    }
}

int crypto_layer3_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;

    if (!pkt_is_ipv4(packet, pkt_len))
        return -1;

    int ip_hdr_len = ipv4_hdr_len_at(packet, pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return -1;

    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    if (packet[IPV4_PROTO_OFF] != fake_proto)
        return -1;

    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;

    if (pkt_len < (size_t)enc_off)
        return -1;
    if (!l3_is_frag_tunnel(packet + tunnel_off, nonce_size))
        return -1;

    l3_read_frag_tag(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    if (crypto_mode_is_pqc()) {
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

    uint8_t nonce[16];
    memcpy(nonce, packet + tunnel_off, nonce_size);

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    size_t total_after = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];

    if (is_gcm) {
        if (total_after < AES_GCM_TAG_SIZE)
            return -1;
        enc_len = total_after - AES_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);
    } else {
        enc_len = total_after;
    }

    /* Match L2 frag decrypt: try CURRENT/PREV/NEXT with ciphertext snapshot. */
    {
        uint8_t backup[2048];
        int has_backup = (enc_len <= sizeof(backup));
        int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

        if (has_backup)
            memcpy(backup, packet + enc_off, enc_len);

        for (int k = 0; k < KEY_SLOT_COUNT; k++) {
            const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
            uint8_t *work = packet + enc_off;

            if (!key)
                continue;
            if (k > 0 && has_backup)
                memcpy(work, backup, enc_len);

            if (is_gcm) {
                if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work, (int)enc_len, tag) != 0)
                    continue;
            } else {
                uint8_t iv[AES128_IV_SIZE];
                crypto_nonce_to_iv(nonce, nonce_size, iv);
                if (crypto_aes_ctr_with_key(key, iv, work, (int)enc_len) != 0)
                    continue;
            }

            memmove(packet + tunnel_off, packet + enc_off, enc_len);
            return (int)(tunnel_off + enc_len);
        }
    }
    return -1;
}
