#include "../../inc/crypto/crypto_layer3_internal.h"

/* ---------- CTR ---------- */

int crypto_layer3_ctr_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, uint8_t *ip,
                                     uint16_t old_totlen, uint8_t fake_proto)
{
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    uint8_t orig_proto = packet[IPV4_PROTO_OFF];
    size_t payload_len = pkt_len - (size_t)tunnel_off;
    int enc_off = tunnel_off + tunnel_hdr_size;
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t iv[AES128_IV_SIZE];
    int total_overhead;

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    memmove(packet + enc_off, packet + tunnel_off, payload_len);
    crypto_write_l3_tunnel_header(packet + tunnel_off, nonce, nonce_size,
                                  packet_crypto_get_policy_id(), orig_proto);

    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)payload_len) != 0)
        return -1;

    total_overhead = tunnel_hdr_size;
    l3_patch_ipv4_fast(ip, old_totlen + (uint16_t)total_overhead, fake_proto);
    return (int)(pkt_len + (size_t)total_overhead);
}

int crypto_layer3_ctr_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int tunnel_off, int tunnel_hdr_size,
                                     int nonce_size, uint8_t *ip, uint16_t old_totlen)
{
    uint8_t orig_proto;
    uint8_t nonce[16];
    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t enc_len = pkt_len - (size_t)enc_off;
    int total_overhead = tunnel_hdr_size;
    uint8_t *work_ptr = packet + enc_off;
    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    crypto_read_l3_tunnel_header(packet + tunnel_off, nonce_size,
                                 nonce, NULL, NULL, &orig_proto);

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
        if (!l3_verify_decrypted_payload(work_ptr, enc_len, orig_proto))
            continue;

        memmove(packet + tunnel_off, work_ptr, enc_len);
        l3_patch_ipv4_fast(ip, old_totlen - (uint16_t)total_overhead, orig_proto);
        return (int)(pkt_len - (size_t)total_overhead);
    }
    return -1;
}

int crypto_layer3_ctr_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, uint8_t fake_proto)
{
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;
    size_t need = (size_t)enc_off + enc_plain_len;
    uint32_t counter;
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    uint8_t iv[AES128_IV_SIZE];
    size_t ip_payload_len;

    if (need > out_max)
        return -1;

    memcpy(out_buf, eth_hdr, ETH_HEADER_SIZE);
    memcpy(out_buf + ETH_HEADER_SIZE, ip_hdr, (size_t)ip_hdr_len);

    counter = packet_crypto_next_counter();
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    packet_crypto_update_keys(ctx);
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    memmove(out_buf + enc_off, enc_plain, enc_plain_len);
    l3_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
    l3_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (crypto_aes_ctr_with_key(key, iv, out_buf + enc_off, (int)enc_plain_len) != 0)
        return -1;

    ip_payload_len = (size_t)(tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE + enc_plain_len);
    l3_patch_ipv4_fast(out_buf + ETH_HEADER_SIZE,
                       (uint16_t)(ip_hdr_len + ip_payload_len), fake_proto);

    *out_len = (uint32_t)need;
    return 0;
}

int crypto_layer3_ctr_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, int tunnel_off, int enc_off, int tunnel_hdr_size, uint8_t fake_proto)
{
    int nonce_size = packet_crypto_get_nonce_size();
    uint32_t counter;
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    uint8_t iv[AES128_IV_SIZE];
    size_t need = (size_t)enc_off + frag0_plain_len;

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

    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)frag0_plain_len) != 0)
        return -1;

    l3_patch_ipv4_fast(ip,
                       (uint16_t)(ip_hdr_len + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE +
                                  frag0_plain_len),
                       fake_proto);
    *out_len = (uint32_t)need;
    return 0;
}

int crypto_layer3_ctr_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int tunnel_off, int enc_off, int nonce_size)
{
    uint8_t nonce[16];
    size_t enc_len = pkt_len - (size_t)enc_off;
    uint8_t backup[2048];
    int has_backup;
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    memcpy(nonce, packet + tunnel_off, nonce_size);

    has_backup = (enc_len <= sizeof(backup));
    if (has_backup)
        memcpy(backup, packet + enc_off, enc_len);

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        uint8_t *work = packet + enc_off;
        uint8_t iv[AES128_IV_SIZE];

        if (!key)
            continue;
        if (k > 0 && has_backup)
            memcpy(work, backup, enc_len);

        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, work, (int)enc_len) != 0)
            continue;

        memmove(packet + tunnel_off, packet + enc_off, enc_len);
        return (int)(tunnel_off + enc_len);
    }
    return -1;
}

/* ---------- Public dispatchers ---------- */
