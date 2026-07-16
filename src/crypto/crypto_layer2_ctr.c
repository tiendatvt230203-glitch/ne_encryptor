#include "../../inc/crypto/crypto_layer2_internal.h"

/* ---------- CTR ---------- */

int crypto_layer2_ctr_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int et_off, size_t payload_len)
{
    const int nonce_size = PACKET_CRYPTO_NONCE_BYTES;
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    int enc_start;
    uint8_t iv[AES128_IV_SIZE];
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);

    enc_start = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size;
    if (pkt_len < (size_t)enc_start)
        return -1;

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    memmove(packet + enc_start, packet + l3_off, payload_len);
    l2_write_wire_header(packet, et_off, packet_crypto_get_policy_id(), nonce, nonce_size);

    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (unlikely(crypto_aes_ctr_with_key(key, iv, packet + enc_start, (int)payload_len) != 0))
        return -1;
    return enc_start + (int)payload_len;
}

int crypto_layer2_ctr_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int wire_ns = l2_wire_nonce_size();
    int enc_start;
    int nonce_off;
    uint8_t nonce[16];
    size_t enc_len;
    uint8_t iv[AES128_IV_SIZE];
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t *work_ptr;

    enc_start = crypto_layer2_enc_start_off(packet, pkt_len, wire_ns);
    if (enc_start < 0)
        return -1;

    nonce_off = crypto_layer2_nonce_off(packet, pkt_len);
    if (nonce_off < 0)
        return -1;
    memcpy(nonce, packet + nonce_off, (size_t)wire_ns);

    enc_len = pkt_len - (size_t)enc_start;
    work_ptr = packet + enc_start;

    crypto_nonce_to_iv(nonce, wire_ns, iv);
    if (unlikely(crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0))
        return -1;
    if (unlikely(!l2_verify_ipv4_after_decrypt(work_ptr, enc_len)))
        return -1;

    return l2_restore_plain_packet(packet, pkt_len, work_ptr, enc_len);
}

int crypto_layer2_ctr_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, int et_off)
{
    int nonce_size = PACKET_CRYPTO_NONCE_BYTES;
    size_t need;
    uint32_t counter;
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    int enc_off;
    int frag_magic_off;
    uint8_t iv[AES128_IV_SIZE];

    enc_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size +
              1 + CRYPTO_L2_FRAG_TAG_SIZE;
    need = (size_t)enc_off + enc_plain_len;
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

    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (crypto_aes_ctr_with_key(key, iv, out_buf + enc_off, (int)enc_plain_len) != 0)
        return -1;

    *out_len = (uint32_t)(enc_off + enc_plain_len);
    return 0;
}

int crypto_layer2_ctr_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len, int et_off, int l3_off)
{
    int nonce_size = PACKET_CRYPTO_NONCE_BYTES;
    uint32_t counter;
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    int enc_off;
    int frag_magic_off;
    size_t need;
    uint8_t iv[AES128_IV_SIZE];

    (void)pkt_len;
    enc_off = et_off + 2 + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + nonce_size +
              1 + CRYPTO_L2_FRAG_TAG_SIZE;
    need = (size_t)enc_off + frag0_plain_len;
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

    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)frag0_plain_len) != 0)
        return -1;

    *out_len = (uint32_t)need;
    return 0;
}

int crypto_layer2_ctr_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index)
{
    int wire_ns = l2_wire_nonce_size();
    size_t enc_len;
    uint8_t backup[2048];
    int has_backup;
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int nonce_off;
    int enc_off;
    int frag_magic_off;
    int l3_off;

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

    enc_len = pkt_len - (size_t)enc_off;

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
        uint8_t iv[AES128_IV_SIZE];
        uint8_t *work = packet + enc_off;

        if (!key)
            continue;
        if (k > 0 && has_backup)
            memcpy(work, backup, enc_len);

        memcpy(nonce, packet + nonce_off, (size_t)wire_ns);
        crypto_nonce_to_iv(nonce, wire_ns, iv);
        if (crypto_aes_ctr_with_key(key, iv, work, (int)enc_len) != 0)
            continue;

        memmove(packet + l3_off, packet + enc_off, enc_len);
        return l3_off + (int)enc_len;
    }
    return -1;
}
