#include "../../inc/crypto/crypto_layer4_internal.h"

/* ---------- GCM ---------- */

int crypto_layer4_gcm_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int plain_off, size_t plain_len)
{
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    int tunnel_off = plain_off;
    int enc_off = tunnel_off + tunnel_hdr_size;
    uint8_t tag[AES_GCM_TAG_SIZE];
    int total_overhead;
    size_t ip_payload_len;

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    memmove(packet + enc_off, packet + plain_off, plain_len);
    l4_write_tunnel_header(packet + tunnel_off, nonce, nonce_size);

    if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off, (int)plain_len,
                               tag) != 0)
        return -1;
    memcpy(packet + enc_off + plain_len, tag, AES_GCM_TAG_SIZE);

    total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
    ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + plain_len;
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
    return (int)(pkt_len + (size_t)total_overhead);
}

int crypto_layer4_gcm_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                                     size_t pkt_len, int l3_off, int ip_hdr_len,
                                     int transport_off, int tunnel_off, int tunnel_hdr_size,
                                     int nonce_size)
{
    uint8_t nonce[16];
    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t total_after_tunnel = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];
    int total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
    uint8_t *work_ptr = packet + enc_off;
    const uint8_t *key;
    int new_len;
    size_t ip_payload_len;

    memcpy(nonce, packet + tunnel_off, nonce_size);

    if (total_after_tunnel < AES_GCM_TAG_SIZE)
        return -1;
    enc_len = total_after_tunnel - AES_GCM_TAG_SIZE;
    memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);

    /* Match L3: AEAD authenticates; try CURRENT only. */
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;
    if (crypto_aes_gcm_decrypt(key, nonce, nonce_size, work_ptr, (int)enc_len, tag) != 0)
        return -1;
    memmove(packet + transport_off + L4_WIRE_PORT_LEN, work_ptr, enc_len);
    new_len = (int)(pkt_len - (size_t)total_overhead);
    ip_payload_len = (size_t)(new_len - l3_off - ip_hdr_len);
    /* Payload bit-identical to pre-encrypt; L4 checksum stays valid. */
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
    return new_len;
}

int crypto_layer4_gcm_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len)
{
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + AES_GCM_TAG_SIZE;
    size_t need = (size_t)(14 + ip_hdr_len + L4_WIRE_PORT_LEN + total_overhead + enc_plain_len);
    int offset;
    uint32_t counter;
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    int tunnel_off;
    int enc_off;
    uint8_t tag[AES_GCM_TAG_SIZE];
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

    counter = packet_crypto_next_counter();
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    packet_crypto_update_keys(ctx);
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    tunnel_off = offset;
    enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    memmove(out_buf + enc_off, enc_plain, enc_plain_len);

    l4_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
    l4_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

    if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, out_buf + enc_off, (int)enc_plain_len,
                               tag) != 0)
        return -1;
    memcpy(out_buf + enc_off + enc_plain_len, tag, AES_GCM_TAG_SIZE);

    ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + enc_plain_len;
    l4_fix_ipv4_totlen_and_cksum(out_buf, 14, ip_hdr_len, ip_payload_len);

    *out_len = (uint32_t)(enc_off + enc_plain_len + AES_GCM_TAG_SIZE);
    return 0;
}

int crypto_layer4_gcm_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len,
    uint8_t *ip, const uint8_t *wire_ports, int tunnel_off, int enc_off, int tunnel_hdr_size)
{
    int nonce_size = packet_crypto_get_nonce_size();
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + AES_GCM_TAG_SIZE;
    uint32_t counter;
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    uint8_t tag[AES_GCM_TAG_SIZE];
    size_t need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;

    if (need > out_max)
        return -1;

    memmove(packet + enc_off, ip, frag0_plain_len);
    memcpy(packet + 14 + ip_hdr_len, wire_ports, L4_WIRE_PORT_LEN);

    counter = packet_crypto_next_counter();
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    packet_crypto_update_keys(ctx);
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    l4_write_tunnel_header_frag(packet + tunnel_off, nonce, nonce_size);
    l4_write_frag_tag(packet + tunnel_off + tunnel_hdr_size, pkt_id, 0);

    if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off,
                               (int)frag0_plain_len, tag) != 0)
        return -1;
    memcpy(packet + enc_off + frag0_plain_len, tag, AES_GCM_TAG_SIZE);

    l4_fix_ipv4_totlen_and_cksum(packet, 14, ip_hdr_len,
                                    L4_WIRE_PORT_LEN + (size_t)total_overhead + frag0_plain_len);
    *out_len = (uint32_t)need;
    return 0;
}

int crypto_layer4_gcm_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len, int transport_off, int tunnel_off, int tunnel_hdr_size,
    int nonce_size)
{
    uint8_t nonce[16];
    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    size_t total_after = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];
    uint8_t backup[2048];
    int has_backup;
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    memcpy(nonce, packet + tunnel_off, nonce_size);

    if (total_after < AES_GCM_TAG_SIZE)
        return -1;
    enc_len = total_after - AES_GCM_TAG_SIZE;
    memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);

    has_backup = (enc_len <= sizeof(backup));
    if (has_backup)
        memcpy(backup, packet + enc_off, enc_len);

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        uint8_t *work;

        if (!key)
            continue;

        work = packet + enc_off;
        if (k > 0 && has_backup)
            memcpy(work, backup, enc_len);

        if (crypto_aes_gcm_decrypt(key, nonce, nonce_size, work, (int)enc_len, tag) != 0)
            continue;

        memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, enc_len);
        return (int)(transport_off + L4_WIRE_PORT_LEN + enc_len);
    }
    return -1;
}
