#include "../../inc/crypto/crypto_layer3_internal.h"
#include "../../inc/core/config.h"

int l3_pkt_is_ipv4(const uint8_t *packet, size_t pkt_len) {
    if (pkt_len < ETH_HEADER_SIZE + IPV4_HDR_SIZE)
        return 0;
    return ((((uint16_t)packet[12] << 8) | packet[13]) == 0x0800);
}

int l3_ipv4_hdr_len_at(const uint8_t *packet, size_t pkt_len, int l3_off) {
    if (pkt_len < (size_t)l3_off + 20)
        return -1;
    int ihl = (packet[l3_off] & 0x0F) * 4;
    if (ihl < 20 || pkt_len < (size_t)(l3_off + ihl))
        return -1;
    return ihl;
}

/* Patch totlen and/or protocol with RFC 1624 incremental checksum (no full header walk). */
void l3_patch_ipv4_fast(uint8_t *ip, uint16_t new_totlen, uint8_t new_proto) {
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

void l3_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L3_FRAG_MAGIC;
}

int l3_is_frag_tunnel(const uint8_t *tunnel, int nonce_size) {
    return tunnel[nonce_size + 1] == CRYPTO_L3_FRAG_MAGIC;
}

void l3_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

void l3_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int l3_verify_decrypted_payload(const uint8_t *payload, size_t len, uint8_t orig_proto) {
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
    int mode = packet_crypto_get_mode();
    int meta = packet_crypto_get_tunnel_hdr_size() + CRYPTO_L3_FRAG_TAG_SIZE;

    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC)
        meta += AES_GCM_TAG_SIZE;
    return meta;
}

int crypto_layer3_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    int ip_hdr_len;
    int tunnel_off;
    int nonce_size;
    uint8_t *ip;
    uint16_t old_totlen;
    uint8_t fake_proto;

    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT)
        return -1;
    if (!l3_pkt_is_ipv4(packet, pkt_len))
        return (int)pkt_len;

    ip_hdr_len = l3_ipv4_hdr_len_at(packet, pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return -1;

    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    nonce_size = packet_crypto_get_nonce_size();
    /* Only skip already-wrapped L3 frags (fake IP proto). Plain UDP/TCP can
     * accidentally match FRAG_MAGIC at tunnel_off+nonce_size+1 (~1/256). */
    if (packet[IPV4_PROTO_OFF] == packet_crypto_get_fake_protocol() &&
        pkt_len >= (size_t)(tunnel_off + nonce_size + 2) &&
        l3_is_frag_tunnel(packet + tunnel_off, nonce_size))
        return (int)pkt_len;

    ip = packet + ETH_HEADER_SIZE;
    old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];
    fake_proto = packet_crypto_get_fake_protocol();

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer3_ctr_encrypt(ctx, packet, pkt_len, tunnel_off, ip,
                                         old_totlen, fake_proto);
    case CRYPTO_MODE_GCM:
        return crypto_layer3_gcm_encrypt(ctx, packet, pkt_len, tunnel_off, ip,
                                         old_totlen, fake_proto);
    case CRYPTO_MODE_PQC:
        return crypto_layer3_pqc_encrypt(ctx, packet, pkt_len, tunnel_off, ip,
                                         old_totlen, fake_proto);
    default:
        return -1;
    }
}

int crypto_layer3_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    int ip_hdr_len;
    int tunnel_off;
    int tunnel_hdr_size;
    int nonce_size;
    uint8_t *ip;
    uint16_t old_totlen;
    uint8_t fake_proto;

    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT)
        return -1;
    if (!l3_pkt_is_ipv4(packet, pkt_len))
        return (int)pkt_len;

    ip_hdr_len = l3_ipv4_hdr_len_at(packet, pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return (int)pkt_len;

    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    nonce_size = packet_crypto_get_nonce_size();
    ip = packet + ETH_HEADER_SIZE;
    old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size))
        return (int)pkt_len;

    if (packet[tunnel_off + nonce_size + 1] == CRYPTO_L3_FRAG_MAGIC)
        return (int)pkt_len;

    fake_proto = packet_crypto_get_fake_protocol();
    if (packet[IPV4_PROTO_OFF] != fake_proto)
        return (int)pkt_len;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer3_ctr_decrypt(ctx, packet, pkt_len, tunnel_off, tunnel_hdr_size,
                                         nonce_size, ip, old_totlen);
    case CRYPTO_MODE_GCM:
        return crypto_layer3_gcm_decrypt(ctx, packet, pkt_len, tunnel_off, tunnel_hdr_size,
                                         nonce_size, ip, old_totlen);
    case CRYPTO_MODE_PQC:
        return crypto_layer3_pqc_decrypt(ctx, packet, pkt_len, tunnel_off, tunnel_hdr_size,
                                         ip, old_totlen);
    default:
        return -1;
    }
}

int crypto_layer3_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len) {
    uint8_t fake_proto;

    if (!ctx || !ctx->initialized || !eth_hdr || !ip_hdr || !enc_plain || !out_buf || !out_len)
        return -1;
    if (enc_plain_len == 0 || ip_hdr_len < 20)
        return -1;

    fake_proto = packet_crypto_get_fake_protocol();

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer3_ctr_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                                         enc_plain, enc_plain_len, pkt_id,
                                                         frag_index, out_buf, out_max, out_len,
                                                         fake_proto);
    case CRYPTO_MODE_GCM:
        return crypto_layer3_gcm_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                                         enc_plain, enc_plain_len, pkt_id,
                                                         frag_index, out_buf, out_max, out_len,
                                                         fake_proto);
    case CRYPTO_MODE_PQC:
        return crypto_layer3_pqc_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                                         enc_plain, enc_plain_len, pkt_id,
                                                         frag_index, out_buf, out_max, out_len,
                                                         fake_proto);
    default:
        return -1;
    }
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

    if (!ctx || !ctx->initialized || !packet || !out_len || ip_hdr_len < 20 ||
        frag0_plain_len < (uint32_t)ip_hdr_len)
        return -1;

    ip = packet + ETH_HEADER_SIZE;
    fake_proto = packet_crypto_get_fake_protocol();
    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer3_ctr_encrypt_fragment0_inplace(ctx, packet, ip_hdr_len,
                                                           frag0_plain_len, pkt_id, out_max,
                                                           out_len, ip, tunnel_off, enc_off,
                                                           tunnel_hdr_size, fake_proto);
    case CRYPTO_MODE_GCM:
        return crypto_layer3_gcm_encrypt_fragment0_inplace(ctx, packet, ip_hdr_len,
                                                           frag0_plain_len, pkt_id, out_max,
                                                           out_len, ip, tunnel_off, enc_off,
                                                           tunnel_hdr_size, fake_proto);
    case CRYPTO_MODE_PQC:
        return crypto_layer3_pqc_encrypt_fragment0_inplace(ctx, packet, ip_hdr_len,
                                                           frag0_plain_len, pkt_id, out_max,
                                                           out_len, ip, tunnel_off, enc_off,
                                                           tunnel_hdr_size, fake_proto);
    default:
        return -1;
    }
}

int crypto_layer3_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    int ip_hdr_len;
    uint8_t fake_proto;
    int tunnel_off;
    int nonce_size;
    int tunnel_hdr_size;
    int enc_off;

    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;

    if (!l3_pkt_is_ipv4(packet, pkt_len))
        return -1;

    ip_hdr_len = l3_ipv4_hdr_len_at(packet, pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return -1;

    fake_proto = packet_crypto_get_fake_protocol();
    if (packet[IPV4_PROTO_OFF] != fake_proto)
        return -1;

    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    nonce_size = packet_crypto_get_nonce_size();
    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    enc_off = tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE;

    if (pkt_len < (size_t)enc_off)
        return -1;
    if (!l3_is_frag_tunnel(packet + tunnel_off, nonce_size))
        return -1;

    l3_read_frag_tag(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer3_ctr_decrypt_fragment(ctx, packet, pkt_len, tunnel_off, enc_off,
                                                  nonce_size);
    case CRYPTO_MODE_GCM:
        return crypto_layer3_gcm_decrypt_fragment(ctx, packet, pkt_len, tunnel_off, enc_off,
                                                  nonce_size);
    case CRYPTO_MODE_PQC:
        return crypto_layer3_pqc_decrypt_fragment(ctx, packet, pkt_len, tunnel_off, enc_off);
    default:
        return -1;
    }
}
