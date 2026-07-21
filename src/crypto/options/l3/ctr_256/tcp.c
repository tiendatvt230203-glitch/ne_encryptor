#include "../../../../../inc/crypto/crypto_option.h"
#include "../../../../../inc/crypto/eth_parse.h"
#include "../../../../../inc/core/interface.h"
#include "../../common/opt_no_frag_ops.h"

#include <string.h>

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

/* wire — local to this option */
#define OPT_FAKE_PROTOCOL   99
#define OPT_AES_BITS        256

#define L3_FRAG_MAGIC           0x5C
#define L3_TUNNEL_HDR_SIZE      (PACKET_CRYPTO_NONCE_BYTES + 2)
#define L3_IPV4_PROTO_OFF       (ETH_HEADER_SIZE + 9)
#define L3_IPV4_TOTLEN_OFF      (ETH_HEADER_SIZE + 2)

static int l3_pkt_is_ipv4(const uint8_t *packet, size_t pkt_len)
{
    if (pkt_len < ETH_HEADER_SIZE + 20)
        return 0;
    return ((((uint16_t)packet[12] << 8) | packet[13]) == 0x0800);
}

static int l3_ipv4_hdr_len_at(const uint8_t *packet, size_t pkt_len, int l3_off)
{
    if (pkt_len < (size_t)l3_off + 20)
        return -1;
    int ihl = (packet[l3_off] & 0x0F) * 4;
    if (ihl < 20 || pkt_len < (size_t)(l3_off + ihl))
        return -1;
    return ihl;
}

static void l3_patch_ipv4_fast(uint8_t *ip, uint16_t new_totlen, uint8_t new_proto)
{
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

static int l3_is_frag_tunnel(const uint8_t *tunnel, int nonce_size)
{
    return tunnel[nonce_size + 1] == L3_FRAG_MAGIC;
}

static int l3_verify_decrypted_payload(const uint8_t *payload, size_t len, uint8_t orig_proto)
{
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

static void l3_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size,
                                   uint8_t policy_id, uint8_t orig_proto)
{
    memcpy(buf, nonce, (size_t)nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = orig_proto;
}

static void l3_read_tunnel_header(const uint8_t *buf, int nonce_size, uint8_t *nonce_out,
                                  uint8_t *proto_flag, uint8_t *policy_id, uint8_t *orig_proto)
{
    memcpy(nonce_out, buf, (size_t)nonce_size);
    if (proto_flag)
        *proto_flag = buf[0] >> 7;
    if (policy_id)
        *policy_id = buf[nonce_size];
    if (orig_proto)
        *orig_proto = buf[nonce_size + 1];
}

static int l3_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int tunnel_off, uint8_t *ip, uint16_t old_totlen, uint8_t fake_proto)
{
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t orig_proto = packet[L3_IPV4_PROTO_OFF];
    size_t payload_len = pkt_len - (size_t)tunnel_off;
    int enc_off = tunnel_off + L3_TUNNEL_HDR_SIZE;
    uint8_t iv[AES128_IV_SIZE];
    int total_overhead;

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    memmove(packet + enc_off, packet + tunnel_off, payload_len);
    l3_write_tunnel_header(packet + tunnel_off, nonce, PACKET_CRYPTO_NONCE_BYTES,
                                  ctx->wire_id, orig_proto);
    crypto_nonce_to_iv(nonce, PACKET_CRYPTO_NONCE_BYTES, iv);
    if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)payload_len, OPT_AES_BITS) != 0)
        return -1;
    total_overhead = L3_TUNNEL_HDR_SIZE;
    l3_patch_ipv4_fast(ip, old_totlen + (uint16_t)total_overhead, fake_proto);
    return (int)(pkt_len + (size_t)total_overhead);

}

static int l3_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int tunnel_off, uint8_t *ip, uint16_t old_totlen)
{
    uint8_t orig_proto;
    uint8_t nonce[16];
    int enc_off = tunnel_off + L3_TUNNEL_HDR_SIZE;
    size_t enc_len = pkt_len - (size_t)enc_off;
    uint8_t *work_ptr = packet + enc_off;
    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    l3_read_tunnel_header(packet + tunnel_off, PACKET_CRYPTO_NONCE_BYTES,
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
        crypto_nonce_to_iv(nonce, PACKET_CRYPTO_NONCE_BYTES, iv);
        if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len, OPT_AES_BITS) != 0)
            continue;
        if (!l3_verify_decrypted_payload(work_ptr, enc_len, orig_proto))
            continue;
        memmove(packet + tunnel_off, work_ptr, enc_len);
        l3_patch_ipv4_fast(ip, old_totlen - (uint16_t)L3_TUNNEL_HDR_SIZE, orig_proto);
        return (int)(pkt_len - (size_t)L3_TUNNEL_HDR_SIZE);
    }
    return -1;

}

static int tcp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int ip_hdr_len;
    int tunnel_off;
    int n;
    uint8_t *ip;
    uint16_t old_totlen;
    uint8_t fake_proto;

    if (!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT)
        return -1;
    if (!l3_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    ip_hdr_len = l3_ipv4_hdr_len_at(pkt, *pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return -1;
    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    if (pkt[L3_IPV4_PROTO_OFF] == OPT_FAKE_PROTOCOL &&
        *pkt_len >= (uint32_t)(tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 2) &&
        l3_is_frag_tunnel(pkt + tunnel_off, PACKET_CRYPTO_NONCE_BYTES))
        return 0;
    ip = pkt + ETH_HEADER_SIZE;
    old_totlen = ((uint16_t)pkt[L3_IPV4_TOTLEN_OFF] << 8) | pkt[L3_IPV4_TOTLEN_OFF + 1];
    fake_proto = OPT_FAKE_PROTOCOL;
    n = l3_do_encrypt(ctx, pkt, *pkt_len, tunnel_off, ip, old_totlen, fake_proto);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int tcp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int ip_hdr_len;
    int tunnel_off;
    int n;
    uint8_t *ip;
    uint16_t old_totlen;

    if (!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT)
        return -1;
    if (!l3_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    ip_hdr_len = l3_ipv4_hdr_len_at(pkt, *pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return 0;
    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    if (*pkt_len < (uint32_t)(tunnel_off + L3_TUNNEL_HDR_SIZE))
        return 0;
    if (pkt[tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 1] == L3_FRAG_MAGIC)
        return 0;
    if (pkt[L3_IPV4_PROTO_OFF] != OPT_FAKE_PROTOCOL)
        return 0;
    ip = pkt + ETH_HEADER_SIZE;
    old_totlen = ((uint16_t)pkt[L3_IPV4_TOTLEN_OFF] << 8) | pkt[L3_IPV4_TOTLEN_OFF + 1];
    n = l3_do_decrypt(ctx, pkt, *pkt_len, tunnel_off, ip, old_totlen);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}
CRYPTO_OPS_PLAIN(crypto_opt_l3_ctr256_tcp_ops, tcp_encrypt, tcp_decrypt)
