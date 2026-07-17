#define _POSIX_C_SOURCE 199309L

#include "../../../../../inc/crypto/crypto_option.h"
#include "../../../../../inc/crypto/eth_parse.h"
#include "../../../../../inc/core/interface.h"
#include "../../../../../inc/core/cpu_map.h"
#include "../../common/opt_no_frag_ops.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

/* wire — local to this option */
#define OPT_IS_PQC          0
#define OPT_AES_BITS        128
#define OPT_NONCE_SIZE      PACKET_CRYPTO_NONCE_BYTES

static int opt_policy_match(const struct app_config *cfg, int action, int mode,
                            int aes_bits, uint8_t wire_id)
{
    if (!cfg)
        return 0;
    for (int i = 0; i < cfg->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        const struct crypto_policy *cp = &cfg->policies[i];
        if (!cp || cp->action != action)
            continue;
        if (cp->crypto_mode != mode)
            continue;
        if (cp->aes_bits != aes_bits)
            continue;
        if ((uint8_t)cp->id == wire_id)
            return 1;
    }
    return 0;
}

static int opt_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto,
                                  size_t remaining)
{
    if (ip_proto == 6) {
        if (remaining < 20)
            return -1;
        int data_off = ((transport_hdr[12] >> 4) & 0x0F) * 4;
        if (data_off < 20 || (size_t)data_off > remaining)
            return -1;
        return data_off;
    }
    if (ip_proto == 17) {
        if (remaining < 8)
            return -1;
        return 8;
    }
    if (ip_proto == 1) {
        if (remaining < 4)
            return -1;
        return 4;
    }
    return -1;
}

#define L4_WIRE_PORT_LEN        4
#define L4_FRAG_MAGIC           0x5A
#define L4_TUNNEL_MAGIC         0xA5
#define L4_FRAG_TAG_SIZE        4
#define L4_TUNNEL_HDR_SIZE      (PACKET_CRYPTO_NONCE_BYTES + 2)

static void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size,
                                   uint8_t policy_id)
{
    memcpy(buf, nonce, (size_t)nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = L4_TUNNEL_MAGIC;
}

static int l4_is_tunnel_header(const uint8_t *buf, int nonce_size)
{
    if (buf[nonce_size + 1] != L4_TUNNEL_MAGIC)
        return 0;
    if (OPT_IS_PQC == 0 && (buf[0] & 0x80) != 0)
        return 0;
    return 1;
}

static void l4_fix_ipv4_totlen_and_cksum(uint8_t *packet, int l3_off, int ip_hdr_len,
                                         size_t ip_payload_len)
{
    uint8_t *ip = packet + l3_off;
    uint16_t old_totlen = ((uint16_t)ip[2] << 8) | ip[3];
    uint16_t new_totlen = (uint16_t)(ip_hdr_len + ip_payload_len);
    (void)ip_hdr_len;
    if (old_totlen == new_totlen)
        return;
    ip[2] = (uint8_t)(new_totlen >> 8);
    ip[3] = (uint8_t)(new_totlen & 0xFF);
    crypto_ipv4_checksum_replace_word(ip, old_totlen, new_totlen);
}

static int l4_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int l3_off, int ip_hdr_len, int plain_off, size_t plain_len)
{
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    int tunnel_off = plain_off;
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE;
    uint8_t iv[AES128_IV_SIZE];
    int total_overhead;
    size_t ip_payload_len;

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    memmove(packet + enc_off, packet + plain_off, plain_len);
    l4_write_tunnel_header(packet + tunnel_off, nonce, PACKET_CRYPTO_NONCE_BYTES, ctx->wire_id);
    crypto_nonce_to_iv(nonce, PACKET_CRYPTO_NONCE_BYTES, iv);
    if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)plain_len, OPT_AES_BITS) != 0)
        return -1;
    total_overhead = L4_TUNNEL_HDR_SIZE;
    ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + plain_len;
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
    return (int)(pkt_len + (size_t)total_overhead);

}

static int l4_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int l3_off, int ip_hdr_len, int transport_off, int tunnel_off)
{
    uint8_t nonce[16];
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE;
    size_t enc_len = pkt_len - (size_t)enc_off;
    uint8_t *work_ptr = packet + enc_off;
    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int new_len;
    size_t ip_payload_len;

    memcpy(nonce, packet + tunnel_off, PACKET_CRYPTO_NONCE_BYTES);
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
        memmove(packet + transport_off + L4_WIRE_PORT_LEN, work_ptr, enc_len);
        new_len = (int)(pkt_len - (size_t)L4_TUNNEL_HDR_SIZE);
        ip_payload_len = (size_t)(new_len - l3_off - ip_hdr_len);
        l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
        return new_len;
    }
    return -1;

}

static int tcp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    uint8_t ip_proto;
    int ip_hdr_len;
    int transport_off;
    size_t remaining;
    int transport_hdr_size;
    int plain_off;
    size_t plain_len;
    int n;

    if (!ctx || !ctx->initialized || !pkt)
        return -1;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    if (l3_off < 0)
        return 0;
    if (*pkt_len < (uint32_t)l3_off + 20)
        return -1;
    ip_proto = pkt[l3_off + 9];
    ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    transport_off = l3_off + ip_hdr_len;
    if (*pkt_len < (uint32_t)transport_off)
        return -1;
    remaining = *pkt_len - (size_t)transport_off;
    transport_hdr_size = opt_transport_hdr_size(pkt + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0)
        return 0;
    plain_off = transport_off + L4_WIRE_PORT_LEN;
    plain_len = *pkt_len - (size_t)plain_off;
    if (plain_len == 0)
        return 0;
    n = l4_do_encrypt(ctx, pkt, *pkt_len, l3_off, ip_hdr_len, plain_off, plain_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int tcp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    uint8_t ip_proto;
    int ip_hdr_len;
    int transport_off;
    int tunnel_off;
    int n;

    if (!ctx || !ctx->initialized || !pkt)
        return -1;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    if (l3_off < 0)
        return 0;
    if (*pkt_len < (uint32_t)l3_off + 20)
        return -1;
    ip_proto = pkt[l3_off + 9];
    ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    transport_off = l3_off + ip_hdr_len;
    if (*pkt_len < (uint32_t)transport_off)
        return -1;
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return 0;
    tunnel_off = transport_off + L4_WIRE_PORT_LEN;
    if (*pkt_len < (uint32_t)(tunnel_off + L4_TUNNEL_HDR_SIZE) ||
        !l4_is_tunnel_header(pkt + tunnel_off, PACKET_CRYPTO_NONCE_BYTES))
        return 0;
    n = l4_do_decrypt(ctx, pkt, *pkt_len, l3_off, ip_hdr_len, transport_off, tunnel_off);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}
CRYPTO_OPS_PLAIN(crypto_opt_l4_ctr128_tcp_ops, tcp_encrypt, tcp_decrypt)
