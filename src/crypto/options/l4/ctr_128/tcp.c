#include "../../../../../inc/crypto/crypto_option.h"
#include "../../../../../inc/crypto/eth_parse.h"
#include "../../../../../inc/core/interface.h"
#include "../../common/opt_no_frag_ops.h"

#include <string.h>

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

#define OPT_AES_BITS            128
#define L4_WIRE_PORT_LEN        4
#define L4_TUNNEL_MAGIC         0xA5
/* nonce | core_id | policy_id | marker */
#define L4_TUNNEL_HDR_SIZE      (PACKET_CRYPTO_NONCE_BYTES + 3)

static void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size,
                                   uint8_t policy_id)
{
    memcpy(buf, nonce, (size_t)nonce_size);
    buf[nonce_size] = crypto_option_worker_idx();
    buf[nonce_size + 1] = policy_id;
    buf[nonce_size + 2] = L4_TUNNEL_MAGIC;
}

static int l4_is_tunnel_header(const uint8_t *buf, int nonce_size)
{
    /* L4 wire marker only — L2/L3 (incl. IP totlen) untouched. */
    return buf[nonce_size + 2] == L4_TUNNEL_MAGIC;
}

static int l4_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int l3_off, int ip_hdr_len, int plain_off, size_t plain_len)
{
    (void)l3_off;
    (void)ip_hdr_len;
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    int tunnel_off = plain_off;
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE;
    uint8_t iv[AES128_IV_SIZE];

    if (pkt_len + (size_t)L4_TUNNEL_HDR_SIZE > NE_FRAME)
        return -1;

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    memmove(packet + enc_off, packet + plain_off, plain_len);
    l4_write_tunnel_header(packet + tunnel_off, nonce, PACKET_CRYPTO_NONCE_BYTES, ctx->wire_id);
    crypto_nonce_to_iv(nonce, PACKET_CRYPTO_NONCE_BYTES, iv);
    if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)plain_len, OPT_AES_BITS) != 0)
        return -1;
    return (int)(pkt_len + (size_t)L4_TUNNEL_HDR_SIZE);
}

static int l4_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int l3_off, int ip_hdr_len, int transport_off, int tunnel_off)
{
    (void)l3_off;
    (void)ip_hdr_len;
    uint8_t nonce[16];
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE;
    size_t enc_len = pkt_len - (size_t)enc_off;
    uint8_t *work_ptr = packet + enc_off;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t iv[AES128_IV_SIZE];
    int new_len;

    if (!key)
        return -1;
    memcpy(nonce, packet + tunnel_off, PACKET_CRYPTO_NONCE_BYTES);
    crypto_nonce_to_iv(nonce, PACKET_CRYPTO_NONCE_BYTES, iv);
    if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len, OPT_AES_BITS) != 0)
        return -1;
    memmove(packet + transport_off + L4_WIRE_PORT_LEN, work_ptr, enc_len);
    new_len = (int)(pkt_len - (size_t)L4_TUNNEL_HDR_SIZE);
    return new_len;
}

static int tcp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    uint8_t ip_proto;
    int ip_hdr_len;
    int transport_off;
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
    if (ip_proto != 6)
        return 0;
    ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    transport_off = l3_off + ip_hdr_len;
    if (*pkt_len < (uint32_t)(transport_off + L4_WIRE_PORT_LEN))
        return -1;
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
    if (ip_proto != 6)
        return 0;
    ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    transport_off = l3_off + ip_hdr_len;
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
