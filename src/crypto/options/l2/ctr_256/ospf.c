#include "../../../../../inc/crypto/crypto_option.h"
#include "../../../../../inc/crypto/eth_parse.h"
#include "../../../../../inc/core/interface.h"
#include "../../common/opt_no_frag_ops.h"

#include <string.h>

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

/* wire — local to this option */
#define OPT_FAKE_ETHERTYPE  0x88B5u
#define OPT_AES_BITS        256

#define L2_POLICY_LEN           1
#define L2_CORE_ID_LEN          1
#define L2_NONCE_SIZE           PACKET_CRYPTO_NONCE_BYTES
static int l2_policy_off(const uint8_t *packet, size_t pkt_len)
{
    return crypto_eth_l2_policy_off(packet, pkt_len);
}

static int l2_core_id_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_policy_off(packet, pkt_len);
    if (off < 0)
        return -1;
    return off + L2_POLICY_LEN;
}

static int l2_nonce_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_core_id_off(packet, pkt_len);
    if (off < 0)
        return -1;
    return off + L2_CORE_ID_LEN;
}

static int l2_enc_start_off(const uint8_t *packet, size_t pkt_len)
{
    int off = l2_nonce_off(packet, pkt_len);
    if (off < 0 || pkt_len < (size_t)(off + L2_NONCE_SIZE))
        return -1;
    return off + L2_NONCE_SIZE;
}

static void l2_write_wire_header(uint8_t *packet, int et_off, uint8_t policy_id,
                                 const uint8_t *nonce, int nonce_size)
{
    uint16_t fake = OPT_FAKE_ETHERTYPE;
    packet[et_off] = (uint8_t)(fake >> 8);
    packet[et_off + 1] = (uint8_t)(fake & 0xFF);
    packet[et_off + 2] = policy_id;
    packet[et_off + 3] = crypto_option_worker_idx();
    memcpy(packet + et_off + 4, nonce, (size_t)nonce_size);
}

static int l2_verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len)
{
    if (unlikely(len < 20))
        return 0;
    uint8_t ttl = ip_payload[8];
    uint8_t proto = ip_payload[9];
    if (unlikely(ttl == 0))
        return 0;
    if (proto == 1 || proto == 2 || proto == 6 || proto == 17 ||
        proto == 47 || proto == 50 || proto == 51 || proto == 58 ||
        proto == 89 || proto == 132)
        return 1;
    return 0;
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

static int l2_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    size_t payload_len;

    if (l3_off < 0 || et_off < 0)
        return -1;
    payload_len = pkt_len - (size_t)l3_off;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    int enc_start = et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE;
    uint8_t iv[AES128_IV_SIZE];
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);

    if (pkt_len < (size_t)enc_start)
        return -1;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    memmove(packet + enc_start, packet + l3_off, payload_len);
    l2_write_wire_header(packet, et_off, ctx->wire_id, nonce, L2_NONCE_SIZE);
    crypto_nonce_to_iv(nonce, L2_NONCE_SIZE, iv);
    if (unlikely(crypto_aes_ctr_with_key(key, iv, packet + enc_start, (int)payload_len, OPT_AES_BITS) != 0))
        return -1;
    return enc_start + (int)payload_len;

}

static int l2_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{

    int enc_start = l2_enc_start_off(packet, pkt_len);
    int nonce_off;
    uint8_t nonce[16];
    size_t enc_len;
    uint8_t iv[AES128_IV_SIZE];
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t *work_ptr;

    if (enc_start < 0)
        return -1;
    nonce_off = l2_nonce_off(packet, pkt_len);
    if (nonce_off < 0)
        return -1;
    memcpy(nonce, packet + nonce_off, (size_t)L2_NONCE_SIZE);
    enc_len = pkt_len - (size_t)enc_start;
    work_ptr = packet + enc_start;
    crypto_nonce_to_iv(nonce, L2_NONCE_SIZE, iv);
    if (unlikely(crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len, OPT_AES_BITS) != 0))
        return -1;
    if (unlikely(!l2_verify_ipv4_after_decrypt(work_ptr, enc_len)))
        return -1;
    return l2_restore_plain_packet(packet, pkt_len, work_ptr, enc_len);

}

static int ospf_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int l3_off;
    int et_off;
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    if (!OPT_FAKE_ETHERTYPE)
        return 0;
    l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
    et_off = crypto_eth_l2_prefix_len(pkt, *pkt_len);
    if (l3_off < 0 || et_off < 0)
        return -1;
    n = l2_do_encrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int ospf_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}
CRYPTO_OPS_PLAIN(crypto_opt_l2_ctr256_ospf_ops, ospf_encrypt, ospf_decrypt)
