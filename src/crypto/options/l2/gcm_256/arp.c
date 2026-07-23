#include "../../../../../inc/crypto/crypto_option.h"
#include "../../../../../inc/crypto/eth_parse.h"
#include "../../../../../inc/core/interface.h"
#include "../../common/opt_no_frag_ops.h"

#include <string.h>

/*
 * Step: L2 ARP overhead only (no cipher yet).
 *
 * Wire (same 0x88B5 marker as IPv4 L2):
 *   [dst|src|0x88B5|policy_id|core_id|nonce|ARP body|orig_et(2)]
 *
 * orig_et (normally 0x0806) is appended at the end — same idea as L3
 * keeping orig_proto — so WAN can tell ARP vs IPv4 after detach.
 * Later cipher step will encrypt ARP body + orig_et trailer together.
 */

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

#define OPT_FAKE_ETHERTYPE  0x88B5u
#define L2_POLICY_LEN           1
#define L2_CORE_ID_LEN          1
#define L2_NONCE_SIZE           PACKET_CRYPTO_NONCE_BYTES
#define L2_ORIG_ET_LEN          2
#define ETH_TYPE_ARP            0x0806u

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

static int l2_enc_start_off(const uint8_t *packet, size_t pkt_len)
{
    int off = crypto_eth_l2_policy_off(packet, pkt_len);

    if (off < 0)
        return -1;
    off += L2_POLICY_LEN + L2_CORE_ID_LEN;
    if (pkt_len < (size_t)(off + L2_NONCE_SIZE))
        return -1;
    return off + L2_NONCE_SIZE;
}

static int l2_verify_arp_after_detach(const uint8_t *arp_payload, size_t len)
{
    if (unlikely(len < 28))
        return 0;
    if (arp_payload[0] != 0x00 || arp_payload[1] != 0x01)
        return 0;
    if (arp_payload[2] != 0x08 || arp_payload[3] != 0x00)
        return 0;
    if (arp_payload[4] != 6 || arp_payload[5] != 4)
        return 0;
    return 1;
}

static int l2_restore_plain_arp_packet(uint8_t *packet, size_t pkt_len,
                                       const uint8_t *payload, size_t payload_len,
                                       uint16_t orig_et)
{
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    int arp_off;

    (void)orig_et;
    if (et_off < 0)
        return -1;
    arp_off = et_off + 2;
    /* orig_et is expected ARP; restore canonical 0x0806 */
    crypto_eth_set_arp_et(packet, et_off);
    memmove(packet + arp_off, payload, payload_len);
    return arp_off + (int)payload_len;
}

/* Attach: fake ET + policy/core/nonce; ARP body plaintext; append orig_et. */
static int l2_do_attach_arp(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int arp_off = crypto_eth_arp_offset(packet, pkt_len);
    int et_off;
    size_t payload_len;
    uint8_t nonce[PACKET_CRYPTO_NONCE_BYTES];
    int enc_start;
    uint16_t orig_et;

    if (arp_off < 0)
        return -1;
    et_off = arp_off - 2;
    orig_et = ((uint16_t)packet[et_off] << 8) | packet[et_off + 1];
    if (orig_et != ETH_TYPE_ARP)
        return -1;
    payload_len = pkt_len - (size_t)arp_off;
    enc_start = et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE;
    if (pkt_len < (size_t)enc_start)
        return -1;
    memset(nonce, 0, sizeof(nonce));
    memmove(packet + enc_start, packet + arp_off, payload_len);
    l2_write_wire_header(packet, et_off, ctx->wire_id, nonce, L2_NONCE_SIZE);
    packet[enc_start + (int)payload_len] = (uint8_t)(orig_et >> 8);
    packet[enc_start + (int)payload_len + 1] = (uint8_t)(orig_et & 0xFF);
    return enc_start + (int)payload_len + L2_ORIG_ET_LEN;
}

/* Detach: strip overhead + orig_et trailer, restore ethertype 0x0806. */
static int l2_do_detach_arp(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int enc_start = l2_enc_start_off(packet, pkt_len);
    size_t enc_len;
    size_t payload_len;
    uint8_t *work_ptr;
    uint16_t orig_et;

    (void)ctx;
    if (enc_start < 0)
        return -1;
    enc_len = pkt_len - (size_t)enc_start;
    if (enc_len < 28 + L2_ORIG_ET_LEN)
        return -1;
    work_ptr = packet + enc_start;
    orig_et = ((uint16_t)work_ptr[enc_len - 2] << 8) | work_ptr[enc_len - 1];
    if (orig_et != ETH_TYPE_ARP)
        return -1;
    payload_len = enc_len - L2_ORIG_ET_LEN;
    if (unlikely(!l2_verify_arp_after_detach(work_ptr, payload_len)))
        return -1;
    return l2_restore_plain_arp_packet(packet, pkt_len, work_ptr, payload_len, orig_et);
}

static int arp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_pkt_is_arp(pkt, *pkt_len))
        return 0;
    n = l2_do_attach_arp(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

static int arp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt))
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_detach_arp(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l2_gcm256_arp_ops, arp_encrypt, arp_decrypt)
