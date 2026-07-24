#include "../../../../../inc/crypto/crypto_option.h"
#include "../../../../../inc/crypto/eth_parse.h"
#include "../../../../../inc/core/interface.h"
#include "../../common/opt_no_frag_ops.h"

#include <string.h>

/*
 * L2 ARP AES-GCM-256.
 *
 * Wire (on):
 *   [dst|src|0x88B6|policy_id|core_id|nonce|ciphertext(ARP body)|tag16]
 *
 * 0x88B6 already marks ARP — no orig_et trailer.
 * Off (NE_L2_GCM256_ARP_ENABLE=0): plain Ethernet ARP.
 */

#ifndef NE_L2_GCM256_ARP_ENABLE
#define NE_L2_GCM256_ARP_ENABLE  1
#endif

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

#define OPT_FAKE_ETHERTYPE      NE_L2_FAKE_ETHERTYPE_ARP
#define OPT_AES_BITS            256
#define L2_POLICY_LEN           1
#define L2_CORE_ID_LEN          1
#define L2_NONCE_SIZE           PACKET_CRYPTO_NONCE_BYTES
#define ETH_TYPE_ARP            0x0806u

int crypto_opt_l2_gcm256_arp_enabled(void)
{
    return NE_L2_GCM256_ARP_ENABLE ? 1 : 0;
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

static int l2_verify_arp_body(const uint8_t *arp_payload, size_t len)
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

static int l2_restore_plain_arp(uint8_t *packet, size_t pkt_len,
                                const uint8_t *payload, size_t payload_len)
{
    int et_off = crypto_eth_l2_prefix_len(packet, pkt_len);
    int arp_off;

    if (et_off < 0)
        return -1;
    arp_off = et_off + 2;
    crypto_eth_set_arp_et(packet, et_off);
    memmove(packet + arp_off, payload, payload_len);
    return arp_off + (int)payload_len;
}

/* Encrypt: 0x88B6 + GCM over ARP body only, append tag. */
static int l2_do_encrypt_arp(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int arp_off = crypto_eth_arp_offset(packet, pkt_len);
    int et_off;
    size_t payload_len;
    uint32_t counter;
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    int enc_start;
    uint16_t et;
    uint8_t tag[AES_GCM_TAG_SIZE];

    if (arp_off < 0)
        return -1;
    et_off = arp_off - 2;
    et = ((uint16_t)packet[et_off] << 8) | packet[et_off + 1];
    if (et != ETH_TYPE_ARP)
        return -1;
    payload_len = pkt_len - (size_t)arp_off;
    if (payload_len < 28)
        return -1;
    enc_start = et_off + 2 + L2_POLICY_LEN + L2_CORE_ID_LEN + L2_NONCE_SIZE;
    if (pkt_len < (size_t)enc_start)
        return -1;

    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    counter = packet_crypto_next_counter();
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    if (nonce_len != L2_NONCE_SIZE)
        return -1;

    memmove(packet + enc_start, packet + arp_off, payload_len);
    l2_write_wire_header(packet, et_off, ctx->wire_id, nonce, L2_NONCE_SIZE);
    if (unlikely(crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_start,
                                        (int)payload_len, tag, OPT_AES_BITS) != 0))
        return -1;
    memcpy(packet + enc_start + payload_len, tag, AES_GCM_TAG_SIZE);
    return enc_start + (int)payload_len + AES_GCM_TAG_SIZE;
}

/* Decrypt: GCM unwrap ARP body, restore ethertype 0x0806. */
static int l2_do_decrypt_arp(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    int enc_start = l2_enc_start_off(packet, pkt_len);
    int nonce_off;
    uint8_t nonce[16];
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];
    const uint8_t *key;
    uint8_t *work_ptr;

    if (enc_start < 0)
        return -1;
    nonce_off = l2_nonce_off(packet, pkt_len);
    if (nonce_off < 0)
        return -1;
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    memcpy(nonce, packet + nonce_off, (size_t)L2_NONCE_SIZE);
    if (unlikely(pkt_len < (size_t)(enc_start + AES_GCM_TAG_SIZE)))
        return -1;
    enc_len = pkt_len - (size_t)enc_start - AES_GCM_TAG_SIZE;
    if (enc_len < 28)
        return -1;

    memcpy(tag, packet + enc_start + enc_len, AES_GCM_TAG_SIZE);
    work_ptr = packet + enc_start;
    if (unlikely(crypto_aes_gcm_decrypt(key, nonce, L2_NONCE_SIZE, work_ptr,
                                        (int)enc_len, tag, OPT_AES_BITS) != 0))
        return -1;
    if (unlikely(!l2_verify_arp_body(work_ptr, enc_len)))
        return -1;
    return l2_restore_plain_arp(packet, pkt_len, work_ptr, enc_len);
}

static int arp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int n;

    if (unlikely(!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT))
        return -1;
    if (!crypto_opt_l2_gcm256_arp_enabled())
        return 0;
    if (!crypto_pkt_is_arp(pkt, *pkt_len))
        return 0;
    n = l2_do_encrypt_arp(ctx, pkt, *pkt_len);
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
    if (!crypto_opt_l2_gcm256_arp_enabled())
        return 0;
    if (!crypto_eth_l2_is_arp_marker(pkt, *pkt_len))
        return 0;
    n = l2_do_decrypt_arp(ctx, pkt, *pkt_len);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l2_gcm256_arp_ops, arp_encrypt, arp_decrypt)
