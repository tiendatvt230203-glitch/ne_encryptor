#include "../../../inc/core/arp_l2_overhead.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/packet_crypto.h"

#include <string.h>

#define FAKE_ET        0x88B5u
#define ETH_TYPE_ARP   0x0806u
#define POLICY_LEN     1
#define CORE_LEN       1
#define NONCE_LEN      PACKET_CRYPTO_NONCE_BYTES
#define ORIG_ET_LEN    2

static int eth_et_off(const uint8_t *pkt, uint32_t len)
{
    if (!pkt || len < 14u)
        return -1;
    if ((((uint16_t)pkt[12] << 8) | pkt[13]) == 0x8100u) {
        if (len < 18u)
            return -1;
        return 16;
    }
    return 12;
}

int arp_l2_overhead_read_policy_id(const uint8_t *pkt, uint32_t pkt_len, uint8_t *policy_id_out)
{
    int et_off = eth_et_off(pkt, pkt_len);
    uint16_t et;

    if (et_off < 0 || !policy_id_out)
        return -1;
    if (pkt_len < (uint32_t)(et_off + 2 + POLICY_LEN))
        return -1;
    et = ((uint16_t)pkt[et_off] << 8) | pkt[et_off + 1];
    if (et != FAKE_ET)
        return -1;
    *policy_id_out = pkt[et_off + 2];
    return 0;
}

int arp_l2_overhead_attach(uint8_t *pkt, uint32_t *pkt_len, uint8_t policy_pkt_tag)
{
    int arp_off;
    int et_off;
    uint16_t orig_et;
    size_t payload_len;
    int enc_start;
    uint8_t nonce[NONCE_LEN];

    if (!pkt || !pkt_len)
        return -1;
    arp_off = crypto_eth_arp_offset(pkt, *pkt_len);
    if (arp_off < 0)
        return -1;
    et_off = arp_off - 2;
    orig_et = ((uint16_t)pkt[et_off] << 8) | pkt[et_off + 1];
    if (orig_et != ETH_TYPE_ARP)
        return -1;

    payload_len = (size_t)(*pkt_len - (uint32_t)arp_off);
    enc_start = et_off + 2 + POLICY_LEN + CORE_LEN + NONCE_LEN;
    if (*pkt_len < (uint32_t)enc_start)
        return -1;

    memset(nonce, 0, sizeof(nonce));
    memmove(pkt + enc_start, pkt + arp_off, payload_len);

    pkt[et_off] = (uint8_t)(FAKE_ET >> 8);
    pkt[et_off + 1] = (uint8_t)(FAKE_ET & 0xFF);
    pkt[et_off + 2] = policy_pkt_tag;
    pkt[et_off + 3] = 0; /* core_id placeholder */
    memcpy(pkt + et_off + 4, nonce, NONCE_LEN);

    pkt[enc_start + (int)payload_len] = (uint8_t)(orig_et >> 8);
    pkt[enc_start + (int)payload_len + 1] = (uint8_t)(orig_et & 0xFF);
    *pkt_len = (uint32_t)(enc_start + (int)payload_len + ORIG_ET_LEN);
    return 0;
}

int arp_l2_overhead_detach(uint8_t *pkt, uint32_t *pkt_len)
{
    int et_off;
    int enc_start;
    size_t enc_len;
    size_t payload_len;
    uint16_t orig_et;
    uint8_t *body;
    int arp_off;

    if (!pkt || !pkt_len)
        return -1;
    et_off = eth_et_off(pkt, *pkt_len);
    if (et_off < 0)
        return -1;
    if (*pkt_len < (uint32_t)(et_off + 2 + POLICY_LEN + CORE_LEN + NONCE_LEN + 28 + ORIG_ET_LEN))
        return -1;
    if ((((uint16_t)pkt[et_off] << 8) | pkt[et_off + 1]) != FAKE_ET)
        return -1;

    enc_start = et_off + 2 + POLICY_LEN + CORE_LEN + NONCE_LEN;
    enc_len = (size_t)(*pkt_len - (uint32_t)enc_start);
    if (enc_len < 28 + ORIG_ET_LEN)
        return -1;

    body = pkt + enc_start;
    orig_et = ((uint16_t)body[enc_len - 2] << 8) | body[enc_len - 1];
    if (orig_et != ETH_TYPE_ARP)
        return -1;
    payload_len = enc_len - ORIG_ET_LEN;

    /* Minimal ARP header check */
    if (body[0] != 0x00 || body[1] != 0x01 || body[2] != 0x08 || body[3] != 0x00 ||
        body[4] != 6 || body[5] != 4)
        return -1;

    arp_off = et_off + 2;
    pkt[et_off] = (uint8_t)(ETH_TYPE_ARP >> 8);
    pkt[et_off + 1] = (uint8_t)(ETH_TYPE_ARP & 0xFF);
    memmove(pkt + arp_off, body, payload_len);
    *pkt_len = (uint32_t)(arp_off + (int)payload_len);
    return 0;
}
