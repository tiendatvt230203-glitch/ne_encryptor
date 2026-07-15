#include "../../inc/crypto/eth_parse.h"
#include "../../inc/crypto/packet_crypto.h"

#define ETH_P_8021Q  0x8100u
#define ETH_P_IP     0x0800u

static uint16_t eth_read_et(const uint8_t *pkt, int off)
{
    return (uint16_t)(((uint16_t)pkt[off] << 8) | pkt[off + 1]);
}

static int eth_match_et(uint16_t et, uint16_t target, uint16_t fake)
{
    return et == target || (fake != 0 && et == fake);
}


int crypto_eth_inner_et_off(const uint8_t *pkt, size_t pkt_len)
{
    uint16_t fake;

    if (!pkt || pkt_len < 14)
        return -1;

    fake = packet_crypto_get_fake_ethertype_ipv4();

    if (eth_match_et(eth_read_et(pkt, 12), ETH_P_IP, fake))
        return 12;

    if (eth_read_et(pkt, 12) != ETH_P_8021Q)
        return -1;
    if (pkt_len < 18)
        return -1;

    if (eth_match_et(eth_read_et(pkt, 16), ETH_P_IP, fake))
        return 16;

    return -1;
}

int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len)
{
    int et_off = crypto_eth_inner_et_off(pkt, pkt_len);

    if (et_off < 0)
        return -1;
    if (eth_read_et(pkt, et_off) != ETH_P_IP)
        return -1;
    if (pkt_len < (size_t)(et_off + 2 + 20))
        return -1;
    return et_off + 2;
}

int crypto_eth_l2_prefix_len(const uint8_t *pkt, size_t pkt_len)
{
    int et_off = crypto_eth_inner_et_off(pkt, pkt_len);

    if (et_off < 0)
        return -1;
    return et_off;
}

int crypto_pkt_is_ipv4(const uint8_t *pkt, size_t pkt_len)
{
    return crypto_eth_ipv4_offset(pkt, pkt_len) >= 0;
}

void crypto_eth_set_ipv4_et(uint8_t *pkt, int inner_et_off)
{
    if (!pkt || inner_et_off < 0)
        return;
    pkt[inner_et_off] = 0x08;
    pkt[inner_et_off + 1] = 0x00;
}