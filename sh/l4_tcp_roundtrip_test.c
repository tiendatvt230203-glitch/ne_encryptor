/* Offline L4 TCP roundtrip: CTR/GCM with high-bit nonce + totlen match.
 * Build: gcc -O2 -Iinc -Iinc/crypto -o /tmp/l4_tcp_rt \
 *   sh/l4_tcp_roundtrip_test.c src/crypto/common/aes_crypto.c -lssl -lcrypto
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "aes_crypto.h"

#define ETH 14
#define IP_HDR 20
#define PORTS 4
#define NONCE 12
#define TUNNEL (NONCE + 3)
#define MAGIC 0xA5
#define PAYLOAD 64

static void ipv4_checksum(uint8_t *ip)
{
    uint32_t sum = 0;
    ip[10] = ip[11] = 0;
    for (int i = 0; i < IP_HDR; i += 2)
        sum += ((uint16_t)ip[i] << 8) | ip[i + 1];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum;
    ip[10] = (uint8_t)(sum >> 8);
    ip[11] = (uint8_t)(sum & 0xFF);
}

static void set_totlen(uint8_t *ip, uint16_t totlen)
{
    ip[2] = (uint8_t)(totlen >> 8);
    ip[3] = (uint8_t)(totlen & 0xFF);
    ipv4_checksum(ip);
}

static int frame_matches_totlen(const uint8_t *pkt, uint32_t pkt_len)
{
    uint16_t totlen = ((uint16_t)pkt[ETH + 2] << 8) | pkt[ETH + 3];
    return pkt_len == (uint32_t)(ETH + totlen);
}

static int is_tunnel_new(const uint8_t *buf)
{
    return buf[NONCE + 2] == MAGIC;
}

static int build_plain(uint8_t *pkt, uint8_t *orig_after_ports, size_t *plain_len)
{
    memset(pkt, 0, 2048);
    /* eth */
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    /* ipv4 */
    pkt[ETH] = 0x45;
    pkt[ETH + 9] = 6; /* TCP */
    memset(pkt + ETH + 12, 0x0a, 8);
    /* tcp ports + header + payload */
    pkt[ETH + IP_HDR + 0] = 0x12;
    pkt[ETH + IP_HDR + 1] = 0x34;
    pkt[ETH + IP_HDR + 2] = 0x00;
    pkt[ETH + IP_HDR + 3] = 0x16;
    for (int i = 0; i < 16 + PAYLOAD; i++)
        pkt[ETH + IP_HDR + PORTS + i] = (uint8_t)(0x40 + i);

    *plain_len = 16 + PAYLOAD; /* seq..payload after ports */
    memcpy(orig_after_ports, pkt + ETH + IP_HDR + PORTS, *plain_len);
    set_totlen(pkt + ETH, (uint16_t)(IP_HDR + PORTS + *plain_len));
    return (int)(ETH + IP_HDR + PORTS + *plain_len);
}

static int roundtrip_gcm(int aes_bits)
{
    uint8_t pkt[2048];
    uint8_t orig[256];
    uint8_t key[32];
    uint8_t nonce[NONCE];
    uint8_t tag[AES_GCM_TAG_SIZE];
    size_t plain_len;
    int pkt_len;
    int tunnel_off;
    int enc_off;
    int overhead = TUNNEL + AES_GCM_TAG_SIZE;
    size_t enc_len;
    uint16_t new_totlen;

    memset(key, 0x5a, sizeof(key));
    memset(nonce, 0x11, sizeof(nonce));
    nonce[0] = 0xFF; /* MSB set — old detector would reject */

    pkt_len = build_plain(pkt, orig, &plain_len);
    tunnel_off = ETH + IP_HDR + PORTS;
    enc_off = tunnel_off + TUNNEL;
    memmove(pkt + enc_off, pkt + tunnel_off, plain_len);
    memcpy(pkt + tunnel_off, nonce, NONCE);
    pkt[tunnel_off + NONCE] = 0;     /* core */
    pkt[tunnel_off + NONCE + 1] = 1; /* policy */
    pkt[tunnel_off + NONCE + 2] = MAGIC;
    if (crypto_aes_gcm_encrypt(key, nonce, NONCE, pkt + enc_off, (int)plain_len, tag, aes_bits) != 0)
        return -1;
    memcpy(pkt + enc_off + plain_len, tag, AES_GCM_TAG_SIZE);
    pkt_len += overhead;
    new_totlen = (uint16_t)(IP_HDR + PORTS + overhead + plain_len);
    set_totlen(pkt + ETH, new_totlen);

    if (!is_tunnel_new(pkt + tunnel_off))
        return -2;
    if (!frame_matches_totlen(pkt, (uint32_t)pkt_len))
        return -3;

    enc_len = plain_len;
    memcpy(tag, pkt + enc_off + enc_len, AES_GCM_TAG_SIZE);
    if (crypto_aes_gcm_decrypt(key, nonce, NONCE, pkt + enc_off, (int)enc_len, tag, aes_bits) != 0)
        return -4;
    memmove(pkt + tunnel_off, pkt + enc_off, enc_len);
    pkt_len -= overhead;
    set_totlen(pkt + ETH, (uint16_t)(IP_HDR + PORTS + plain_len));
    if (memcmp(pkt + tunnel_off, orig, plain_len) != 0)
        return -5;
    if (!frame_matches_totlen(pkt, (uint32_t)pkt_len))
        return -6;
    return 0;
}

static int roundtrip_ctr(int aes_bits)
{
    uint8_t pkt[2048];
    uint8_t orig[256];
    uint8_t key[32];
    uint8_t nonce[NONCE];
    uint8_t iv[AES128_IV_SIZE];
    size_t plain_len;
    int pkt_len;
    int tunnel_off;
    int enc_off;
    int overhead = TUNNEL;
    uint16_t new_totlen;

    memset(key, 0x3c, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    nonce[0] = 0x80; /* MSB set */

    pkt_len = build_plain(pkt, orig, &plain_len);
    tunnel_off = ETH + IP_HDR + PORTS;
    enc_off = tunnel_off + TUNNEL;
    memmove(pkt + enc_off, pkt + tunnel_off, plain_len);
    memcpy(pkt + tunnel_off, nonce, NONCE);
    pkt[tunnel_off + NONCE] = 0;
    pkt[tunnel_off + NONCE + 1] = 1;
    pkt[tunnel_off + NONCE + 2] = MAGIC;
    memcpy(iv, nonce, NONCE);
    memset(iv + NONCE, 0, AES128_IV_SIZE - NONCE);
    if (crypto_aes_ctr_with_key(key, iv, pkt + enc_off, (int)plain_len, aes_bits) != 0)
        return -1;
    pkt_len += overhead;
    new_totlen = (uint16_t)(IP_HDR + PORTS + overhead + plain_len);
    set_totlen(pkt + ETH, new_totlen);

    if (!is_tunnel_new(pkt + tunnel_off))
        return -2;
    if (!frame_matches_totlen(pkt, (uint32_t)pkt_len))
        return -3;

    if (crypto_aes_ctr_with_key(key, iv, pkt + enc_off, (int)plain_len, aes_bits) != 0)
        return -4;
    memmove(pkt + tunnel_off, pkt + enc_off, plain_len);
    pkt_len -= overhead;
    set_totlen(pkt + ETH, (uint16_t)(IP_HDR + PORTS + plain_len));
    if (memcmp(pkt + tunnel_off, orig, plain_len) != 0)
        return -5;
    if (!frame_matches_totlen(pkt, (uint32_t)pkt_len))
        return -6;
    return 0;
}

int main(void)
{
    int rc;
    struct {
        const char *name;
        int (*fn)(int);
        int bits;
    } cases[] = {
        {"CTR128", roundtrip_ctr, 128},
        {"CTR256", roundtrip_ctr, 256},
        {"GCM128", roundtrip_gcm, 128},
        {"GCM256", roundtrip_gcm, 256},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rc = cases[i].fn(cases[i].bits);
        if (rc != 0) {
            fprintf(stderr, "FAIL %s rc=%d\n", cases[i].name, rc);
            return 1;
        }
        printf("OK %s roundtrip (MSB nonce + totlen match)\n", cases[i].name);
    }
    return 0;
}
