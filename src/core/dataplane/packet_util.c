#include "../../../inc/core/dataplane_util.h"

#include "../../../inc/core/dataplane_stats.h"
#include "../../../inc/crypto/eth_parse.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

int dp_parse_flow(void *pkt_data, uint32_t pkt_len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto)
{
    int l3_off;
    struct iphdr *ip;
    uint32_t ihl;

    if (!pkt_data || !src_ip || !dst_ip || !src_port || !dst_port || !proto)
        return -1;

    l3_off = crypto_eth_ipv4_offset(pkt_data, pkt_len);
    if (l3_off < 0)
        return -1;

    ip = (struct iphdr *)((uint8_t *)pkt_data + l3_off);
    ihl = (uint32_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < (uint32_t)(l3_off + ihl))
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *proto = ip->protocol;
    *src_port = 0;
    *dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        uint8_t *l4 = (uint8_t *)pkt_data + l3_off + ihl;
        if (pkt_len < (uint32_t)(l4 - (uint8_t *)pkt_data + 4))
            return -1;
        uint16_t *ports = (uint16_t *)l4;
        *src_port = ntohs(ports[0]);
        *dst_port = ntohs(ports[1]);
    }
    return 0;
}

uint32_t dp_dest_ipv4(void *pkt, uint32_t len)
{
    uint32_t src = 0, dst = 0;
    uint16_t sp = 0, dp = 0;
    uint8_t proto = 0;
    if (dp_parse_flow(pkt, len, &src, &dst, &sp, &dp, &proto) != 0)
        return 0;
    return dst;
}

int dp_write_l2_src_only(uint8_t *pkt, uint32_t len, const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_write_l2(uint8_t *pkt, uint32_t len,
                const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN],
                int allow_empty_src)
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0)
        return -1;
    if (!allow_empty_src && memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt, dst, MAC_LEN);
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_apply_wan_l2(uint8_t *pkt, uint32_t len,
                    const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0 || memcmp(src, zero, MAC_LEN) == 0)
        return 0;
    return dp_write_l2(pkt, len, dst, src, 0);
}

int dp_pkt_is_arp(const uint8_t *pkt, uint32_t len)
{
    uint16_t et;

    if (!pkt || len < ETH_HEADER_SIZE)
        return 0;

    et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x8100u) {
        if (len < 18u)
            return 0;
        et = ((uint16_t)pkt[16] << 8) | pkt[17];
    }
    return et == 0x0806u;
}

static int arp_payload_offset(const uint8_t *pkt, uint32_t len, uint32_t *off_out)
{
    uint32_t off = 14u;
    uint16_t et;

    if (!pkt || !off_out || len < off + 28u)
        return -1;

    et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x8100u) {
        off = 18u;
        if (len < off + 28u)
            return -1;
    }
    *off_out = off;
    return 0;
}

static void format_mac(const uint8_t mac[6], char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_ipv4_be32(uint32_t ip_be, char *buf, size_t bufsz)
{
    uint8_t b[4];

    memcpy(b, &ip_be, 4);
    snprintf(buf, bufsz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

void dp_log_arp_userspace(const char *dir, const char *iface,
                          const uint8_t *pkt, uint32_t len)
{
    uint32_t off;
    const uint8_t *arp;
    uint16_t op;
    char sha[18], tha[18], spa[16], tpa[16];

    if (!dir || !iface || !pkt)
        return;
    if (arp_payload_offset(pkt, len, &off) != 0)
        return;

    arp = pkt + off;
    op = ((uint16_t)arp[6] << 8) | arp[7];
    format_mac(arp + 8, sha, sizeof(sha));
    format_mac(arp + 18, tha, sizeof(tha));
    format_ipv4_be32(*(const uint32_t *)(arp + 14), spa, sizeof(spa));
    format_ipv4_be32(*(const uint32_t *)(arp + 24), tpa, sizeof(tpa));

    fprintf(stderr,
            "[ARP] userspace dir=%s iface=%s len=%u op=%s "
            "sha=%s spa=%s tha=%s tpa=%s\n",
            dir, iface, len,
            op == 1 ? "request" : (op == 2 ? "reply" : "other"),
            sha, spa, tha, tpa);
}

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt)
{
    if (pkt->len > fwd->pair.frame_size || ne_ring_try_push(ring, pkt) != 0) {
        ne_dp_stats_mid_ring_drop(1);
        ne_frame_free(&fwd->pair, pkt->addr);
        return -1;
    }
    return 0;
}