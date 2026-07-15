#define _POSIX_C_SOURCE 199309L
#include "../../inc/core/interface.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/packet_crypto.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/core/config.h"
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>

static atomic_uint_fast32_t g_pkt_id_counter = 0;
static atomic_uint_fast32_t g_frag_mtu = FRAG_MTU;

void frag_set_mtu(uint32_t mtu) {
    if (mtu < 512)
        mtu = 512;
    if (mtu > NE_FRAME)
        mtu = NE_FRAME;
    atomic_store(&g_frag_mtu, mtu);
}

uint32_t frag_get_mtu(void) {
    uint32_t mtu = (uint32_t)atomic_load(&g_frag_mtu);
    if (mtu < 512 || mtu > NE_FRAME)
        return FRAG_MTU;
    return mtu;
}

uint16_t frag_next_pkt_id(void) {
    return (uint16_t)(atomic_fetch_add(&g_pkt_id_counter, 1) & 0xFFFF);
}

void frag_table_init(struct frag_table *ft) {
    memset(ft, 0, sizeof(*ft));
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void frag_table_gc_at(struct frag_table *ft, uint64_t now)
{
    for (int i = 0; i < FRAG_TABLE_SIZE; i++) {
        if ((ft->entries[i].got_first || ft->entries[i].got_second) &&
            (now - ft->entries[i].timestamp_ns) > FRAG_TIMEOUT_NS)
            memset(&ft->entries[i], 0, sizeof(ft->entries[i]));
    }
}

static void frag_read_hdr(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

static int frag_require_ipv4(const uint8_t *pkt, uint32_t pkt_len, int *ip_hdr_len_out) {
    if (pkt_len < 14 + 20)
        return -1;
    if ((((uint16_t)pkt[12] << 8) | pkt[13]) != 0x0800)
        return -1;
    int ihl = (pkt[14] & 0x0F) * 4;
    if (ihl < 20 || pkt_len < (uint32_t)(14 + ihl))
        return -1;
    *ip_hdr_len_out = ihl;
    return 0;
}

static void frag_prepare_entry(struct frag_entry *entry, uint16_t pkt_id, uint64_t now) {
    if (entry->pkt_id != pkt_id ||
        ((entry->got_first || entry->got_second) &&
         (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS))
        memset(entry, 0, sizeof(*entry));
    entry->pkt_id = pkt_id;
    entry->timestamp_ns = now;
}

static int frag_store_first(struct frag_entry *entry, uint16_t pkt_id,
                            const uint8_t *eth, uint8_t eth_len,
                            const uint8_t *data, uint32_t data_len,
                            uint64_t now) {
    if (data_len > sizeof(entry->first))
        return -1;
    if (eth_len == 0 || eth_len > sizeof(entry->eth_hdr))
        return -1;
    frag_prepare_entry(entry, pkt_id, now);
    entry->first_len = data_len;
    memcpy(entry->first, data, data_len);
    memcpy(entry->eth_hdr, eth, eth_len);
    entry->eth_len = eth_len;
    entry->got_first = 1;
    return 0;
}

static int frag_store_second(struct frag_entry *entry, uint16_t pkt_id,
                             const uint8_t *data, uint32_t data_len,
                             uint64_t now) {
    if (data_len > sizeof(entry->second))
        return -1;
    frag_prepare_entry(entry, pkt_id, now);
    entry->second_len = data_len;
    memcpy(entry->second, data, data_len);
    entry->got_second = 1;
    return 0;
}

static int frag_pick_slot(struct frag_table *ft, uint16_t pkt_id, uint64_t now)
{
    const int probe = 8;
    int base = (int)(pkt_id % FRAG_TABLE_SIZE);
    int empty_idx = -1;
    int oldest_idx = -1;
    uint64_t oldest_age = 0;

    for (int i = 0; i < probe; i++) {
        int idx = (base + i) % FRAG_TABLE_SIZE;
        struct frag_entry *e = &ft->entries[idx];
        int occupied = (e->got_first || e->got_second);

        if (occupied && (now - e->timestamp_ns) > FRAG_TIMEOUT_NS) {
            memset(e, 0, sizeof(*e));
            occupied = 0;
        }
        if (!occupied) {
            if (empty_idx < 0)
                empty_idx = idx;
            continue;
        }
        if (e->pkt_id == pkt_id)
            return idx;

        uint64_t age = now - e->timestamp_ns;
        if (oldest_idx < 0 || age > oldest_age) {
            oldest_idx = idx;
            oldest_age = age;
        }
    }

    if (empty_idx >= 0)
        return empty_idx;
    if (oldest_idx >= 0)
        return oldest_idx;
    return base;
}

static int frag_emit_join(struct frag_entry *entry, uint8_t *out_buf, uint32_t *out_len) {
    if (!entry->got_first || !entry->got_second)
        return 0;
    int eth_len = entry->eth_len ? entry->eth_len : (int)ETH_HEADER_SIZE;
    if (entry->first_len + entry->second_len + (uint32_t)eth_len > NE_FRAME) {
        memset(entry, 0, sizeof(*entry));
        return -1;
    }
    int off = 0;
    memcpy(out_buf, entry->eth_hdr, (size_t)eth_len);
    off += eth_len;
    memcpy(out_buf + off, entry->first, entry->first_len);
    off += (int)entry->first_len;
    if (entry->second_len > 0) {
        memcpy(out_buf + off, entry->second, entry->second_len);
        off += (int)entry->second_len;
    }
    *out_len = (uint32_t)off;
    memset(entry, 0, sizeof(*entry));
    return 1;
}

int frag_is_fragment(const struct app_config *cfg,
                     const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index) {
    if (!cfg)
        return 0;
    int ip_hdr_len;
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    if (frag_require_ipv4(pkt_data, pkt_len, &ip_hdr_len) != 0)
        return 0;
    if (pkt_data[14 + 9] != packet_crypto_get_fake_protocol())
        return 0;

    int tunnel_off = 14 + ip_hdr_len;
    int ns = PACKET_CRYPTO_NONCE_BYTES;

    if (pkt_len < (uint32_t)(tunnel_off + tunnel_hdr_size + CRYPTO_L3_FRAG_TAG_SIZE))
        return 0;
    if (tunnel_off + ns + 1 >= (int)pkt_len)
        return 0;
    if (pkt_data[tunnel_off + ns + 1] != CRYPTO_L3_FRAG_MAGIC)
        return 0;

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
            continue;
        if (pkt_data[tunnel_off + ns] != (uint8_t)cp->id)
            continue;
        frag_read_hdr(pkt_data + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);
        if (*frag_index > 1)
            return 0;
        return 1;
    }
    return 0;
}

int frag_split_and_encrypt(struct packet_crypto_ctx *ctx,
                           uint8_t *pkt_data, uint32_t pkt_len,
                           size_t frag0_max, uint32_t *frag0_len,
                           uint8_t *frag1, size_t frag1_max,
                           uint32_t *frag1_len) {
    /* Same split math as L2; L3 keeps clear IPv4 on wire (encrypts plain after it). */
    uint32_t frag_mtu = frag_get_mtu();
    int l3_off = crypto_eth_ipv4_offset(pkt_data, pkt_len);
    if (l3_off < 0)
        return -1;
    /* L3 crypto currently assumes flat Ethernet (no VLAN). */
    if (l3_off != ETH_HEADER_SIZE)
        return -1;

    const uint8_t *eth_hdr = pkt_data;
    const uint8_t *ip_hdr = pkt_data + l3_off;

    int ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    if ((ip_hdr[0] >> 4) != 4 || ip_hdr_len < 20 ||
        pkt_len < (uint32_t)(l3_off + ip_hdr_len))
        return -1;

    uint8_t ip_proto = ip_hdr[9];
    const uint8_t *ip_payload = pkt_data + l3_off + ip_hdr_len;
    uint32_t ip_payload_len = pkt_len - (uint32_t)l3_off - (uint32_t)ip_hdr_len;

    int transport_hdr_len = -1;
    uint32_t app_off = 0;
    uint32_t app_len = ip_payload_len;

    if (ip_proto == 6 || ip_proto == 17) {
        transport_hdr_len = crypto_layer4_get_transport_hdr_size(
            ip_payload, ip_proto, ip_payload_len);
        if (transport_hdr_len < 0)
            return -1;
        app_off = (uint32_t)transport_hdr_len;
        app_len = ip_payload_len - app_off;
    }

    if (app_len == 0)
        return -1;

    uint32_t frag_overhead = (uint32_t)l3_off + (uint32_t)ip_hdr_len +
                             (uint32_t)crypto_layer3_frag_meta_len();
    if (frag_overhead >= frag_mtu)
        return -1;
    uint32_t max_plain0 = frag_mtu - frag_overhead;
    uint32_t fixed_plain0 = (uint32_t)ip_hdr_len + app_off;
    if (max_plain0 <= fixed_plain0)
        return -1;
    uint32_t half1 = max_plain0 - fixed_plain0;
    if (half1 >= app_len)
        half1 = app_len - 1;
    uint32_t half2 = app_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    uint32_t frag0_plain_len;
    if (transport_hdr_len >= 0)
        frag0_plain_len = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len + half1;
    else
        frag0_plain_len = (uint32_t)ip_hdr_len + half1;

    const uint8_t *frag1_plain = (transport_hdr_len >= 0)
                                   ? ip_payload + app_off + half1
                                   : ip_payload + half1;

    if (crypto_layer3_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                              frag1_plain, half2,
                                              pkt_id, 1, frag1, frag1_max, frag1_len) != 0)
        return -1;
    /* Frag0: cut+encrypt in place on original UMEM frame (half2 already copied out). */
    if (crypto_layer3_encrypt_fragment0_inplace(ctx, pkt_data, ip_hdr_len, frag0_plain_len,
                                                pkt_id, frag0_max, frag0_len) != 0)
        return -1;
    return 0;
}

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len) {
    /* After crypto_layer3_decrypt_fragment: [Eth][outer IP][inner plain].
     * Reassemble like L2: keep Eth, join inner plains (frag0 = IP+...), drop outer IP. */
    int ip_hdr_len;
    if (frag_require_ipv4(pkt_data, pkt_len, &ip_hdr_len) != 0)
        return -1;
    if (pkt_len < (uint32_t)(ETH_HEADER_SIZE + ip_hdr_len + 1))
        return -1;

    const uint8_t *inner = pkt_data + ETH_HEADER_SIZE + ip_hdr_len;
    uint32_t inner_len = pkt_len - (uint32_t)(ETH_HEADER_SIZE + ip_hdr_len);

    uint64_t now = get_time_ns();
    int idx = frag_pick_slot(ft, pkt_id, now);
    struct frag_entry *entry = &ft->entries[idx];

    if (frag_index == 0) {
        if (inner_len < 20 || (inner[0] >> 4) != 4)
            return -1;
        int inner_ihl = (inner[0] & 0x0F) * 4;
        if (inner_ihl < 20 || inner_len < (uint32_t)inner_ihl)
            return -1;
        if (frag_store_first(entry, pkt_id, pkt_data, ETH_HEADER_SIZE,
                             inner, inner_len, now) != 0)
            return -1;
        int joined = frag_emit_join(entry, out_buf, out_len);
        if (joined < 0)
            return -1;
        if (joined == 0)
            return 0;
        return 1;
    }

    if (frag_index == 1) {
        if ((entry->got_first || entry->got_second) && entry->pkt_id == pkt_id &&
            (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS)
            memset(entry, 0, sizeof(*entry));
        if (frag_store_second(entry, pkt_id, inner, inner_len, now) != 0)
            return -1;
        int joined = frag_emit_join(entry, out_buf, out_len);
        if (joined < 0)
            return -1;
        if (joined == 0)
            return 0;
        return 1;
    }

    return -1;
}

int frag_split_and_encrypt_l2(struct packet_crypto_ctx *ctx,
                              uint8_t *pkt_data, uint32_t pkt_len,
                              size_t frag0_max, uint32_t *frag0_len,
                              uint8_t *frag1, size_t frag1_max,
                              uint32_t *frag1_len) {
    uint32_t frag_mtu = frag_get_mtu();
    int l3_off = crypto_eth_ipv4_offset(pkt_data, pkt_len);
    if (l3_off < 0)
        return -1;

    const uint8_t *eth_hdr = pkt_data;
    const uint8_t *ip_hdr = pkt_data + l3_off;

    int ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    if ((ip_hdr[0] >> 4) != 4 || ip_hdr_len < 20 ||
        pkt_len < (uint32_t)(l3_off + ip_hdr_len))
        return -1;

    uint8_t ip_proto = ip_hdr[9];

    const uint8_t *ip_payload = pkt_data + l3_off + ip_hdr_len;
    uint32_t ip_payload_len = pkt_len - (uint32_t)l3_off - (uint32_t)ip_hdr_len;

    int transport_hdr_len = -1;
    uint32_t app_off = 0;
    uint32_t app_len = ip_payload_len;

    if (ip_proto == 6 || ip_proto == 17) {
        transport_hdr_len = crypto_layer4_get_transport_hdr_size(
            ip_payload, ip_proto, ip_payload_len);
        if (transport_hdr_len < 0)
            return -1;
        app_off = (uint32_t)transport_hdr_len;
        app_len = ip_payload_len - app_off;
    }

    if (app_len == 0)
        return -1;

    uint32_t frag_overhead = (uint32_t)l3_off + (uint32_t)crypto_layer2_frag_meta_len();
    if (frag_overhead >= frag_mtu)
        return -1;
    uint32_t max_plain0 = frag_mtu - frag_overhead;
    uint32_t fixed_plain0 = (uint32_t)ip_hdr_len + app_off;
    if (max_plain0 <= fixed_plain0)
        return -1;
    uint32_t half1 = max_plain0 - fixed_plain0;
    if (half1 >= app_len)
        half1 = app_len - 1;
    uint32_t half2 = app_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    uint32_t frag0_plain_len;
    if (transport_hdr_len >= 0) {
        frag0_plain_len = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len + half1;
    } else {
        frag0_plain_len = (uint32_t)ip_hdr_len + half1;
    }

    const uint8_t *frag1_plain = (transport_hdr_len >= 0)
                                   ? ip_payload + app_off + half1
                                   : ip_payload + half1;
    if (crypto_layer2_encrypt_fragment_single(ctx, eth_hdr, frag1_plain, half2,
                                              pkt_id, 1, frag1, frag1_max, frag1_len) != 0)
        return -1;
    if (crypto_layer2_encrypt_fragment0_inplace(ctx, pkt_data, pkt_len, frag0_plain_len,
                                                pkt_id, frag0_max, frag0_len) != 0)
        return -1;

    return 0;
}

int frag_is_fragment_l2(const struct app_config *cfg,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index) {
    int ns, tag_off;
    uint8_t wire_pol;

    if (!cfg || !pkt_id || !frag_index)
        return 0;

    if (!crypto_layer2_has_fake_ethertype(pkt_data, pkt_len))
        return 0;

    ns = PACKET_CRYPTO_NONCE_BYTES;
    tag_off = crypto_layer2_frag_magic_off(pkt_data, pkt_len, ns);
    if (tag_off < 0)
        return 0;
    if (pkt_len < (uint32_t)(tag_off + 1 + CRYPTO_L2_FRAG_TAG_SIZE))
        return 0;

    /* Non-frag L2 crypto hits this on every WAN packet — bail before policy scan. */
    if (pkt_data[tag_off] != CRYPTO_L2_FRAG_MAGIC)
        return 0;

    if (crypto_layer2_read_policy_id(pkt_data, pkt_len, &wire_pol) != 0)
        return 0;
    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L2)
            continue;
        if ((uint8_t)cp->id != wire_pol)
            continue;
        frag_read_hdr(pkt_data + tag_off + 1, pkt_id, frag_index);
        if (*frag_index > 1)
            return 0;
        return 1;
    }
    return 0;
}

int frag_try_reassemble_l2(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len) {
    /* Wire prefix = MAC + optional VLAN tags + inner ethertype (fake). */
    int wire_eth = crypto_layer2_wire_prefix_len(pkt_data, pkt_len);
    if (wire_eth < 0 || wire_eth > (int)ETH_L2_HDR_MAX)
        return -1;
    if (pkt_len < (uint32_t)(wire_eth + 20))
        return -1;

    const uint8_t *inner = pkt_data + wire_eth;
    uint32_t inner_len = pkt_len - (uint32_t)wire_eth;

    uint64_t now = get_time_ns();
    int idx = frag_pick_slot(ft, pkt_id, now);
    struct frag_entry *entry = &ft->entries[idx];

    if (frag_index == 0) {
        if (inner_len < 20 || (inner[0] >> 4) != 4)
            return -1;
        int ip_hdr_len = (inner[0] & 0x0F) * 4;
        if (ip_hdr_len < 20 || inner_len < (uint32_t)ip_hdr_len)
            return -1;
        if (frag_store_first(entry, pkt_id, pkt_data, (uint8_t)wire_eth, inner, inner_len, now) != 0)
            return -1;
        int joined = frag_emit_join(entry, out_buf, out_len);
        if (joined < 0)
            return -1;
        if (joined == 0)
            return 0;
        crypto_eth_set_ipv4_et(out_buf, wire_eth - 2);
        return 1;
    }

    if (frag_index == 1) {
        if ((entry->got_first || entry->got_second) && entry->pkt_id == pkt_id &&
            (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS)
            memset(entry, 0, sizeof(*entry));
        if (frag_store_second(entry, pkt_id, inner, inner_len, now) != 0)
            return -1;
        int out_eth_len = entry->eth_len ? entry->eth_len : wire_eth;
        int joined = frag_emit_join(entry, out_buf, out_len);
        if (joined < 0)
            return -1;
        if (joined == 0)
            return 0;
        crypto_eth_set_ipv4_et(out_buf, out_eth_len - 2);
        return 1;
    }

    return -1;
}

int frag_split_and_encrypt_l4(struct packet_crypto_ctx *ctx,
                              uint8_t *pkt_data, uint32_t pkt_len,
                              size_t frag0_max, uint32_t *frag0_len,
                              uint8_t *frag1, size_t frag1_max,
                              uint32_t *frag1_len) {
    uint32_t frag_mtu = frag_get_mtu();
    if (pkt_len < 14 + 20 + 8) return -1;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    if (ether_type != 0x0800) return -1;

    uint8_t ip_proto = pkt_data[14 + 9];
    if (ip_proto != 6 && ip_proto != 17) return -1;

    int ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20) return -1;

    int transport_off = 14 + ip_hdr_len;
    if (pkt_len < (uint32_t)transport_off) return -1;
    size_t remaining = pkt_len - transport_off;
    int transport_hdr_len = crypto_layer4_get_transport_hdr_size(
        pkt_data + transport_off, ip_proto, remaining);
    if (transport_hdr_len < 0) return -1;

    int app_off = transport_off + transport_hdr_len;
    uint32_t app_len = pkt_len - app_off;
    if (app_len == 0) return -1;

    uint32_t frag_overhead = 14u + (uint32_t)ip_hdr_len + (uint32_t)crypto_layer4_frag_meta_len();
    if (frag_overhead >= frag_mtu)
        return -1;
    uint32_t max_plain0 = frag_mtu - frag_overhead;
    uint32_t fixed_plain0 = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len;
    if (max_plain0 <= fixed_plain0)
        return -1;
    uint32_t half1 = max_plain0 - fixed_plain0;
    if (half1 >= app_len)
        half1 = app_len - 1;
    uint32_t half2 = app_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    const uint8_t *eth_hdr = pkt_data;
    const uint8_t *ip_hdr = pkt_data + 14;
    const uint8_t *wire_ports = pkt_data + transport_off;

    uint32_t frag0_plain_len = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len + half1;

    if (crypto_layer4_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len, wire_ports,
                                              pkt_data + app_off + half1, half2, pkt_id, 1,
                                              frag1, frag1_max, frag1_len) != 0)
        return -1;
    if (crypto_layer4_encrypt_fragment0_inplace(ctx, pkt_data, ip_hdr_len, frag0_plain_len,
                                                pkt_id, frag0_max, frag0_len) != 0)
        return -1;
    return 0;
}

int frag_is_fragment_l4(const struct app_config *cfg,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index) {
    if (!cfg)
        return 0;
    if (pkt_len < 14 + 20 + 8) return 0;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    if (ether_type != 0x0800) return 0;

    uint8_t ip_proto = pkt_data[14 + 9];
    if (ip_proto != 6 && ip_proto != 17) return 0;

    int ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20) return 0;

    int transport_off = 14 + ip_hdr_len;
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + crypto_layer4_wire_port_len();
    int ns = PACKET_CRYPTO_NONCE_BYTES;

    if (pkt_len < (uint32_t)(tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE))
        return 0;
    if (tunnel_off + ns + 1 >= (int)pkt_len)
        return 0;
    if (pkt_data[tunnel_off + ns + 1] != CRYPTO_L4_FRAG_MAGIC)
        return 0;

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L4)
            continue;
        if (pkt_data[tunnel_off + ns] != (uint8_t)cp->id)
            continue;
        frag_read_hdr(pkt_data + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);
        return (*frag_index <= 1) ? 1 : 0;
    }
    return 0;
}

int frag_try_reassemble_l4(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len) {
    if (pkt_len < 14 + 20) return -1;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    if (ether_type != 0x0800) return -1;

    int ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    int idx = pkt_id % FRAG_TABLE_SIZE;
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();

    if (frag_index == 0) {
        int wire_ports = crypto_layer4_wire_port_len();
        uint32_t plain_len = payload_len > (uint32_t)wire_ports
                                 ? payload_len - (uint32_t)wire_ports
                                 : 0;
        const uint8_t *plain = payload + wire_ports;
        if (plain_len < 28 || (plain[0] >> 4) != 4)
            return -1;
        int inner_ip_hdr_len = (plain[0] & 0x0F) * 4;
        if (inner_ip_hdr_len < 20 || plain_len < (uint32_t)(inner_ip_hdr_len + 8))
            return -1;
        uint8_t inner_proto = plain[9];
        if (inner_proto != 6 && inner_proto != 17)
            return -1;

        if (frag_store_first(entry, pkt_id, pkt_data, ETH_HEADER_SIZE, plain, plain_len, now) != 0)
            return -1;
        int joined = frag_emit_join(entry, out_buf, out_len);
        return joined;
    }

    if (frag_index == 1) {
        if ((entry->got_first || entry->got_second) && entry->pkt_id == pkt_id &&
            (now - entry->timestamp_ns) > FRAG_TIMEOUT_NS)
            memset(entry, 0, sizeof(*entry));
        int wire_ports = crypto_layer4_wire_port_len();
        uint32_t second_half_len = payload_len > (uint32_t)wire_ports
                                       ? payload_len - (uint32_t)wire_ports
                                       : 0;
        if (second_half_len == 0)
            return -1;
        if (frag_store_second(entry, pkt_id, payload + wire_ports, second_half_len, now) != 0)
            return -1;
        int joined = frag_emit_join(entry, out_buf, out_len);
        return joined;
    }

    return -1;
}