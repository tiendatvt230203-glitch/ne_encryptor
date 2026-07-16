#define _POSIX_C_SOURCE 199309L

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/cpu_map.h"
#include "../../../inc/crypto/crypto_pqc_layer.h"

#include <string.h>
#include <time.h>

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

/* wire — local to this option */
#define OPT_IS_PQC          1
#define OPT_AES_BITS        256
#define OPT_NONCE_SIZE      PACKET_CRYPTO_NONCE_BYTES



struct opt_entry {
    uint16_t pkt_id;
    uint8_t  first[1600];
    uint8_t  second[1600];
    uint32_t first_len;
    uint32_t second_len;
    uint8_t  eth_hdr[ETH_L2_HDR_MAX];
    uint8_t  eth_len;
    uint64_t timestamp_ns;
    uint8_t  got_first;
    uint8_t  got_second;
};

struct opt_table {
    struct opt_entry entries[OPT_FRAG_TABLE_SIZE];
};

static struct opt_table g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS];

static uint64_t opt_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}


static void opt_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index)
{
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

static void opt_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index)
{
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

static void opt_prepare_entry(struct opt_entry *entry, uint16_t pkt_id, uint64_t now)
{
    if (entry->pkt_id != pkt_id ||
        ((entry->got_first || entry->got_second) &&
         (now - entry->timestamp_ns) > OPT_FRAG_TIMEOUT_NS))
        memset(entry, 0, sizeof(*entry));
    entry->pkt_id = pkt_id;
    entry->timestamp_ns = now;
}

static int opt_pick_slot(struct opt_table *ft, uint16_t pkt_id, uint64_t now)
{
    const int probe = 8;
    int base = (int)(pkt_id % OPT_FRAG_TABLE_SIZE);
    int empty_idx = -1;
    int oldest_idx = -1;
    uint64_t oldest_age = 0;

    for (int i = 0; i < probe; i++) {
        int idx = (base + i) % OPT_FRAG_TABLE_SIZE;
        struct opt_entry *e = &ft->entries[idx];
        int occupied = (e->got_first || e->got_second);

        if (occupied && (now - e->timestamp_ns) > OPT_FRAG_TIMEOUT_NS) {
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

        {
            uint64_t age = now - e->timestamp_ns;
            if (oldest_idx < 0 || age > oldest_age) {
                oldest_idx = idx;
                oldest_age = age;
            }
        }
    }
    if (empty_idx >= 0)
        return empty_idx;
    if (oldest_idx >= 0)
        return oldest_idx;
    return base;
}

static int opt_store_first(struct opt_entry *entry, uint16_t pkt_id,
                           const uint8_t *eth, uint8_t eth_len,
                           const uint8_t *data, uint32_t data_len, uint64_t now)
{
    if (data_len > sizeof(entry->first))
        return -1;
    if (eth_len == 0 || eth_len > sizeof(entry->eth_hdr))
        return -1;
    opt_prepare_entry(entry, pkt_id, now);
    entry->first_len = data_len;
    memcpy(entry->first, data, data_len);
    memcpy(entry->eth_hdr, eth, eth_len);
    entry->eth_len = eth_len;
    entry->got_first = 1;
    return 0;
}

static int opt_store_second(struct opt_entry *entry, uint16_t pkt_id,
                            const uint8_t *data, uint32_t data_len, uint64_t now)
{
    if (data_len > sizeof(entry->second))
        return -1;
    opt_prepare_entry(entry, pkt_id, now);
    entry->second_len = data_len;
    memcpy(entry->second, data, data_len);
    entry->got_second = 1;
    return 0;
}

static int opt_emit_join(struct opt_entry *entry, uint8_t *out_buf, uint32_t *out_len)
{
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

static void opt_frag_gc_table(struct opt_table *ft, uint64_t now_ns)
{
    for (int i = 0; i < OPT_FRAG_TABLE_SIZE; i++) {
        struct opt_entry *e = &ft->entries[i];
        if ((e->got_first || e->got_second) &&
            (now_ns - e->timestamp_ns) > OPT_FRAG_TIMEOUT_NS)
            memset(e, 0, sizeof(*e));
    }
}

static struct opt_table *opt_table(int profile_slot, int worker_idx)
{
    if (profile_slot < 0 || profile_slot >= MAX_PROFILES)
        profile_slot = 0;
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        worker_idx = 0;
    return &g_tables[profile_slot][worker_idx];
}

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

static void l4_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size,
                                        uint8_t policy_id)
{
    memcpy(buf, nonce, (size_t)nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = L4_FRAG_MAGIC;
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

#define OPT_FRAG_META_LEN       38


static int l4_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int l3_off, int ip_hdr_len, int plain_off, size_t plain_len)
{
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int tunnel_off = plain_off;
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE;
    int new_len = 0;
    int total_overhead;
    size_t ip_payload_len;

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    memmove(packet + enc_off, packet + plain_off, plain_len);
    l4_write_tunnel_header(packet + tunnel_off, nonce, CRYPTO_PQC_NONCE_BYTES, ctx->wire_id);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off, (int)plain_len, &new_len) != 0)
        return -1;
    total_overhead = L4_TUNNEL_HDR_SIZE + AES_GCM_TAG_SIZE;
    ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + plain_len;
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
    return (int)(pkt_len + (size_t)total_overhead);

}


static int l4_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int l3_off, int ip_hdr_len, int transport_off, int tunnel_off)
{
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE;
    int dec_len = 0;
    int total_overhead = L4_TUNNEL_HDR_SIZE + AES_GCM_TAG_SIZE;
    int new_len;
    size_t ip_payload_len;

    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    memcpy(nonce, packet + tunnel_off, CRYPTO_PQC_NONCE_BYTES);
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
        return -1;
    memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
    new_len = (int)(pkt_len - (size_t)total_overhead);
    ip_payload_len = (size_t)(new_len - l3_off - ip_hdr_len);
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
    return new_len;

}


static int l4_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports, const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len)
{

    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int total_overhead = L4_TUNNEL_HDR_SIZE + L4_FRAG_TAG_SIZE + AES_GCM_TAG_SIZE;
    size_t need = (size_t)(14 + ip_hdr_len + L4_WIRE_PORT_LEN + total_overhead + enc_plain_len);
    int offset = 0;
    int tunnel_off;
    int enc_off;
    int new_len = 0;
    size_t ip_payload_len;

    if (need > out_max)
        return -1;
    memcpy(out_buf, eth_hdr, 14);
    offset += 14;
    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;
    memcpy(out_buf + offset, wire_ports, L4_WIRE_PORT_LEN);
    offset += L4_WIRE_PORT_LEN;
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    tunnel_off = offset;
    enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE + L4_FRAG_TAG_SIZE;
    memmove(out_buf + enc_off, enc_plain, enc_plain_len);
    l4_write_tunnel_header_frag(out_buf + tunnel_off, nonce, CRYPTO_PQC_NONCE_BYTES, ctx->wire_id);
    opt_write_frag_tag(out_buf + tunnel_off + L4_TUNNEL_HDR_SIZE, pkt_id, frag_index);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, out_buf + enc_off, (int)enc_plain_len, &new_len) != 0)
        return -1;
    ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + new_len;
    l4_fix_ipv4_totlen_and_cksum(out_buf, 14, ip_hdr_len, ip_payload_len);
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}


static int l4_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len)
{
    uint8_t *ip = packet + 14;
    uint8_t wire_ports[L4_WIRE_PORT_LEN];
    int tunnel_off = 14 + ip_hdr_len + L4_WIRE_PORT_LEN;
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE + L4_FRAG_TAG_SIZE;
    memcpy(wire_ports, packet + 14 + ip_hdr_len, L4_WIRE_PORT_LEN);

    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int total_overhead = L4_TUNNEL_HDR_SIZE + L4_FRAG_TAG_SIZE + AES_GCM_TAG_SIZE;
    int new_len = 0;
    size_t need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;

    if (need > out_max)
        return -1;
    memmove(packet + enc_off, ip, frag0_plain_len);
    memcpy(packet + 14 + ip_hdr_len, wire_ports, L4_WIRE_PORT_LEN);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_generate_nonce(nonce) != 0)
        return -1;
    l4_write_tunnel_header_frag(packet + tunnel_off, nonce, CRYPTO_PQC_NONCE_BYTES, ctx->wire_id);
    opt_write_frag_tag(packet + tunnel_off + L4_TUNNEL_HDR_SIZE, pkt_id, 0);
    if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off, (int)frag0_plain_len, &new_len) != 0)
        return -1;
    l4_fix_ipv4_totlen_and_cksum(packet, 14, ip_hdr_len,
                                 L4_WIRE_PORT_LEN + (size_t)total_overhead + new_len);
    *out_len = (uint32_t)(enc_off + new_len);
    return 0;
}


static int l4_decrypt_fragment_body(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                                    int transport_off, int tunnel_off)
{
    crypto_pqc_sess_t pqc;
    byte nonce[CRYPTO_PQC_NONCE_BYTES];
    int enc_off = tunnel_off + L4_TUNNEL_HDR_SIZE + L4_FRAG_TAG_SIZE;
    int dec_len = 0;

    memcpy(nonce, packet + tunnel_off, CRYPTO_PQC_NONCE_BYTES);
    if (crypto_pqc_sess_load(ctx, &pqc) != 0)
        return -1;
    if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                   (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
        return -1;
    memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
    return (int)(transport_off + L4_WIRE_PORT_LEN + dec_len);

}


static int l4_decrypt_fragment(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                               uint16_t *out_pkt_id, uint8_t *out_frag_index)
{
    int l3_off;
    uint8_t ip_proto;
    int ip_hdr_len;
    int transport_off;
    int tunnel_off;

    if (!ctx || !packet || !out_pkt_id || !out_frag_index)
        return -1;
    l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (size_t)l3_off + 20)
        return -1;
    ip_proto = packet[l3_off + 9];
    ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    transport_off = l3_off + ip_hdr_len;
    if (pkt_len < (size_t)transport_off)
        return -1;
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return -1;
    tunnel_off = transport_off + L4_WIRE_PORT_LEN;
    if (pkt_len < (size_t)(tunnel_off + L4_TUNNEL_HDR_SIZE + L4_FRAG_TAG_SIZE))
        return -1;
    if (packet[tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 1] != L4_FRAG_MAGIC)
        return -1;
    opt_read_frag_tag(packet + tunnel_off + L4_TUNNEL_HDR_SIZE, out_pkt_id, out_frag_index);
    return l4_decrypt_fragment_body(ctx, packet, pkt_len, transport_off, tunnel_off);
}


static int l4_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                    size_t frag0_max, uint32_t *frag0_len,
                    uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    uint32_t frag_mtu = crypto_option_get_mtu();
    int ip_hdr_len;
    int transport_off;
    int transport_hdr_len;
    int app_off;
    uint32_t app_len;
    uint32_t frag_overhead;
    uint32_t max_plain0;
    uint32_t fixed_plain0;
    uint32_t half1;
    uint32_t half2;
    uint16_t pkt_id;
    const uint8_t *eth_hdr;
    const uint8_t *ip_hdr;
    const uint8_t *wire_ports;
    uint32_t frag0_plain_len;

    if (pkt_len < 14 + 20 + 8)
        return -1;
    if ((((uint16_t)pkt_data[12] << 8) | pkt_data[13]) != 0x0800)
        return -1;
    if (pkt_data[14 + 9] != 6 && pkt_data[14 + 9] != 17)
        return -1;
    ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    transport_off = 14 + ip_hdr_len;
    if (pkt_len < (uint32_t)transport_off)
        return -1;
    transport_hdr_len = opt_transport_hdr_size(pkt_data + transport_off, pkt_data[14 + 9],
                                               pkt_len - transport_off);
    if (transport_hdr_len < 0)
        return -1;
    app_off = transport_off + transport_hdr_len;
    app_len = pkt_len - app_off;
    if (app_len == 0)
        return -1;
    frag_overhead = 14u + (uint32_t)ip_hdr_len + (uint32_t)OPT_FRAG_META_LEN;
    if (frag_overhead >= frag_mtu)
        return -1;
    max_plain0 = frag_mtu - frag_overhead;
    fixed_plain0 = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len;
    if (max_plain0 <= fixed_plain0)
        return -1;
    half1 = max_plain0 - fixed_plain0;
    if (half1 >= app_len)
        half1 = app_len - 1;
    half2 = app_len - half1;
    pkt_id = crypto_option_next_pkt_id();
    eth_hdr = pkt_data;
    ip_hdr = pkt_data + 14;
    wire_ports = pkt_data + transport_off;
    frag0_plain_len = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len + half1;
    if (l4_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len, wire_ports,
                                   pkt_data + app_off + half1, half2, pkt_id, 1,
                                   frag1, frag1_max, frag1_len) != 0)
        return -1;
    if (l4_encrypt_fragment0_inplace(ctx, pkt_data, ip_hdr_len, frag0_plain_len, pkt_id,
                                     frag0_max, frag0_len) != 0)
        return -1;
    return 0;
}


static int l4_reassemble(struct opt_table *ft, const uint8_t *pkt_data, uint32_t pkt_len,
                         uint16_t pkt_id, uint8_t frag_index,
                         uint8_t *out_buf, uint32_t *out_len)
{
    int ip_hdr_len;
    const uint8_t *payload;
    uint32_t payload_len;
    uint64_t now;
    int idx;
    struct opt_entry *entry;

    if (pkt_len < 14 + 20)
        return -1;
    if ((((uint16_t)pkt_data[12] << 8) | pkt_data[13]) != 0x0800)
        return -1;
    ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    payload = pkt_data + 14 + ip_hdr_len;
    payload_len = pkt_len - 14 - ip_hdr_len;
    now = opt_time_ns();
    idx = opt_pick_slot(ft, pkt_id, now);
    entry = &ft->entries[idx];
    if (frag_index == 0) {
        uint32_t plain_len = payload_len > L4_WIRE_PORT_LEN ? payload_len - L4_WIRE_PORT_LEN : 0;
        const uint8_t *plain = payload + L4_WIRE_PORT_LEN;
        if (plain_len < 28 || (plain[0] >> 4) != 4)
            return -1;
        {
            int inner_ip_hdr_len = (plain[0] & 0x0F) * 4;
            if (inner_ip_hdr_len < 20 || plain_len < (uint32_t)(inner_ip_hdr_len + 8))
                return -1;
        }
        if (plain[9] != 6 && plain[9] != 17)
            return -1;
        if (opt_store_first(entry, pkt_id, pkt_data, ETH_HEADER_SIZE, plain, plain_len, now) != 0)
            return -1;
        return opt_emit_join(entry, out_buf, out_len);
    }
    if (frag_index == 1) {
        uint32_t second_half_len = payload_len > L4_WIRE_PORT_LEN ? payload_len - L4_WIRE_PORT_LEN : 0;
        if (second_half_len == 0)
            return -1;
        if ((entry->got_first || entry->got_second) && entry->pkt_id == pkt_id &&
            (now - entry->timestamp_ns) > OPT_FRAG_TIMEOUT_NS)
            memset(entry, 0, sizeof(*entry));
        if (opt_store_second(entry, pkt_id, payload + L4_WIRE_PORT_LEN, second_half_len, now) != 0)
            return -1;
        return opt_emit_join(entry, out_buf, out_len);
    }
    return -1;
}


int crypto_opt_l4_pqc_need_split(uint32_t pkt_len)
{
    return (pkt_len + OPT_FRAG_META_LEN) > crypto_option_get_mtu();
}

int crypto_opt_l4_pqc_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                           size_t frag0_max, uint32_t *frag0_len,
                           uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    return l4_split(ctx, pkt_data, pkt_len, frag0_max, frag0_len, frag1, frag1_max, frag1_len);
}


int crypto_opt_l4_pqc_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
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


int crypto_opt_l4_pqc_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
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


int crypto_opt_l4_pqc_is_fragment(const struct app_config *cfg, const uint8_t *pkt_data,
                                 uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index)
{
    int ip_hdr_len;
    int tunnel_off;
    uint8_t wire_pol;

    if (!cfg || !pkt_id || !frag_index)
        return 0;
    if (pkt_len < 14 + 20 + 8)
        return 0;
    if ((((uint16_t)pkt_data[12] << 8) | pkt_data[13]) != 0x0800)
        return 0;
    if (pkt_data[14 + 9] != 6 && pkt_data[14 + 9] != 17)
        return 0;
    ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return 0;
    tunnel_off = 14 + ip_hdr_len + L4_WIRE_PORT_LEN;
    if (pkt_len < (uint32_t)(tunnel_off + L4_TUNNEL_HDR_SIZE + L4_FRAG_TAG_SIZE))
        return 0;
    if (tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 1 >= (int)pkt_len)
        return 0;
    if (pkt_data[tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 1] != L4_FRAG_MAGIC)
        return 0;
    wire_pol = pkt_data[tunnel_off + PACKET_CRYPTO_NONCE_BYTES];
    if (!opt_policy_match(cfg, POLICY_ACTION_ENCRYPT_L4, CRYPTO_MODE_PQC, 256, wire_pol))
        return 0;
    opt_read_frag_tag(pkt_data + tunnel_off + L4_TUNNEL_HDR_SIZE, pkt_id, frag_index);
    return (*frag_index <= 1) ? 1 : 0;
}


int crypto_opt_l4_pqc_reasm(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx,
                           uint8_t *pkt_data, uint32_t *pkt_len,
                           uint8_t *out_buf, uint32_t *out_len)
{
    int nd;
    uint16_t opid = 0;
    uint8_t ofidx = 0;
    int rr;

    if (!ctx || !pkt_data || !pkt_len || !out_buf || !out_len)
        return -1;
    nd = l4_decrypt_fragment(ctx, pkt_data, *pkt_len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    *pkt_len = (uint32_t)nd;
    rr = l4_reassemble(opt_table(profile_slot, worker_idx), pkt_data, *pkt_len,
                     opid, ofidx, out_buf, out_len);
    if (rr == 1)
        *pkt_len = *out_len;
    return rr;
}

void crypto_opt_l4_pqc_frag_gc(int profile_slot, int worker_idx, uint64_t now_ns)
{
    opt_frag_gc_table(opt_table(profile_slot, worker_idx), now_ns);
}
