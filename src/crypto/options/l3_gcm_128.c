#define _POSIX_C_SOURCE 199309L

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/cpu_map.h"

#include <string.h>
#include <time.h>

#define MIN_ETH_PKT             (ETH_HEADER_SIZE + 8)
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

/* wire — local to this option */
#define OPT_FAKE_PROTOCOL   99
#define OPT_AES_BITS        128
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



#define L3_FRAG_MAGIC           0x5C
#define L3_FRAG_TAG_SIZE        4
#define L3_TUNNEL_HDR_SIZE      (PACKET_CRYPTO_NONCE_BYTES + 2)
#define L3_IPV4_PROTO_OFF       (ETH_HEADER_SIZE + 9)
#define L3_IPV4_TOTLEN_OFF      (ETH_HEADER_SIZE + 2)

static int l3_pkt_is_ipv4(const uint8_t *packet, size_t pkt_len)
{
    if (pkt_len < ETH_HEADER_SIZE + 20)
        return 0;
    return ((((uint16_t)packet[12] << 8) | packet[13]) == 0x0800);
}

static int l3_ipv4_hdr_len_at(const uint8_t *packet, size_t pkt_len, int l3_off)
{
    if (pkt_len < (size_t)l3_off + 20)
        return -1;
    int ihl = (packet[l3_off] & 0x0F) * 4;
    if (ihl < 20 || pkt_len < (size_t)(l3_off + ihl))
        return -1;
    return ihl;
}

static void l3_patch_ipv4_fast(uint8_t *ip, uint16_t new_totlen, uint8_t new_proto)
{
    uint16_t old_totlen = ((uint16_t)ip[2] << 8) | ip[3];
    uint8_t old_proto = ip[9];
    uint16_t old_ttl_proto = ((uint16_t)ip[8] << 8) | old_proto;
    uint16_t new_ttl_proto = ((uint16_t)ip[8] << 8) | new_proto;

    if (old_totlen != new_totlen) {
        ip[2] = (uint8_t)(new_totlen >> 8);
        ip[3] = (uint8_t)(new_totlen & 0xFF);
        crypto_ipv4_checksum_replace_word(ip, old_totlen, new_totlen);
    }
    if (old_proto != new_proto) {
        ip[9] = new_proto;
        crypto_ipv4_checksum_replace_word(ip, old_ttl_proto, new_ttl_proto);
    }
}

static void l3_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size,
                                        uint8_t policy_id)
{
    memcpy(buf, nonce, (size_t)nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = L3_FRAG_MAGIC;
}

static int l3_is_frag_tunnel(const uint8_t *tunnel, int nonce_size)
{
    return tunnel[nonce_size + 1] == L3_FRAG_MAGIC;
}


static void l3_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size,
                                   uint8_t policy_id, uint8_t orig_proto)
{
    memcpy(buf, nonce, (size_t)nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = orig_proto;
}

static void l3_read_tunnel_header(const uint8_t *buf, int nonce_size, uint8_t *nonce_out,
                                  uint8_t *proto_flag, uint8_t *policy_id, uint8_t *orig_proto)
{
    memcpy(nonce_out, buf, (size_t)nonce_size);
    if (proto_flag)
        *proto_flag = buf[0] >> 7;
    if (policy_id)
        *policy_id = buf[nonce_size];
    if (orig_proto)
        *orig_proto = buf[nonce_size + 1];
}


#define OPT_FRAG_META_LEN       34


static int l3_do_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int tunnel_off, uint8_t *ip, uint16_t old_totlen, uint8_t fake_proto)
{
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t orig_proto = packet[L3_IPV4_PROTO_OFF];
    size_t payload_len = pkt_len - (size_t)tunnel_off;
    int enc_off = tunnel_off + L3_TUNNEL_HDR_SIZE;
    uint8_t tag[AES_GCM_TAG_SIZE];
    int total_overhead;

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    memmove(packet + enc_off, packet + tunnel_off, payload_len);
    l3_write_tunnel_header(packet + tunnel_off, nonce, PACKET_CRYPTO_NONCE_BYTES,
                                  ctx->wire_id, orig_proto);
    if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off, (int)payload_len, tag, OPT_AES_BITS) != 0)
        return -1;
    memcpy(packet + enc_off + payload_len, tag, AES_GCM_TAG_SIZE);
    total_overhead = L3_TUNNEL_HDR_SIZE + AES_GCM_TAG_SIZE;
    l3_patch_ipv4_fast(ip, old_totlen + (uint16_t)total_overhead, fake_proto);
    return (int)(pkt_len + (size_t)total_overhead);

}


static int l3_do_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                         int tunnel_off, uint8_t *ip, uint16_t old_totlen)
{
    uint8_t orig_proto;
    uint8_t nonce[16];
    int enc_off = tunnel_off + L3_TUNNEL_HDR_SIZE;
    size_t total_after = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];
    const uint8_t *key;

    l3_read_tunnel_header(packet + tunnel_off, PACKET_CRYPTO_NONCE_BYTES,
                                 nonce, NULL, NULL, &orig_proto);
    if (total_after < AES_GCM_TAG_SIZE)
        return -1;
    enc_len = total_after - AES_GCM_TAG_SIZE;
    memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;
    if (crypto_aes_gcm_decrypt(key, nonce, PACKET_CRYPTO_NONCE_BYTES, packet + enc_off,
                               (int)enc_len, tag, OPT_AES_BITS) != 0)
        return -1;
    memmove(packet + tunnel_off, packet + enc_off, enc_len);
    l3_patch_ipv4_fast(ip, old_totlen - (uint16_t)(L3_TUNNEL_HDR_SIZE + AES_GCM_TAG_SIZE), orig_proto);
    return (int)(pkt_len - (size_t)(L3_TUNNEL_HDR_SIZE + AES_GCM_TAG_SIZE));

}


static int l3_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len, uint8_t fake_proto)
{

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int enc_off = tunnel_off + L3_TUNNEL_HDR_SIZE + L3_FRAG_TAG_SIZE;
    uint8_t tag[AES_GCM_TAG_SIZE];
    size_t need = (size_t)enc_off + enc_plain_len + AES_GCM_TAG_SIZE;
    size_t ip_payload_len;

    if (need > out_max)
        return -1;
    memcpy(out_buf, eth_hdr, ETH_HEADER_SIZE);
    memcpy(out_buf + ETH_HEADER_SIZE, ip_hdr, (size_t)ip_hdr_len);
    counter = packet_crypto_next_counter();
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    packet_crypto_update_keys(ctx);
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;
    memmove(out_buf + enc_off, enc_plain, enc_plain_len);
    l3_write_tunnel_header_frag(out_buf + tunnel_off, nonce, PACKET_CRYPTO_NONCE_BYTES, ctx->wire_id);
    opt_write_frag_tag(out_buf + tunnel_off + L3_TUNNEL_HDR_SIZE, pkt_id, frag_index);
    if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, out_buf + enc_off, (int)enc_plain_len, tag, OPT_AES_BITS) != 0)
        return -1;
    memcpy(out_buf + enc_off + enc_plain_len, tag, AES_GCM_TAG_SIZE);
    ip_payload_len = (size_t)(L3_TUNNEL_HDR_SIZE + L3_FRAG_TAG_SIZE + enc_plain_len + AES_GCM_TAG_SIZE);
    l3_patch_ipv4_fast(out_buf + ETH_HEADER_SIZE, (uint16_t)(ip_hdr_len + ip_payload_len), fake_proto);
    *out_len = (uint32_t)need;
    return 0;
}


static int l3_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len)
{
    uint8_t *ip = packet + ETH_HEADER_SIZE;
    uint8_t fake_proto = OPT_FAKE_PROTOCOL;
    int tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    int enc_off = tunnel_off + L3_TUNNEL_HDR_SIZE + L3_FRAG_TAG_SIZE;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const uint8_t *key;
    uint8_t tag[AES_GCM_TAG_SIZE];
    size_t need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;

    if (need > out_max)
        return -1;
    memmove(packet + enc_off, ip, frag0_plain_len);
    counter = packet_crypto_next_counter();
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
    packet_crypto_update_keys(ctx);
    key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;
    l3_write_tunnel_header_frag(packet + tunnel_off, nonce, PACKET_CRYPTO_NONCE_BYTES, ctx->wire_id);
    opt_write_frag_tag(packet + tunnel_off + L3_TUNNEL_HDR_SIZE, pkt_id, 0);
    if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off, (int)frag0_plain_len, tag, OPT_AES_BITS) != 0)
        return -1;
    memcpy(packet + enc_off + frag0_plain_len, tag, AES_GCM_TAG_SIZE);
    l3_patch_ipv4_fast(ip, (uint16_t)(ip_hdr_len + L3_TUNNEL_HDR_SIZE + L3_FRAG_TAG_SIZE +
                                      frag0_plain_len + AES_GCM_TAG_SIZE), fake_proto);
    *out_len = (uint32_t)need;
    return 0;
}


static int l3_decrypt_fragment_body(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                                    int tunnel_off, int enc_off)
{
    uint8_t nonce[16];
    size_t total_after = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];
    uint8_t backup[2048];
    int has_backup;
    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    memcpy(nonce, packet + tunnel_off, PACKET_CRYPTO_NONCE_BYTES);
    if (total_after < AES_GCM_TAG_SIZE)
        return -1;
    enc_len = total_after - AES_GCM_TAG_SIZE;
    memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);
    has_backup = (enc_len <= sizeof(backup));
    if (has_backup)
        memcpy(backup, packet + enc_off, enc_len);
    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        uint8_t *work = packet + enc_off;
        if (!key)
            continue;
        if (k > 0 && has_backup)
            memcpy(work, backup, enc_len);
        if (crypto_aes_gcm_decrypt(key, nonce, PACKET_CRYPTO_NONCE_BYTES, work, (int)enc_len, tag, OPT_AES_BITS) != 0)
            continue;
        memmove(packet + tunnel_off, packet + enc_off, enc_len);
        return (int)(tunnel_off + enc_len);
    }
    return -1;

}


static int l3_decrypt_fragment(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len,
                               uint16_t *out_pkt_id, uint8_t *out_frag_index)
{
    int ip_hdr_len;
    int tunnel_off;
    int enc_off;

    if (!ctx || !packet || !out_pkt_id || !out_frag_index)
        return -1;
    if (!l3_pkt_is_ipv4(packet, pkt_len))
        return -1;
    ip_hdr_len = l3_ipv4_hdr_len_at(packet, pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return -1;
    if (packet[L3_IPV4_PROTO_OFF] != OPT_FAKE_PROTOCOL)
        return -1;
    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    enc_off = tunnel_off + L3_TUNNEL_HDR_SIZE + L3_FRAG_TAG_SIZE;
    if (pkt_len < (size_t)enc_off)
        return -1;
    if (!l3_is_frag_tunnel(packet + tunnel_off, PACKET_CRYPTO_NONCE_BYTES))
        return -1;
    opt_read_frag_tag(packet + tunnel_off + L3_TUNNEL_HDR_SIZE, out_pkt_id, out_frag_index);
    return l3_decrypt_fragment_body(ctx, packet, pkt_len, tunnel_off, enc_off);
}


static int l3_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                    size_t frag0_max, uint32_t *frag0_len,
                    uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    uint32_t frag_mtu = crypto_option_get_mtu();
    int l3_off = crypto_eth_ipv4_offset(pkt_data, pkt_len);
    const uint8_t *eth_hdr;
    const uint8_t *ip_hdr;
    int ip_hdr_len;
    uint8_t ip_proto;
    const uint8_t *ip_payload;
    uint32_t ip_payload_len;
    int transport_hdr_len = -1;
    uint32_t app_off = 0;
    uint32_t app_len;
    uint32_t frag_overhead;
    uint32_t max_plain0;
    uint32_t fixed_plain0;
    uint32_t half1;
    uint32_t half2;
    uint16_t pkt_id;
    uint32_t frag0_plain_len;
    const uint8_t *frag1_plain;
    uint8_t fake_proto = OPT_FAKE_PROTOCOL;

    if (l3_off < 0 || l3_off != ETH_HEADER_SIZE)
        return -1;
    eth_hdr = pkt_data;
    ip_hdr = pkt_data + l3_off;
    ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    if ((ip_hdr[0] >> 4) != 4 || ip_hdr_len < 20 ||
        pkt_len < (uint32_t)(l3_off + ip_hdr_len))
        return -1;
    ip_proto = ip_hdr[9];
    ip_payload = pkt_data + l3_off + ip_hdr_len;
    ip_payload_len = pkt_len - (uint32_t)l3_off - (uint32_t)ip_hdr_len;
    if (ip_proto == 6 || ip_proto == 17) {
        transport_hdr_len = opt_transport_hdr_size(ip_payload, ip_proto, ip_payload_len);
        if (transport_hdr_len < 0)
            return -1;
        app_off = (uint32_t)transport_hdr_len;
        app_len = ip_payload_len - app_off;
    } else {
        app_len = ip_payload_len;
    }
    if (app_len == 0)
        return -1;
    frag_overhead = (uint32_t)l3_off + (uint32_t)ip_hdr_len + (uint32_t)OPT_FRAG_META_LEN;
    if (frag_overhead >= frag_mtu)
        return -1;
    max_plain0 = frag_mtu - frag_overhead;
    fixed_plain0 = (uint32_t)ip_hdr_len + app_off;
    if (max_plain0 <= fixed_plain0)
        return -1;
    half1 = max_plain0 - fixed_plain0;
    if (half1 >= app_len)
        half1 = app_len - 1;
    half2 = app_len - half1;
    pkt_id = crypto_option_next_pkt_id();
    if (transport_hdr_len >= 0)
        frag0_plain_len = (uint32_t)ip_hdr_len + (uint32_t)transport_hdr_len + half1;
    else
        frag0_plain_len = (uint32_t)ip_hdr_len + half1;
    frag1_plain = (transport_hdr_len >= 0) ? ip_payload + app_off + half1 : ip_payload + half1;
    if (l3_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len, frag1_plain, half2,
                                   pkt_id, 1, frag1, frag1_max, frag1_len, fake_proto) != 0)
        return -1;
    if (l3_encrypt_fragment0_inplace(ctx, pkt_data, ip_hdr_len, frag0_plain_len, pkt_id,
                                     frag0_max, frag0_len) != 0)
        return -1;
    return 0;
}


static int l3_reassemble(struct opt_table *ft, const uint8_t *pkt_data, uint32_t pkt_len,
                         uint16_t pkt_id, uint8_t frag_index,
                         uint8_t *out_buf, uint32_t *out_len)
{
    int ip_hdr_len;
    const uint8_t *inner;
    uint32_t inner_len;
    uint64_t now;
    int idx;
    struct opt_entry *entry;

    if (pkt_len < 14 + 20)
        return -1;
    if ((((uint16_t)pkt_data[12] << 8) | pkt_data[13]) != 0x0800)
        return -1;
    ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20 || pkt_len < (uint32_t)(ETH_HEADER_SIZE + ip_hdr_len + 1))
        return -1;
    inner = pkt_data + ETH_HEADER_SIZE + ip_hdr_len;
    inner_len = pkt_len - (uint32_t)(ETH_HEADER_SIZE + ip_hdr_len);
    now = opt_time_ns();
    idx = opt_pick_slot(ft, pkt_id, now);
    entry = &ft->entries[idx];
    if (frag_index == 0) {
        if (inner_len < 20 || (inner[0] >> 4) != 4)
            return -1;
        {
            int inner_ihl = (inner[0] & 0x0F) * 4;
            if (inner_ihl < 20 || inner_len < (uint32_t)inner_ihl)
                return -1;
        }
        if (opt_store_first(entry, pkt_id, pkt_data, ETH_HEADER_SIZE, inner, inner_len, now) != 0)
            return -1;
        return opt_emit_join(entry, out_buf, out_len);
    }
    if (frag_index == 1) {
        if ((entry->got_first || entry->got_second) && entry->pkt_id == pkt_id &&
            (now - entry->timestamp_ns) > OPT_FRAG_TIMEOUT_NS)
            memset(entry, 0, sizeof(*entry));
        if (opt_store_second(entry, pkt_id, inner, inner_len, now) != 0)
            return -1;
        return opt_emit_join(entry, out_buf, out_len);
    }
    return -1;
}


int crypto_opt_l3_gcm128_need_split(uint32_t pkt_len)
{
    return (pkt_len + OPT_FRAG_META_LEN) > crypto_option_get_mtu();
}

int crypto_opt_l3_gcm128_split(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                           size_t frag0_max, uint32_t *frag0_len,
                           uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    return l3_split(ctx, pkt_data, pkt_len, frag0_max, frag0_len, frag1, frag1_max, frag1_len);
}


int crypto_opt_l3_gcm128_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int ip_hdr_len;
    int tunnel_off;
    int n;
    uint8_t *ip;
    uint16_t old_totlen;
    uint8_t fake_proto;

    if (!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT)
        return -1;
    if (!l3_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    ip_hdr_len = l3_ipv4_hdr_len_at(pkt, *pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return -1;
    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    if (pkt[L3_IPV4_PROTO_OFF] == OPT_FAKE_PROTOCOL &&
        *pkt_len >= (uint32_t)(tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 2) &&
        l3_is_frag_tunnel(pkt + tunnel_off, PACKET_CRYPTO_NONCE_BYTES))
        return 0;
    ip = pkt + ETH_HEADER_SIZE;
    old_totlen = ((uint16_t)pkt[L3_IPV4_TOTLEN_OFF] << 8) | pkt[L3_IPV4_TOTLEN_OFF + 1];
    fake_proto = OPT_FAKE_PROTOCOL;
    n = l3_do_encrypt(ctx, pkt, *pkt_len, tunnel_off, ip, old_totlen, fake_proto);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}


int crypto_opt_l3_gcm128_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    int ip_hdr_len;
    int tunnel_off;
    int n;
    uint8_t *ip;
    uint16_t old_totlen;

    if (!ctx || !ctx->initialized || !pkt || *pkt_len < MIN_ETH_PKT)
        return -1;
    if (!l3_pkt_is_ipv4(pkt, *pkt_len))
        return 0;
    ip_hdr_len = l3_ipv4_hdr_len_at(pkt, *pkt_len, ETH_HEADER_SIZE);
    if (ip_hdr_len < 0)
        return 0;
    tunnel_off = ETH_HEADER_SIZE + ip_hdr_len;
    if (*pkt_len < (uint32_t)(tunnel_off + L3_TUNNEL_HDR_SIZE))
        return 0;
    if (pkt[tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 1] == L3_FRAG_MAGIC)
        return 0;
    if (pkt[L3_IPV4_PROTO_OFF] != OPT_FAKE_PROTOCOL)
        return 0;
    ip = pkt + ETH_HEADER_SIZE;
    old_totlen = ((uint16_t)pkt[L3_IPV4_TOTLEN_OFF] << 8) | pkt[L3_IPV4_TOTLEN_OFF + 1];
    n = l3_do_decrypt(ctx, pkt, *pkt_len, tunnel_off, ip, old_totlen);
    if (n < 0)
        return -1;
    *pkt_len = (uint32_t)n;
    return 0;
}


int crypto_opt_l3_gcm128_is_fragment(const struct app_config *cfg, const uint8_t *pkt_data,
                                 uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index)
{
    int ip_hdr_len;
    int tunnel_off;
    uint8_t wire_pol;

    if (!cfg || !pkt_id || !frag_index)
        return 0;
    if (pkt_len < 14 + 20)
        return 0;
    if ((((uint16_t)pkt_data[12] << 8) | pkt_data[13]) != 0x0800)
        return 0;
    if (pkt_data[14 + 9] != OPT_FAKE_PROTOCOL)
        return 0;
    ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return 0;
    tunnel_off = 14 + ip_hdr_len;
    if (pkt_len < (uint32_t)(tunnel_off + L3_TUNNEL_HDR_SIZE + L3_FRAG_TAG_SIZE))
        return 0;
    if (tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 1 >= (int)pkt_len)
        return 0;
    if (pkt_data[tunnel_off + PACKET_CRYPTO_NONCE_BYTES + 1] != L3_FRAG_MAGIC)
        return 0;
    wire_pol = pkt_data[tunnel_off + PACKET_CRYPTO_NONCE_BYTES];
    if (!opt_policy_match(cfg, POLICY_ACTION_ENCRYPT_L3, CRYPTO_MODE_GCM, 128, wire_pol))
        return 0;
    opt_read_frag_tag(pkt_data + tunnel_off + L3_TUNNEL_HDR_SIZE, pkt_id, frag_index);
    return (*frag_index <= 1) ? 1 : 0;
}


int crypto_opt_l3_gcm128_reasm(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx,
                           uint8_t *pkt_data, uint32_t *pkt_len,
                           uint8_t *out_buf, uint32_t *out_len)
{
    int nd;
    uint16_t opid = 0;
    uint8_t ofidx = 0;
    int rr;

    if (!ctx || !pkt_data || !pkt_len || !out_buf || !out_len)
        return -1;
    nd = l3_decrypt_fragment(ctx, pkt_data, *pkt_len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    *pkt_len = (uint32_t)nd;
    rr = l3_reassemble(opt_table(profile_slot, worker_idx), pkt_data, *pkt_len,
                     opid, ofidx, out_buf, out_len);
    if (rr == 1)
        *pkt_len = *out_len;
    return rr;
}

void crypto_opt_l3_gcm128_frag_gc(int profile_slot, int worker_idx, uint64_t now_ns)
{
    opt_frag_gc_table(opt_table(profile_slot, worker_idx), now_ns);
}
