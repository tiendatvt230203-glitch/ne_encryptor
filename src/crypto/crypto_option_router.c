#include "../../inc/crypto/crypto_option.h"
#include "../../inc/crypto/eth_parse.h"
#include "../../inc/core/interface.h"

#include <stdatomic.h>
#include <string.h>

/* ===================== worker bind ===================== */

static __thread uint8_t g_worker_idx;

void crypto_option_bind_worker_idx(uint8_t worker_idx)
{
    g_worker_idx = worker_idx;
}

uint8_t crypto_option_worker_idx(void)
{
    return g_worker_idx;
}

/* ===================== ingress policy extract ===================== */

int crypto_l3_extract_policy_id(const struct app_config *cfg,
                                uint8_t *pkt,
                                uint32_t pkt_len,
                                uint8_t *policy_id_out)
{
    const int tunnel_hdr_size = PACKET_CRYPTO_NONCE_BYTES + 2;

    if (!cfg || !pkt || !policy_id_out || pkt_len < 14 + 20)
        return -1;

    if ((((uint16_t)pkt[12] << 8) | pkt[13]) != 0x0800)
        return -1;

    int l3_off = 14;
    int ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20 || pkt_len < (uint32_t)(l3_off + ip_hdr_len + 1))
        return -1;

    if (pkt[l3_off + 9] != L3_FAKE_PROTOCOL)
        return -1;

    int tunnel_off = l3_off + ip_hdr_len;
    if (pkt_len < (uint32_t)(tunnel_off + tunnel_hdr_size))
        return -1;

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
            continue;
        const int ns = PACKET_CRYPTO_NONCE_BYTES;
        if (tunnel_off + ns + 1 >= (int)pkt_len)
            continue;
        if (pkt[tunnel_off + ns] != (uint8_t)cp->id)
            continue;
        *policy_id_out = (uint8_t)cp->id;
        return 0;
    }
    return -1;
}

int crypto_l4_extract_policy_id_ipv4(const struct app_config *cfg,
                                      uint8_t *pkt,
                                      uint32_t pkt_len,
                                      uint8_t *policy_id_out)
{
    if (!cfg || !pkt || !policy_id_out)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    uint8_t ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + 4))
        return -1;

    uint8_t ip_proto = pkt[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return -1;
    int transport_off = l3_off + ip_hdr_len;
    if (transport_off >= (int)pkt_len)
        return -1;

    int tunnel_off = transport_off + L4_WIRE_PORT_LEN;
    if (tunnel_off >= (int)pkt_len)
        return -1;

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L4)
            continue;
        const int ns = PACKET_CRYPTO_NONCE_BYTES;
        if (tunnel_off + ns + 1 >= (int)pkt_len)
            continue;
        uint8_t magic = pkt[tunnel_off + ns + 1];
        if (magic != 0xA5 && magic != 0x5A)
            continue;
        if (pkt[tunnel_off + ns] != (uint8_t)cp->id)
            continue;
        *policy_id_out = (uint8_t)cp->id;
        return 0;
    }

    return -1;
}

/* ===================== option router ===================== */

static atomic_uint_fast32_t g_opt_pkt_id = 0;
static atomic_uint_fast32_t g_opt_frag_mtu = CRYPTO_OPT_FRAG_MTU_DEFAULT;

uint16_t crypto_option_next_pkt_id(void)
{
    return (uint16_t)(atomic_fetch_add(&g_opt_pkt_id, 1) & 0xFFFF);
}

void crypto_option_set_mtu(uint32_t mtu)
{
    if (mtu < 512)
        mtu = 512;
    if (mtu > NE_FRAME)
        mtu = NE_FRAME;
    atomic_store(&g_opt_frag_mtu, mtu);
}

uint32_t crypto_option_get_mtu(void)
{
    uint32_t mtu = (uint32_t)atomic_load(&g_opt_frag_mtu);
    if (mtu < 512 || mtu > NE_FRAME)
        return CRYPTO_OPT_FRAG_MTU_DEFAULT;
    return mtu;
}

#define DECL_OPT(prefix) \
    int crypto_opt_##prefix##_need_split(uint32_t pkt_len); \
    int crypto_opt_##prefix##_split(struct packet_crypto_ctx *, uint8_t *, uint32_t, size_t, uint32_t *, uint8_t *, size_t, uint32_t *); \
    int crypto_opt_##prefix##_encrypt(struct packet_crypto_ctx *, uint8_t *, uint32_t *); \
    int crypto_opt_##prefix##_decrypt(struct packet_crypto_ctx *, uint8_t *, uint32_t *); \
    int crypto_opt_##prefix##_is_fragment(const struct app_config *, const uint8_t *, uint32_t, uint16_t *, uint8_t *); \
    int crypto_opt_##prefix##_reasm(int, int, struct packet_crypto_ctx *, uint8_t *, uint32_t *, uint8_t *, uint32_t *); \
    void crypto_opt_##prefix##_frag_gc(int, int, uint64_t)

DECL_OPT(l2_ctr128);
DECL_OPT(l2_ctr256);
DECL_OPT(l2_gcm128);
DECL_OPT(l2_gcm256);
DECL_OPT(l2_pqc);
DECL_OPT(l3_ctr128);
DECL_OPT(l3_ctr256);
DECL_OPT(l3_gcm128);
DECL_OPT(l3_gcm256);
DECL_OPT(l3_pqc);
DECL_OPT(l4_ctr128);
DECL_OPT(l4_ctr256);
DECL_OPT(l4_gcm128);
DECL_OPT(l4_gcm256);
DECL_OPT(l4_pqc);
DECL_OPT(bypass);

crypto_option_id crypto_option_from_action_mode_bits(int action, int mode, int aes_bits)
{
    if (action == POLICY_ACTION_BYPASS)
        return CRYPTO_OPT_BYPASS;
    if (action == POLICY_ACTION_ENCRYPT_L2) {
        if (mode == CRYPTO_MODE_PQC) return CRYPTO_OPT_L2_PQC;
        if (mode == CRYPTO_MODE_GCM) return (aes_bits == 256) ? CRYPTO_OPT_L2_GCM256 : CRYPTO_OPT_L2_GCM128;
        return (aes_bits == 256) ? CRYPTO_OPT_L2_CTR256 : CRYPTO_OPT_L2_CTR128;
    }
    if (action == POLICY_ACTION_ENCRYPT_L3) {
        if (mode == CRYPTO_MODE_PQC) return CRYPTO_OPT_L3_PQC;
        if (mode == CRYPTO_MODE_GCM) return (aes_bits == 256) ? CRYPTO_OPT_L3_GCM256 : CRYPTO_OPT_L3_GCM128;
        return (aes_bits == 256) ? CRYPTO_OPT_L3_CTR256 : CRYPTO_OPT_L3_CTR128;
    }
    if (action == POLICY_ACTION_ENCRYPT_L4) {
        if (mode == CRYPTO_MODE_PQC) return CRYPTO_OPT_L4_PQC;
        if (mode == CRYPTO_MODE_GCM) return (aes_bits == 256) ? CRYPTO_OPT_L4_GCM256 : CRYPTO_OPT_L4_GCM128;
        return (aes_bits == 256) ? CRYPTO_OPT_L4_CTR256 : CRYPTO_OPT_L4_CTR128;
    }
    return CRYPTO_OPT_BYPASS;
}

crypto_option_id crypto_option_from_policy(const struct crypto_policy *cp)
{
    if (!cp)
        return CRYPTO_OPT_BYPASS;
    return crypto_option_from_action_mode_bits(cp->action, cp->crypto_mode, cp->aes_bits);
}

uint32_t crypto_option_wire_overhead(crypto_option_id id)
{
    switch (id) {
    case CRYPTO_OPT_L2_CTR128:
    case CRYPTO_OPT_L2_CTR256:
        return 14u;
    case CRYPTO_OPT_L2_GCM128:
    case CRYPTO_OPT_L2_GCM256:
    case CRYPTO_OPT_L2_PQC:
        return 30u;
    case CRYPTO_OPT_L3_CTR128:
    case CRYPTO_OPT_L3_CTR256:
        return 14u;
    case CRYPTO_OPT_L3_GCM128:
    case CRYPTO_OPT_L3_GCM256:
    case CRYPTO_OPT_L3_PQC:
        return 30u;
    case CRYPTO_OPT_L4_CTR128:
    case CRYPTO_OPT_L4_CTR256:
        return 22u;
    case CRYPTO_OPT_L4_GCM128:
    case CRYPTO_OPT_L4_GCM256:
    case CRYPTO_OPT_L4_PQC:
        return 38u;
    case CRYPTO_OPT_BYPASS:
    default:
        return 0u;
    }
}

#define ROUTE_NEED(id, fn, ...) \
    switch (id) { \
    case CRYPTO_OPT_L2_CTR128: return crypto_opt_l2_ctr128_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L2_CTR256: return crypto_opt_l2_ctr256_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L2_GCM128: return crypto_opt_l2_gcm128_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L2_GCM256: return crypto_opt_l2_gcm256_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L2_PQC: return crypto_opt_l2_pqc_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L3_CTR128: return crypto_opt_l3_ctr128_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L3_CTR256: return crypto_opt_l3_ctr256_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L3_GCM128: return crypto_opt_l3_gcm128_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L3_GCM256: return crypto_opt_l3_gcm256_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L3_PQC: return crypto_opt_l3_pqc_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L4_CTR128: return crypto_opt_l4_ctr128_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L4_CTR256: return crypto_opt_l4_ctr256_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L4_GCM128: return crypto_opt_l4_gcm128_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L4_GCM256: return crypto_opt_l4_gcm256_##fn(__VA_ARGS__); \
    case CRYPTO_OPT_L4_PQC: return crypto_opt_l4_pqc_##fn(__VA_ARGS__); \
    default: return crypto_opt_bypass_##fn(__VA_ARGS__); \
    }

int crypto_option_need_split(crypto_option_id id, uint32_t pkt_len)
{
    ROUTE_NEED(id, need_split, pkt_len);
}

int crypto_option_split(crypto_option_id id, struct packet_crypto_ctx *ctx,
                        uint8_t *pkt_data, uint32_t pkt_len,
                        size_t frag0_max, uint32_t *frag0_len,
                        uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    ROUTE_NEED(id, split, ctx, pkt_data, pkt_len, frag0_max, frag0_len, frag1, frag1_max, frag1_len);
}

int crypto_option_encrypt(crypto_option_id id, struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len)
{
    ROUTE_NEED(id, encrypt, ctx, pkt, pkt_len);
}

int crypto_option_decrypt(crypto_option_id id, struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len)
{
    ROUTE_NEED(id, decrypt, ctx, pkt, pkt_len);
}

int crypto_option_is_fragment(crypto_option_id id, const struct app_config *cfg,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint16_t *pkt_id, uint8_t *frag_index)
{
    ROUTE_NEED(id, is_fragment, cfg, pkt_data, pkt_len, pkt_id, frag_index);
}

int crypto_option_reassemble(crypto_option_id id, int profile_slot, int worker_idx,
                             struct packet_crypto_ctx *ctx,
                             uint8_t *pkt_data, uint32_t *pkt_len,
                             uint8_t *out_buf, uint32_t *out_len)
{
    ROUTE_NEED(id, reasm, profile_slot, worker_idx, ctx, pkt_data, pkt_len, out_buf, out_len);
}

int crypto_option_is_any_fragment(const struct app_config *cfg,
                                  const uint8_t *pkt_data, uint32_t pkt_len,
                                  uint16_t *pkt_id, uint8_t *frag_index)
{
    for (int i = 0; i < CRYPTO_OPT_COUNT; i++) {
        if (i == CRYPTO_OPT_BYPASS)
            continue;
        if (crypto_option_is_fragment((crypto_option_id)i, cfg, pkt_data, pkt_len, pkt_id, frag_index))
            return 1;
    }
    return 0;
}

void crypto_option_frag_gc(int profile_slot, int worker_idx, uint64_t now_ns)
{
    for (int i = 0; i < CRYPTO_OPT_COUNT; i++) {
        if (i == CRYPTO_OPT_BYPASS)
            continue;
        switch ((crypto_option_id)i) {
        case CRYPTO_OPT_L2_CTR128: crypto_opt_l2_ctr128_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L2_CTR256: crypto_opt_l2_ctr256_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L2_GCM128: crypto_opt_l2_gcm128_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L2_GCM256: crypto_opt_l2_gcm256_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L2_PQC: crypto_opt_l2_pqc_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L3_CTR128: crypto_opt_l3_ctr128_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L3_CTR256: crypto_opt_l3_ctr256_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L3_GCM128: crypto_opt_l3_gcm128_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L3_GCM256: crypto_opt_l3_gcm256_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L3_PQC: crypto_opt_l3_pqc_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L4_CTR128: crypto_opt_l4_ctr128_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L4_CTR256: crypto_opt_l4_ctr256_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L4_GCM128: crypto_opt_l4_gcm128_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L4_GCM256: crypto_opt_l4_gcm256_frag_gc(profile_slot, worker_idx, now_ns); break;
        case CRYPTO_OPT_L4_PQC: crypto_opt_l4_pqc_frag_gc(profile_slot, worker_idx, now_ns); break;
        default: break;
        }
    }
}
