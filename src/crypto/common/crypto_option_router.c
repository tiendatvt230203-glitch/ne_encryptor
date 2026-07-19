#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/core/interface.h"

#include <netinet/in.h>
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

crypto_proto_class crypto_proto_classify(uint8_t ip_proto)
{
    if (ip_proto == IPPROTO_TCP)
        return CRYPTO_PROTO_TCP;
    if (ip_proto == IPPROTO_UDP)
        return CRYPTO_PROTO_UDP;
    if (ip_proto == IPPROTO_ICMP)
        return CRYPTO_PROTO_ICMP;
    if (ip_proto == 89) /* IPPROTO_OSPF */
        return CRYPTO_PROTO_OSPF;
    return CRYPTO_PROTO_OTHER;
}

static int wire_l4_magic(uint8_t b)
{
    return b == L4_TUNNEL_MAGIC || b == L4_FRAG_MAGIC;
}

int crypto_wire_detach(const uint8_t *pkt, uint32_t pkt_len, struct crypto_wire_info *out)
{
    int et_off;
    uint16_t et;
    int l3_off;
    int ip_hdr_len;
    uint8_t ip_proto;
    int tunnel_off;
    const int ns = PACKET_CRYPTO_NONCE_BYTES;

    if (!out)
        return -1;
    out->layer = CRYPTO_WIRE_NONE;
    out->policy_id = 0;
    out->is_frag = 0;
    if (!pkt || pkt_len < 14)
        return -1;

    et_off = crypto_eth_inner_et_off(pkt, pkt_len);
    if (et_off >= 0) {
        et = (uint16_t)(((uint16_t)pkt[et_off] << 8) | pkt[et_off + 1]);
        if (et == NE_L2_FAKE_ETHERTYPE) {
            int pol_off = et_off + 2;

            if (pkt_len < (uint32_t)(pol_off + 1))
                return -1;
            out->layer = CRYPTO_WIRE_L2;
            out->policy_id = pkt[pol_off];
            /* L2 frag magic sits at ciphertext start — never set is_frag here
             * (false positives ~1/256). Decrypt-first in wan_ingress. */
            (void)ns;
            return 0;
        }
    }

    l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;
    ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20 || pkt_len < (uint32_t)(l3_off + ip_hdr_len))
        return -1;
    ip_proto = pkt[l3_off + 9];

    if (ip_proto == L3_FAKE_PROTOCOL) {
        tunnel_off = l3_off + ip_hdr_len;
        if (pkt_len < (uint32_t)(tunnel_off + ns + 2))
            return -1;
        out->layer = CRYPTO_WIRE_L3;
        out->policy_id = pkt[tunnel_off + ns + 1];
        if (pkt_len > (uint32_t)(tunnel_off + ns + 2) &&
            pkt[tunnel_off + ns + 2] == L3_FRAG_MAGIC)
            out->is_frag = 1;
        return 0;
    }

    if (ip_proto == 6 || ip_proto == 17) {
        tunnel_off = l3_off + ip_hdr_len + L4_WIRE_PORT_LEN;
        if (pkt_len < (uint32_t)(tunnel_off + ns + 2))
            return -1;
        if (pkt_len > (uint32_t)(tunnel_off + ns + 2) &&
            wire_l4_magic(pkt[tunnel_off + ns + 2])) {
            out->layer = CRYPTO_WIRE_L4;
            out->policy_id = pkt[tunnel_off + ns + 1];
            out->is_frag = (pkt[tunnel_off + ns + 2] == L4_FRAG_MAGIC);
            return 0;
        }
        if (wire_l4_magic(pkt[tunnel_off + ns + 1])) {
            out->layer = CRYPTO_WIRE_L4;
            out->policy_id = pkt[tunnel_off + ns];
            out->is_frag = (pkt[tunnel_off + ns + 1] == L4_FRAG_MAGIC);
            return 0;
        }
    }

    return -1;
}

int crypto_l3_extract_policy_id(const struct app_config *cfg,
                                uint8_t *pkt,
                                uint32_t pkt_len,
                                uint8_t *policy_id_out)
{
    struct crypto_wire_info wi;

    (void)cfg;
    if (!pkt || !policy_id_out)
        return -1;
    if (crypto_wire_detach(pkt, pkt_len, &wi) != 0 || wi.layer != CRYPTO_WIRE_L3)
        return -1;
    *policy_id_out = wi.policy_id;
    return 0;
}

int crypto_l4_extract_policy_id_ipv4(const struct app_config *cfg,
                                      uint8_t *pkt,
                                      uint32_t pkt_len,
                                      uint8_t *policy_id_out)
{
    struct crypto_wire_info wi;

    (void)cfg;
    if (!pkt || !policy_id_out)
        return -1;
    if (crypto_wire_detach(pkt, pkt_len, &wi) != 0 || wi.layer != CRYPTO_WIRE_L4)
        return -1;
    *policy_id_out = wi.policy_id;
    return 0;
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
        return 15u;
    case CRYPTO_OPT_L3_GCM128:
    case CRYPTO_OPT_L3_GCM256:
    case CRYPTO_OPT_L3_PQC:
        return 31u;
    case CRYPTO_OPT_L4_CTR128:
    case CRYPTO_OPT_L4_CTR256:
        return 15u; /* nonce12 + core + policy + marker */
    case CRYPTO_OPT_L4_GCM128:
    case CRYPTO_OPT_L4_GCM256:
    case CRYPTO_OPT_L4_PQC:
        return 31u; /* 15 + GCM tag 16 */
    case CRYPTO_OPT_BYPASS:
    default:
        return 0u;
    }
}

#define CALL_OPS(fn, id, proto, ...) do { \
    const struct crypto_option_ops *ops = crypto_option_ops((id), (proto)); \
    if (!ops || !ops->fn) \
        return -1; \
    return ops->fn(__VA_ARGS__); \
} while (0)

#define CALL_OPS_VOID(fn, id, proto, ...) do { \
    const struct crypto_option_ops *ops = crypto_option_ops((id), (proto)); \
    if (!ops || !ops->fn) \
        return; \
    ops->fn(__VA_ARGS__); \
} while (0)

int crypto_option_need_split(crypto_option_id id, crypto_proto_class proto, uint32_t pkt_len)
{
    const struct crypto_option_ops *ops = crypto_option_ops(id, proto);
    if (!ops || !ops->need_split)
        return 0;
    return ops->need_split(pkt_len);
}

int crypto_option_split(crypto_option_id id, crypto_proto_class proto,
                        struct packet_crypto_ctx *ctx,
                        uint8_t *pkt_data, uint32_t pkt_len,
                        size_t frag0_max, uint32_t *frag0_len,
                        uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len)
{
    CALL_OPS(split, id, proto, ctx, pkt_data, pkt_len, frag0_max, frag0_len,
             frag1, frag1_max, frag1_len);
}

int crypto_option_encrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len)
{
    CALL_OPS(encrypt, id, proto, ctx, pkt, pkt_len);
}

int crypto_option_decrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len)
{
    CALL_OPS(decrypt, id, proto, ctx, pkt, pkt_len);
}

int crypto_option_is_fragment(crypto_option_id id, crypto_proto_class proto,
                              const struct app_config *cfg,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint16_t *pkt_id, uint8_t *frag_index)
{
    const struct crypto_option_ops *ops = crypto_option_ops(id, proto);
    if (!ops || !ops->is_fragment)
        return 0;
    return ops->is_fragment(cfg, pkt_data, pkt_len, pkt_id, frag_index);
}

int crypto_option_reassemble(crypto_option_id id, crypto_proto_class proto,
                             int profile_slot, int worker_idx,
                             struct packet_crypto_ctx *ctx,
                             uint8_t *pkt_data, uint32_t *pkt_len,
                             uint8_t *out_buf, uint32_t *out_len)
{
    CALL_OPS(reasm, id, proto, profile_slot, worker_idx, ctx, pkt_data, pkt_len,
             out_buf, out_len);
}

int crypto_option_is_any_fragment(const struct app_config *cfg,
                                  const uint8_t *pkt_data, uint32_t pkt_len,
                                  uint16_t *pkt_id, uint8_t *frag_index)
{
    struct crypto_wire_info wi;

    (void)cfg;
    if (crypto_wire_detach(pkt_data, pkt_len, &wi) != 0 || !wi.is_frag)
        return 0;
    if (pkt_id)
        *pkt_id = 0;
    if (frag_index)
        *frag_index = 0;
    return 1;
}

void crypto_option_frag_gc(crypto_option_id id, crypto_proto_class proto,
                           int profile_slot, int worker_idx, uint64_t now_ns)
{
    CALL_OPS_VOID(frag_gc, id, proto, profile_slot, worker_idx, now_ns);
}

void crypto_option_frag_gc_all(int profile_slot, int worker_idx, uint64_t now_ns)
{
    for (int i = 0; i < CRYPTO_OPT_COUNT; i++) {
        if (i == CRYPTO_OPT_BYPASS)
            continue;
        crypto_option_frag_gc((crypto_option_id)i, CRYPTO_PROTO_UDP,
                                profile_slot, worker_idx, now_ns);
    }
}
