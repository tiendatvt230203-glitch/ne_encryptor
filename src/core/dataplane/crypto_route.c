#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/config.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/crypto_option.h"

#include <arpa/inet.h>
#include <stddef.h>

static __thread int tls_crypto_worker_idx;
static __thread int tls_bypass_worker_idx = -1;

static uint32_t dp_flow_hash_mix(uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint8_t protocol)
{
    uint32_t hash = src_ip ^ dst_ip;

    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= protocol;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash;
}

static inline int dp_flow_hash_to_n(uint32_t hash, uint32_t n)
{
    if (n == 0)
        return 0;
    if ((n & (n - 1u)) == 0u)
        return (int)(hash & (n - 1u));
    return (int)(hash % n);
}

static uint32_t dp_pkt_flow_hash(const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    uint32_t hash;

    if (!pkt || len < 14)
        return len;

    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0) {
        hash = len;
        for (uint32_t i = 0; i < 14 && i < len; i++)
            hash = hash * 31u + pkt[i];
        return dp_flow_hash_mix(hash, hash >> 16, (uint16_t)len, 0, 0);
    }

    return dp_flow_hash_mix(ntohl(src_ip), ntohl(dst_ip), src_port, dst_port, proto);
}

static int wire_policy_matches_layer(crypto_wire_layer layer, uint8_t policy_id)
{
    const struct crypto_policy *cp = fwd_crypto_policy_for_wire_id(policy_id);

    if (!cp)
        return 0;
    if (layer == CRYPTO_WIRE_L2)
        return cp->action == POLICY_ACTION_ENCRYPT_L2;
    if (layer == CRYPTO_WIRE_L3)
        return cp->action == POLICY_ACTION_ENCRYPT_L3;
    if (layer == CRYPTO_WIRE_L4)
        return cp->action == POLICY_ACTION_ENCRYPT_L4;
    return 0;
}

static int resolve_crypto_worker_from_core(uint8_t wire_id)
{
    int wi;

    if (wire_id < NE_CRYPTO_WORKERS)
        return (int)wire_id;
    wi = dp_crypto_worker_idx_for_cpu(wire_id);
    return wi;
}

void dp_crypto_worker_bind(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        worker_idx = 0;
    tls_crypto_worker_idx = worker_idx;
    tls_bypass_worker_idx = -1;
}

int dp_crypto_current_worker_idx(void)
{
    return tls_crypto_worker_idx;
}

void dp_bypass_worker_bind(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_BYPASS_WORKERS)
        worker_idx = 0;
    tls_bypass_worker_idx = worker_idx;
}

int dp_bypass_current_worker_idx(void)
{
    return tls_bypass_worker_idx;
}

int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id)
{
    for (int i = 0; i < (int)NE_CRYPTO_WORKERS; i++) {
        if (NE_CPU_CRYPTO[i] == cpu_id)
            return i;
    }
    return -1;
}

int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len)
{
    return dp_flow_hash_to_n(dp_pkt_flow_hash(pkt, len), NE_CRYPTO_WORKERS);
}

int dp_bypass_pick_worker(const uint8_t *pkt, uint32_t len)
{
    return dp_flow_hash_to_n(dp_pkt_flow_hash(pkt, len), NE_BYPASS_WORKERS);
}

int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    struct crypto_wire_info wi;
    int wi_idx;

    if (!fwd || !pkt)
        return DP_CRYPTO_WAN_PLAIN;

    if (!fwd->cfg || !fwd->cfg->crypto_enabled)
        return DP_CRYPTO_WAN_PLAIN;

    if (crypto_wire_detach(pkt, len, &wi) != 0 || wi.layer == CRYPTO_WIRE_NONE)
        return DP_CRYPTO_WAN_PLAIN;
    if (!wire_policy_matches_layer(wi.layer, wi.policy_id))
        return DP_CRYPTO_WAN_PLAIN;

    wi_idx = resolve_crypto_worker_from_core(wi.core_id);
    if (wi_idx < 0)
        return -1;
    return wi_idx;
}
