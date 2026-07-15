#include "../../inc/core/crypto_route.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_layer2.h"

#include <arpa/inet.h>
#include <stddef.h>

static __thread int tls_crypto_worker_idx;

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

static inline int dp_flow_hash_to_worker(uint32_t hash)
{
    uint32_t n = NE_CRYPTO_WORKERS;

    if ((n & (n - 1u)) == 0u)
        return (int)(hash & (n - 1u));
    return (int)(hash % n);
}

void dp_crypto_worker_bind(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        worker_idx = 0;
    tls_crypto_worker_idx = worker_idx;
}

int dp_crypto_current_worker_idx(void)
{
    return tls_crypto_worker_idx;
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
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    uint32_t hash;

    if (!pkt || len < 14)
        return 0;

    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0) {
        hash = len;
        for (uint32_t i = 0; i < 14 && i < len; i++)
            hash = hash * 31u + pkt[i];
        hash = dp_flow_hash_mix(hash, hash >> 16, (uint16_t)len, 0, 0);
        return dp_flow_hash_to_worker(hash);
    }

    hash = dp_flow_hash_mix(ntohl(src_ip), ntohl(dst_ip), src_port, dst_port, proto);
    return dp_flow_hash_to_worker(hash);
}

int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t wire_id = 0;
    int wi;

    if (!fwd || !pkt)
        return 0;

    if (!fwd->cfg || !fwd->cfg->crypto_enabled)
        return 0;

    if (!fwd_crypto_has_l2_marker(pkt, len)) {
        if (!frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx))
            return 0;
    }

    if (crypto_layer2_read_worker_idx(pkt, len, &wire_id) != 0)
        return -1;

    if (wire_id < NE_CRYPTO_WORKERS)
        return (int)wire_id;

    wi = dp_crypto_worker_idx_for_cpu(wire_id);
    if (wi < 0)
        return -1;
    return wi;
}
