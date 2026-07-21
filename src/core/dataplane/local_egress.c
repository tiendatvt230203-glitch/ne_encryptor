#include "../../../inc/core/dataplane.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/dataplane_stats.h"

#include <netinet/in.h>
#include <string.h>

#define SPLIT_TAIL_REFILL_BATCH 32u
#define ETH_P_ARP_BE    0x0806u
#define ARP_OP_REQUEST  1u
#define ARP_OP_REPLY    2u

static uint16_t eth_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Ethernet ARP Request/Reply → SPA (network order). Returns 0 on success. */
static int parse_arp_spa(const uint8_t *pkt, uint32_t len, uint32_t *spa_out)
{
    uint16_t et;
    uint16_t op;

    if (!pkt || !spa_out || len < 42u)
        return -1;

    et = eth_be16(pkt + 12);
    if (et != ETH_P_ARP_BE)
        return -1;

    /* hrd=1, pro=0x0800, hln=6, pln=4 */
    if (eth_be16(pkt + 14) != 1u ||
        eth_be16(pkt + 16) != 0x0800u ||
        pkt[18] != 6u ||
        pkt[19] != 4u)
        return -1;

    op = eth_be16(pkt + 20);
    if (op != ARP_OP_REQUEST && op != ARP_OP_REPLY)
        return -1;

    memcpy(spa_out, pkt + 28, sizeof(*spa_out));
    return 0;
}

static void maybe_learn_arp(struct forwarder *fwd, int local_idx,
                            const uint8_t *pkt, uint32_t len)
{
    uint32_t spa;

    if (!fwd || !fwd->cfg || !pkt)
        return;
    if (parse_arp_spa(pkt, len, &spa) != 0)
        return;
    if (!config_local_policies_cover_ip(fwd->cfg, local_idx, spa))
        return;
    mac_learn(fwd, local_idx, pkt, len);
}

static struct ne_ring *mid_to_wan_ring(struct forwarder *fwd, int wan_dp)
{
    int bwi = dp_bypass_current_worker_idx();

    if (bwi >= 0)
        return &fwd->mid_to_wan_bypass[wan_dp][bwi];
    return &fwd->mid_to_wan[wan_dp][dp_crypto_current_worker_idx()];
}

static int push_to_wan(struct forwarder *fwd, struct ne_packet *job, int wan_dp)
{
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    return dp_ring_push(fwd, mid_to_wan_ring(fwd, wan_dp), job);
}

static int push_split_to_wan(struct forwarder *fwd, struct ne_packet *job,
                            uint32_t l1, struct ne_packet *tail, uint32_t l2, int wan_dp)
{
    struct ne_ring *tx = mid_to_wan_ring(fwd, wan_dp);
    if (wan_dp < 0 || wan_dp >= fwd->wan_count || ne_ring_count(tx) + 2 > tx->cap)
        return -1;
    if (l1 == 0 || l2 == 0 || l1 > fwd->pair.frame_size || l2 > fwd->pair.frame_size)
        return -1;
    if (!tail)
        return -1;
    tail->len = l2;
    tail->dir = NE_DIR_WAN;
    tail->wan_idx = (uint8_t)wan_dp;
    job->len = l1;
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (ne_ring_try_push(tx, job) != 0) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    if (ne_ring_try_push(tx, tail) != 0)
        ne_frame_free(&fwd->pair, tail->addr);
    return 0;
}

static int split_tail_take(struct forwarder *fwd, int worker_idx, uint64_t *addr_out)
{
    uint32_t got;

    if (!fwd || !addr_out || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return -1;

    if (fwd->split_tail_count[worker_idx] == 0) {
        got = ne_frame_alloc_batch(&fwd->pair, fwd->split_tail_cache[worker_idx],
                                   SPLIT_TAIL_REFILL_BATCH);
        if (got == 0)
            return -1;
        fwd->split_tail_count[worker_idx] = (uint16_t)got;
    }

    fwd->split_tail_count[worker_idx]--;
    *addr_out = fwd->split_tail_cache[worker_idx][fwd->split_tail_count[worker_idx]];
    return 0;
}

static int encrypt_to_wan(struct forwarder *fwd, struct ne_packet *job,
                        const struct crypto_policy *cp, int wan_dp,
                        struct packet_crypto_ctx *pctx,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port, uint8_t proto,
                        int flow_ok)
{
    int worker_idx = dp_crypto_current_worker_idx();
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    struct ne_packet tail = {0};
    uint8_t *tail_buf = NULL;
    uint32_t len = job->len;
    uint32_t l1 = 0, l2 = 0;
    crypto_option_id opt_id = crypto_option_from_policy(cp);
    crypto_proto_class pclass = crypto_proto_classify(proto);

    (void)src_ip;
    (void)dst_ip;
    (void)src_port;
    (void)dst_port;
    (void)flow_ok;

    if (crypto_option_need_split(opt_id, pclass, len)) {
        if (split_tail_take(fwd, worker_idx, &tail.addr) != 0)
            return -1;
        tail_buf = ne_packet_data(&fwd->pair, tail.addr);
        if (crypto_option_split(opt_id, pclass, pctx, pkt, len, fwd->pair.frame_size, &l1,
                                tail_buf, fwd->pair.frame_size, &l2) != 0) {
            ne_frame_free(&fwd->pair, tail.addr);
            return -1;
        }
        if (push_split_to_wan(fwd, job, l1, &tail, l2, wan_dp) != 0)
            return -1;
        return 1;
    }

    if (crypto_option_encrypt(opt_id, pclass, pctx, pkt, &len) != 0)
        return -1;
    job->len = len;
    return 0;
}

static int pick_profile_policy(struct forwarder *fwd, int local_idx, int flow_ok,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port, uint8_t proto,
                            int *profile_idx, const struct crypto_policy **cp)
{
    if (!fwd || !fwd->cfg || !profile_idx || !cp)
        return -1;

    const struct crypto_policy *best = NULL;
    int best_pi = -1, best_pri = 0x7fffffff, best_id = 0x7fffffff;

    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        const struct profile_config *p = &fwd->cfg->profiles[pi];
        int found = 0;
        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++)
            if (p->local_indices[i] == local_idx)
                found = 1;
        if (!found)
            continue;
        const struct crypto_policy *c = flow_ok
            ? config_select_crypto_policy(fwd->cfg, pi, src_ip, dst_ip, src_port, dst_port, proto)
            : NULL;
        if (!c)
            continue;
        if (!best || c->priority < best_pri || (c->priority == best_pri && c->id < best_id)) {
            best = c;
            best_pi = pi;
            best_pri = c->priority;
            best_id = c->id;
        }
    }
    if (!best)
        return -1;
    *profile_idx = best_pi;
    *cp = best;
    return 0;
}

int dataplane_local_is_bypass(struct forwarder *fwd, int local_idx,
                              const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok;
    int profile_idx;
    const struct crypto_policy *cp;

    if (!fwd || !pkt)
        return 0;
    flow_ok = dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                            &src_port, &dst_port, &proto) == 0;
    if (pick_profile_policy(fwd, local_idx, flow_ok, src_ip, dst_ip, src_port, dst_port, proto,
                            &profile_idx, &cp) != 0)
        return 0;
    return cp->action == POLICY_ACTION_BYPASS;
}

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok = dp_parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0;
    int li = job.local_idx < fwd->local_count ? (int)job.local_idx : 0;
    int profile_idx;
    const struct crypto_policy *cp;
    int wan_dp;
    int pi;
    struct packet_crypto_ctx *pctx;
    int enc;

    if (!flow_ok) {
        if (dp_pkt_is_arp(pkt, job.len)) {
            maybe_learn_arp(fwd, li, pkt, job.len);
            if (arp_bridge_from_local(fwd, &job, pkt, li) == 0)
                return;
        }
        goto drop;
    }

    if (pick_profile_policy(fwd, li, flow_ok, src_ip, dst_ip, src_port, dst_port, proto,
                            &profile_idx, &cp) != 0)
        goto drop;

    mac_learn(fwd, li, pkt, job.len);

    wan_dp = fwd_wan_pick_for_local(fwd, profile_idx, flow_ok, src_ip, dst_ip,
                                    src_port, dst_port, proto, job.len);
    if (wan_dp < 0 || !fwd_wan_has_tx_room(fwd,wan_dp))
        goto drop;

    if (cp->action == POLICY_ACTION_BYPASS) {
        ne_dp_stats_local_bypass(1);
        (void)push_to_wan(fwd, &job, wan_dp);
        return;
    }
    /* Encrypt path must not run on bypass workers. */
    if (dp_bypass_current_worker_idx() >= 0)
        goto drop;
    if (!fwd->cfg->crypto_enabled)
        goto drop;

    if (proto == IPPROTO_TCP) {
        crypto_option_id opt = crypto_option_from_policy(cp);
        (void)crypto_tcp_clamp_mss(pkt, job.len, CRYPTO_OPT_FRAG_MTU_DEFAULT,
                                   crypto_option_wire_overhead(opt));
    }

    pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi))
        goto drop;
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx)
        goto drop;
    pctx->profile_id = fwd->cfg->profiles[profile_idx].id;
    pctx->wire_id = (uint8_t)cp->id;
    pctx->policy_id = (cp->crypto_mode == CRYPTO_MODE_PQC) ? cp->db_id : cp->id;
    enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx,
                        src_ip, dst_ip, src_port, dst_port, proto, flow_ok);
    if (enc < 0)
        goto drop;
    if (enc > 0)
        return;
    (void)push_to_wan(fwd, &job, wan_dp);
    return;

drop:
    ne_dp_stats_local_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
}
