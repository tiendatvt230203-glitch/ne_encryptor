#include "../../../inc/core/dataplane.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/dataplane_stats.h"
#include "../../../inc/core/dp_idle.h"

#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <time.h>

#define SPLIT_TAIL_REFILL_BATCH 32u
#define LOCAL_DROP_LOG_INTERVAL_MS 3000ull

static uint64_t local_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

static int local_log_rl(uint64_t *last_ms)
{
    uint64_t now = local_now_ms();

    if (!last_ms)
        return 0;
    if (*last_ms != 0 && now - *last_ms < LOCAL_DROP_LOG_INTERVAL_MS)
        return 0;
    *last_ms = now;
    return 1;
}

static int local_key_nonzero(const uint8_t *key, size_t len)
{
    if (!key)
        return 0;
    for (size_t i = 0; i < len; i++) {
        if (key[i] != 0)
            return 1;
    }
    return 0;
}

static uint8_t local_first_encrypt_logged[MAX_CRYPTO_POLICIES];

static int push_to_wan(struct forwarder *fwd, struct ne_packet *job, int wan_dp)
{
    int wi = dp_crypto_current_worker_idx();

    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    return dp_ring_push(fwd, &fwd->mid_to_wan[wan_dp][wi], job);
}

static int push_split_to_wan(struct forwarder *fwd, struct ne_packet *job,
                            uint32_t l1, struct ne_packet *tail, uint32_t l2, int wan_dp)
{
    struct ne_ring *tx = &fwd->mid_to_wan[wan_dp][dp_crypto_current_worker_idx()];

    if (!fwd || !job || !tail)
        return -1;
    if (wan_dp < 0 || wan_dp >= fwd->wan_count || ne_ring_count(tx) + 2 > tx->cap) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
    if (l1 == 0 || l2 == 0 || l1 > fwd->pair.frame_size || l2 > fwd->pair.frame_size) {
        ne_frame_free(&fwd->pair, tail->addr);
        return -1;
    }
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
    ne_dp_idle_wake(NE_DP_WAKE_TX);
    if (ne_ring_try_push(tx, tail) != 0) {
        /* Head already queued; drop only the tail fragment. */
        ne_frame_free(&fwd->pair, tail->addr);
    } else {
        ne_dp_idle_wake(NE_DP_WAKE_TX);
    }
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
                        crypto_proto_class pclass, int flow_ok)
{
    int worker_idx = dp_crypto_current_worker_idx();
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    struct ne_packet tail = {0};
    uint8_t *tail_buf = NULL;
    uint32_t len = job->len;
    uint32_t l1 = 0, l2 = 0;
    crypto_option_id opt_id = crypto_option_from_policy(cp);

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

    if (!fwd || !pkt)
        goto drop;

    if (dp_pkt_is_arp(pkt, job.len)) {
        /* ARP: bridge path only — học MAC trong arp_bridge_from_local (client local). */
        if (arp_bridge_from_local(fwd, &job, pkt, li, NULL) == 0)
            return;
        goto drop;
    }

    if (pick_profile_policy(fwd, li, flow_ok, src_ip, dst_ip, src_port, dst_port, proto,
                            &profile_idx, &cp) != 0) {
        static uint64_t last_no_policy_ms;

        if (local_log_rl(&last_no_policy_ms)) {
            fprintf(stderr,
                    "[LOCAL-EGRESS] drop no-policy/no-match lan=%s flow_ok=%d proto=%u sip=%u dip=%u sp=%u dp=%u\n",
                    (li >= 0 && li < fwd->local_count) ? fwd->locals[li].ifname : "?",
                    flow_ok, (unsigned)proto, (unsigned)src_ip, (unsigned)dst_ip,
                    (unsigned)src_port, (unsigned)dst_port);
        }
        goto drop;
    }
    wan_dp = fwd_wan_pick_for_local(fwd, profile_idx, flow_ok, src_ip, dst_ip,
                                    src_port, dst_port, proto,
                                    dp_flow_window_bytes(pkt, job.len, job.len));
    if (wan_dp < 0 || !fwd_wan_has_tx_room(fwd,wan_dp)) {
        static uint64_t last_wan_unavail_ms;

        if (local_log_rl(&last_wan_unavail_ms)) {
            fprintf(stderr,
                    "[LOCAL-EGRESS] drop wan-unavailable profile=%d lan=%s wan_dp=%d\n",
                    fwd->cfg->profiles[profile_idx].id,
                    (li >= 0 && li < fwd->local_count) ? fwd->locals[li].ifname : "?",
                    wan_dp);
        }
        goto drop;
    }

    if (cp->action == POLICY_ACTION_BYPASS) {
        ne_dp_stats_local_bypass(1);
        (void)push_to_wan(fwd, &job, wan_dp);
        return;
    }
    if (!fwd->cfg->crypto_enabled) {
        static uint64_t last_crypto_off_ms;

        if (local_log_rl(&last_crypto_off_ms)) {
            fprintf(stderr,
                    "[LOCAL-EGRESS] drop crypto-disabled profile=%d policy_db_id=%d action=%d\n",
                    fwd->cfg->profiles[profile_idx].id, cp->db_id, cp->action);
        }
        goto drop;
    }

    if (proto == IPPROTO_TCP) {
        crypto_option_id opt = crypto_option_from_policy(cp);
        (void)crypto_tcp_clamp_mss(pkt, job.len, CRYPTO_OPT_FRAG_MTU_DEFAULT,
                                   crypto_option_wire_overhead(opt));
    }

    pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi)) {
        static uint64_t last_ctx_not_ready_ms;

        if (local_log_rl(&last_ctx_not_ready_ms)) {
            fprintf(stderr,
                    "[LOCAL-EGRESS] drop policy-ctx-missing profile=%d policy_db_id=%d wire_id=%d\n",
                    fwd->cfg->profiles[profile_idx].id, cp->db_id, cp->id);
        }
        goto drop;
    }
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx)
        goto drop;
    if (cp->crypto_mode == CRYPTO_MODE_PQC) {
        const uint8_t *cur = packet_crypto_get_key(pctx, KEY_SLOT_CURRENT);
        if (!local_key_nonzero(cur, AES_KEY_LEN)) {
            static uint64_t last_key_zero_ms;
            if (local_log_rl(&last_key_zero_ms)) {
                fprintf(stderr,
                        "[LOCAL-EGRESS] drop current-key-zero profile=%d policy_db_id=%d wire_id=%d\n",
                        fwd->cfg->profiles[profile_idx].id, cp->db_id, cp->id);
            }
            goto drop;
        }
    }
    pctx->profile_id = fwd->cfg->profiles[profile_idx].id;
    pctx->wire_id = (uint8_t)cp->id;
    pctx->policy_id = (cp->crypto_mode == CRYPTO_MODE_PQC) ? cp->db_id : cp->id;
    enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx,
                        crypto_proto_classify(proto), flow_ok);
    if (enc < 0)
        goto drop;
    if (enc > 0) {
        if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && !local_first_encrypt_logged[pi]) {
            local_first_encrypt_logged[pi] = 1;
            fprintf(stderr,
                    "[LOCAL-EGRESS] first-encrypt-ok profile=%d policy_db_id=%d wire_id=%d mode=%d split=1\n",
                    fwd->cfg->profiles[profile_idx].id, cp->db_id, cp->id, cp->crypto_mode);
        }
        return;
    }
    if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && !local_first_encrypt_logged[pi]) {
        local_first_encrypt_logged[pi] = 1;
        fprintf(stderr,
                "[LOCAL-EGRESS] first-encrypt-ok profile=%d policy_db_id=%d wire_id=%d mode=%d split=0\n",
                fwd->cfg->profiles[profile_idx].id, cp->db_id, cp->id, cp->crypto_mode);
    }
    (void)push_to_wan(fwd, &job, wan_dp);
    return;

drop:
    ne_dp_stats_local_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
}