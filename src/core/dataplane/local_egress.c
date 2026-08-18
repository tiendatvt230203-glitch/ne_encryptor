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

#include "../../../inc/core/config.h"

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>

#define SPLIT_TAIL_REFILL_BATCH 32u
#define LOCAL_KEY_PREFIX_LEN 9

#define STAGE_MATCH  (1u << 0)
#define STAGE_KEY    (1u << 1)
#define STAGE_ENC    (1u << 2)
#define STAGE_QUEUE  (1u << 3)
#define STAGE_XDP    (1u << 4)

struct local_policy_snap {
    uint8_t valid;
    int profile_id;
    int policy_db_id;
    int wire_id;
    int crypto_mode;
    char key_prefix[LOCAL_KEY_PREFIX_LEN];
    char wan_if[IFNAMSIZ];
    uint32_t plain_len;
    uint32_t wire_len;
    int split;
};

static struct local_policy_snap local_snap[MAX_CRYPTO_POLICIES];
static uint8_t local_confirmed[MAX_CRYPTO_POLICIES];
static uint8_t local_pending_valid[MAX_CRYPTO_POLICIES];
static uint64_t local_pending_addr[MAX_CRYPTO_POLICIES];
static uint8_t local_pending_wan[MAX_CRYPTO_POLICIES];
static uint32_t local_pending_wire_len[MAX_CRYPTO_POLICIES];

static uint8_t local_stage_bits[MAX_CRYPTO_POLICIES];
static uint8_t local_stage_data_in;
static uint8_t local_stuck_no_policy;
static uint8_t local_stuck_wan;
static uint8_t local_stuck_wan_room;
static uint8_t local_stuck_crypto_off;
static uint8_t local_stuck_ctx[MAX_CRYPTO_POLICIES];
static uint8_t local_stuck_key_zero[MAX_CRYPTO_POLICIES];
static uint8_t local_stuck_encrypt_fail[MAX_CRYPTO_POLICIES];
static uint8_t local_stuck_split_fail[MAX_CRYPTO_POLICIES];
static uint8_t local_stuck_tx_queue[MAX_CRYPTO_POLICIES];
static uint8_t local_stuck_xdp_full;
static uint8_t local_stuck_xdp_kick;
static uint8_t local_stuck_wan_dead;

void ne_local_egress_reset_diag(void)
{
    memset(local_snap, 0, sizeof(local_snap));
    memset(local_confirmed, 0, sizeof(local_confirmed));
    memset(local_pending_valid, 0, sizeof(local_pending_valid));
    memset(local_pending_addr, 0, sizeof(local_pending_addr));
    memset(local_pending_wan, 0, sizeof(local_pending_wan));
    memset(local_pending_wire_len, 0, sizeof(local_pending_wire_len));

    memset(local_stage_bits, 0, sizeof(local_stage_bits));
    local_stage_data_in = 0;
    local_stuck_no_policy = 0;
    local_stuck_wan = 0;
    local_stuck_wan_room = 0;
    local_stuck_crypto_off = 0;
    memset(local_stuck_ctx, 0, sizeof(local_stuck_ctx));
    memset(local_stuck_key_zero, 0, sizeof(local_stuck_key_zero));
    memset(local_stuck_encrypt_fail, 0, sizeof(local_stuck_encrypt_fail));
    memset(local_stuck_split_fail, 0, sizeof(local_stuck_split_fail));
    memset(local_stuck_tx_queue, 0, sizeof(local_stuck_tx_queue));
    local_stuck_xdp_full = 0;
    local_stuck_xdp_kick = 0;
    local_stuck_wan_dead = 0;
}

static const char *local_crypto_mode_name(int mode)
{
    switch (mode) {
    case CRYPTO_MODE_PQC:
        return "PQC";
    case CRYPTO_MODE_GCM:
        return "GCM";
    case CRYPTO_MODE_CTR:
        return "CTR";
    default:
        return "?";
    }
}

static void local_log_stage(int pi, unsigned bit, const char *msg)
{
    const struct local_policy_snap *s;

    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !msg)
        return;
    if (local_stage_bits[pi] & bit)
        return;
    local_stage_bits[pi] |= (uint8_t)bit;
    s = &local_snap[pi];
    if (s->valid) {
        fprintf(stderr,
                "[LOCAL-EGRESS][STAGE] policy_db_id=%d %s profile=%d wire_id=%d crypto=%s key_prefix=%s wan=%s\n",
                s->policy_db_id, msg, s->profile_id, s->wire_id,
                local_crypto_mode_name(s->crypto_mode),
                s->key_prefix[0] ? s->key_prefix : "n/a",
                s->wan_if[0] ? s->wan_if : "?");
    } else {
        fprintf(stderr, "[LOCAL-EGRESS][STAGE] policy_slot=%d %s\n", pi, msg);
    }
    fflush(stderr);
}

void ne_local_egress_note_wan_submit(uint64_t addr, int policy_slot, int wan_idx,
                                     uint32_t wire_len)
{
    if (policy_slot < 0 || policy_slot >= MAX_CRYPTO_POLICIES)
        return;
    if (local_confirmed[policy_slot] || local_pending_valid[policy_slot])
        return;
    if (!local_snap[policy_slot].valid)
        return;

    local_pending_valid[policy_slot] = 1;
    local_pending_addr[policy_slot] = addr;
    local_pending_wan[policy_slot] = (uint8_t)wan_idx;
    local_pending_wire_len[policy_slot] = wire_len;
    local_log_stage(policy_slot, STAGE_XDP,
                    "6/xdp-submit waiting=nic-cq (kicked kernel, not on-wire yet)");
}

void ne_local_egress_on_wan_cq(uint64_t addr)
{
    for (int pi = 0; pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct local_policy_snap *s;

        if (!local_pending_valid[pi] || local_confirmed[pi])
            continue;
        if (local_pending_addr[pi] != addr)
            continue;

        s = &local_snap[pi];
        if (!s->valid) {
            local_pending_valid[pi] = 0;
            continue;
        }

        local_pending_valid[pi] = 0;
        local_confirmed[pi] = 1;
        fprintf(stderr,
                "[LOCAL-EGRESS] TRAFFIC-OK profile=%d policy_db_id=%d wire_id=%d "
                "crypto=%s key_prefix=%s wan=%s plain_len=%u wire_len=%u split=%d "
                "— encrypted with NE CURRENT key and NIC TX-complete on WAN\n",
                s->profile_id, s->policy_db_id, s->wire_id,
                local_crypto_mode_name(s->crypto_mode),
                s->key_prefix[0] ? s->key_prefix : "n/a",
                s->wan_if[0] ? s->wan_if : "?",
                (unsigned)s->plain_len, (unsigned)local_pending_wire_len[pi], s->split);
        fflush(stderr);
        return;
    }
}

void ne_local_egress_on_xdp_tx_full(int wan_idx)
{
    if (local_stuck_xdp_full)
        return;
    local_stuck_xdp_full = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=xdp-tx reason=tx-ring-full wan_idx=%d "
            "(queued mid_to_wan but NIC TX ring has no free desc)\n",
            wan_idx);
    fflush(stderr);
}

void ne_local_egress_on_xdp_kick_fail(int wan_idx, int err)
{
    if (local_stuck_xdp_kick)
        return;
    local_stuck_xdp_kick = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=xdp-kick reason=sendto-fail wan_idx=%d errno=%d "
            "(submitted to TX ring but kernel wakeup failed)\n",
            wan_idx, err);
    fflush(stderr);
}

void ne_local_egress_on_wan_not_live(int wan_idx)
{
    if (local_stuck_wan_dead)
        return;
    local_stuck_wan_dead = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=wan-tx reason=wan-not-live wan_idx=%d "
            "(encrypted frames waiting in mid_to_wan, XDP WAN down)\n",
            wan_idx);
    fflush(stderr);
}

static const char *local_ifname(const struct forwarder *fwd, int idx,
                                const struct fwd_iface *ifaces, int count)
{
    if (!fwd || idx < 0 || idx >= count)
        return "?";
    return ifaces[idx].ifname;
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

static void local_key_prefix(char *out, size_t outsz, const uint8_t *key)
{
    if (!out || outsz == 0)
        return;
    out[0] = '\0';
    if (!key || !local_key_nonzero(key, 4))
        return;
    snprintf(out, outsz, "%02X%02X%02X%02X", key[0], key[1], key[2], key[3]);
}

static void local_snap_capture(int pi, int profile_id, const struct crypto_policy *cp,
                             struct packet_crypto_ctx *pctx, const char *wan_if,
                             uint32_t plain_len, uint32_t wire_len, int split)
{
    const uint8_t *cur;

    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES)
        return;

    local_snap[pi].valid = 1;
    local_snap[pi].profile_id = profile_id;
    local_snap[pi].policy_db_id = cp->db_id;
    local_snap[pi].wire_id = cp->id;
    local_snap[pi].crypto_mode = cp->crypto_mode;
    local_snap[pi].plain_len = plain_len;
    local_snap[pi].wire_len = wire_len;
    local_snap[pi].split = split;
    strncpy(local_snap[pi].wan_if, wan_if ? wan_if : "?", sizeof(local_snap[pi].wan_if) - 1);
    local_snap[pi].wan_if[sizeof(local_snap[pi].wan_if) - 1] = '\0';

    cur = pctx ? packet_crypto_get_key(pctx, KEY_SLOT_CURRENT) : NULL;
    if (cp->crypto_mode == CRYPTO_MODE_PQC)
        local_key_prefix(local_snap[pi].key_prefix, sizeof(local_snap[pi].key_prefix), cur);
    else
        local_key_prefix(local_snap[pi].key_prefix, sizeof(local_snap[pi].key_prefix),
                         cp->key);
}

static void local_mark_policy_tx(struct ne_packet *job, int pi)
{
    if (!job || pi < 0 || pi >= MAX_CRYPTO_POLICIES)
        return;
    job->policy_slot = (uint8_t)pi;
}

static void local_log_stuck_no_policy(struct forwarder *fwd, int li, int flow_ok,
                                      uint8_t proto, uint32_t src_ip, uint32_t dst_ip,
                                      uint16_t src_port, uint16_t dst_port)
{
    if (local_stuck_no_policy)
        return;
    local_stuck_no_policy = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=policy-match reason=no-policy-match lan=%s flow_ok=%d "
            "proto=%u sip=%u dip=%u sp=%u dp=%u\n",
            local_ifname(fwd, li, fwd->locals, fwd->local_count),
            flow_ok, (unsigned)proto, (unsigned)src_ip, (unsigned)dst_ip,
            (unsigned)src_port, (unsigned)dst_port);
    fflush(stderr);
}

static void local_log_stuck_wan(int profile_id, int policy_db_id, const char *lan_if, int wan_dp)
{
    if (local_stuck_wan)
        return;
    local_stuck_wan = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=wan-pick reason=no-wan-selected policy_db_id=%d "
            "profile=%d lan=%s wan_dp=%d\n",
            policy_db_id, profile_id, lan_if ? lan_if : "?", wan_dp);
    fflush(stderr);
}

static void local_log_stuck_wan_room(int profile_id, int policy_db_id, const char *lan_if, int wan_dp)
{
    if (local_stuck_wan_room)
        return;
    local_stuck_wan_room = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=wan-pick reason=mid_to_wan-backpressure policy_db_id=%d "
            "profile=%d lan=%s wan_dp=%d\n",
            policy_db_id, profile_id, lan_if ? lan_if : "?", wan_dp);
    fflush(stderr);
}

static void local_log_stuck_crypto_off(int profile_id, int policy_db_id, int action)
{
    if (local_stuck_crypto_off)
        return;
    local_stuck_crypto_off = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=crypto-gate reason=crypto-disabled policy_db_id=%d "
            "profile=%d action=%d\n",
            policy_db_id, profile_id, action);
    fflush(stderr);
}

static void local_log_stuck_ctx(int pi, int profile_id, int policy_db_id, int wire_id)
{
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || local_stuck_ctx[pi])
        return;
    local_stuck_ctx[pi] = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=ctx-bind reason=policy-ctx-missing policy_db_id=%d "
            "profile=%d wire_id=%d\n",
            policy_db_id, profile_id, wire_id);
    fflush(stderr);
}

static void local_log_stuck_key_zero(int pi, int profile_id, int policy_db_id, int wire_id)
{
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || local_stuck_key_zero[pi])
        return;
    local_stuck_key_zero[pi] = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=key-ready reason=pqc-current-key-zero policy_db_id=%d "
            "profile=%d wire_id=%d (wait handshake / key refresh)\n",
            policy_db_id, profile_id, wire_id);
    fflush(stderr);
}

static void local_log_stuck_encrypt_fail(int pi, int profile_id, int policy_db_id,
                                         int wire_id, int mode, uint8_t proto, uint32_t len)
{
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || local_stuck_encrypt_fail[pi])
        return;
    local_stuck_encrypt_fail[pi] = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=encrypt reason=encrypt-fail policy_db_id=%d profile=%d "
            "wire_id=%d crypto=%s proto=%u len=%u\n",
            policy_db_id, profile_id, wire_id, local_crypto_mode_name(mode),
            (unsigned)proto, (unsigned)len);
    fflush(stderr);
}

static void local_log_stuck_split_fail(int pi, int profile_id, int policy_db_id, int code)
{
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || local_stuck_split_fail[pi])
        return;
    local_stuck_split_fail[pi] = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=encrypt-split reason=%s policy_db_id=%d profile=%d code=%d\n",
            code == -2 ? "no-tail-buf" : (code == -3 ? "split-crypto-fail" : "split-queue-fail"),
            policy_db_id, profile_id, code);
    fflush(stderr);
}

static void local_log_stuck_tx_queue(int pi, int profile_id, int policy_db_id, const char *wan_if)
{
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || local_stuck_tx_queue[pi])
        return;
    local_stuck_tx_queue[pi] = 1;
    fprintf(stderr,
            "[LOCAL-EGRESS][STUCK] at=tx-queue reason=mid_to_wan-full policy_db_id=%d "
            "profile=%d wan=%s\n",
            policy_db_id, profile_id, wan_if ? wan_if : "?");
    fflush(stderr);
}

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
    tail->policy_slot = job->policy_slot;
    if (ne_ring_try_push(tx, tail) != 0) {
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
    (void)wan_dp;
    (void)pctx;
    (void)cp;

    if (crypto_option_need_split(opt_id, pclass, len)) {
        if (split_tail_take(fwd, worker_idx, &tail.addr) != 0)
            return -2;
        tail_buf = ne_packet_data(&fwd->pair, tail.addr);
        if (crypto_option_split(opt_id, pclass, pctx, pkt, len, fwd->pair.frame_size, &l1,
                                tail_buf, fwd->pair.frame_size, &l2) != 0) {
            ne_frame_free(&fwd->pair, tail.addr);
            return -3;
        }
        if (push_split_to_wan(fwd, job, l1, &tail, l2, wan_dp) != 0)
            return -4;
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
    uint32_t plain_len;
    const char *wan_if;
    int profile_id;

    if (!fwd || !pkt)
        goto drop;

    job.policy_slot = NE_POLICY_SLOT_NONE;

    if (dp_pkt_is_arp(pkt, job.len)) {
        if (arp_bridge_from_local(fwd, &job, pkt, li, NULL) == 0)
            return;
        goto drop;
    }

    if (!local_stage_data_in) {
        local_stage_data_in = 1;
        fprintf(stderr,
                "[LOCAL-EGRESS][STAGE] 1/data-in lan=%s proto=%u len=%u flow_ok=%d\n",
                local_ifname(fwd, li, fwd->locals, fwd->local_count),
                (unsigned)proto, (unsigned)job.len, flow_ok);
        fflush(stderr);
    }

    if (pick_profile_policy(fwd, li, flow_ok, src_ip, dst_ip, src_port, dst_port, proto,
                            &profile_idx, &cp) != 0) {
        local_log_stuck_no_policy(fwd, li, flow_ok, proto, src_ip, dst_ip, src_port, dst_port);
        goto drop;
    }

    pi = (int)(cp - fwd->cfg->policies);
    profile_id = fwd->cfg->profiles[profile_idx].id;
    if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && !(local_stage_bits[pi] & STAGE_MATCH)) {
        local_stage_bits[pi] |= STAGE_MATCH;
        fprintf(stderr,
                "[LOCAL-EGRESS][STAGE] 2/policy-match profile=%d policy_db_id=%d wire_id=%d "
                "crypto=%s action=%d lan=%s proto=%u\n",
                profile_id, cp->db_id, cp->id, local_crypto_mode_name(cp->crypto_mode),
                cp->action, local_ifname(fwd, li, fwd->locals, fwd->local_count),
                (unsigned)proto);
        fflush(stderr);
    }

    wan_dp = fwd_wan_pick_for_local(fwd, profile_idx, flow_ok, src_ip, dst_ip,
                                    src_port, dst_port, proto,
                                    dp_flow_window_bytes(pkt, job.len, job.len));
    wan_if = local_ifname(fwd, wan_dp, fwd->wans, fwd->wan_count);
    if (wan_dp < 0) {
        local_log_stuck_wan(profile_id, cp->db_id,
                            local_ifname(fwd, li, fwd->locals, fwd->local_count), wan_dp);
        goto drop;
    }
    if (!fwd_wan_has_tx_room(fwd, wan_dp)) {
        local_log_stuck_wan_room(profile_id, cp->db_id,
                                 local_ifname(fwd, li, fwd->locals, fwd->local_count), wan_dp);
        goto drop;
    }

    if (cp->action == POLICY_ACTION_BYPASS) {
        ne_dp_stats_local_bypass(1);
        local_snap_capture(pi, profile_id, cp, NULL, wan_if, job.len, job.len, 0);
        local_mark_policy_tx(&job, pi);
        if (push_to_wan(fwd, &job, wan_dp) != 0) {
            local_log_stuck_tx_queue(pi, profile_id, cp->db_id, wan_if);
            return;
        }
        local_log_stage(pi, STAGE_QUEUE, "5/queued-mid-to-wan (bypass, waiting XDP TX)");
        return;
    }
    if (!fwd->cfg->crypto_enabled) {
        local_log_stuck_crypto_off(profile_id, cp->db_id, cp->action);
        goto drop;
    }

    if (proto == IPPROTO_TCP) {
        crypto_option_id opt = crypto_option_from_policy(cp);
        (void)crypto_tcp_clamp_mss(pkt, job.len, CRYPTO_OPT_FRAG_MTU_DEFAULT,
                                   crypto_option_wire_overhead(opt));
    }

    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi)) {
        local_log_stuck_ctx(pi, profile_id, cp->db_id, cp->id);
        goto drop;
    }
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx)
        goto drop;

    pctx->profile_id = profile_id;
    pctx->wire_id = (uint8_t)cp->id;
    pctx->policy_id = (cp->crypto_mode == CRYPTO_MODE_PQC) ? cp->db_id : cp->id;

    if (cp->crypto_mode == CRYPTO_MODE_PQC) {
        const uint8_t *cur = packet_crypto_get_key(pctx, KEY_SLOT_CURRENT);
        if (!local_key_nonzero(cur, AES_KEY_LEN)) {
            local_log_stuck_key_zero(pi, profile_id, cp->db_id, cp->id);
            goto drop;
        }
    }

    local_snap_capture(pi, profile_id, cp, pctx, wan_if, job.len, job.len, 0);
    local_log_stage(pi, STAGE_KEY, "3/key-ready (NE CURRENT)");

    plain_len = job.len;
    local_mark_policy_tx(&job, pi);
    enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx,
                        crypto_proto_classify(proto), flow_ok);
    if (enc <= -2) {
        local_log_stuck_split_fail(pi, profile_id, cp->db_id, enc);
        goto drop;
    }
    if (enc < 0) {
        local_log_stuck_encrypt_fail(pi, profile_id, cp->db_id, cp->id,
                                     cp->crypto_mode, proto, plain_len);
        goto drop;
    }

    local_snap[pi].plain_len = plain_len;
    local_snap[pi].wire_len = job.len;
    local_snap[pi].split = enc > 0 ? 1 : 0;
    local_log_stage(pi, STAGE_ENC, "4/encrypt-ok");

    if (enc > 0) {
        local_log_stage(pi, STAGE_QUEUE, "5/queued-mid-to-wan (split, waiting XDP TX)");
        return;
    }

    if (push_to_wan(fwd, &job, wan_dp) != 0) {
        local_log_stuck_tx_queue(pi, profile_id, cp->db_id, wan_if);
        return;
    }
    local_log_stage(pi, STAGE_QUEUE, "5/queued-mid-to-wan (waiting XDP TX)");
    return;

drop:
    ne_dp_stats_local_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
}
