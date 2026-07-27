#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <net/if.h>

#define ARP_LOG_FAIL_INTERVAL_MS 30000ull

struct arp_l2_pqc_entry {
    int policy_index;
    int priority;
    int wire_id;
    int db_id;
    int profile_id;
    int src_any;
    int dst_any;
    int src_negate;
    int dst_negate;
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
};

static struct arp_l2_pqc_entry g_arp_l2_pqc[MAX_CRYPTO_POLICIES];
static int g_arp_l2_pqc_count;

static uint64_t arp_monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

static int arp_log_fail_ratelimit(uint64_t *last_ms)
{
    uint64_t now = arp_monotonic_ms();

    if (!last_ms || now - *last_ms < ARP_LOG_FAIL_INTERVAL_MS)
        return 0;
    *last_ms = now;
    return 1;
}

static int arp_cidr_match(int any_flag, int negate, uint32_t ip, uint32_t net, uint32_t mask)
{
    int in_cidr;

    if (any_flag)
        return 1;
    in_cidr = ((ip & mask) == (net & mask));
    return negate ? !in_cidr : in_cidr;
}

static int arp_entry_match_ips(const struct arp_l2_pqc_entry *e, uint32_t spa, uint32_t tpa)
{
    if (!e)
        return 0;
    if (!arp_cidr_match(e->src_any, e->src_negate, spa, e->src_net, e->src_mask))
        return 0;
    if (!arp_cidr_match(e->dst_any, e->dst_negate, tpa, e->dst_net, e->dst_mask))
        return 0;
    return 1;
}

void arp_bridge_reload_policies(struct app_config *cfg)
{
    g_arp_l2_pqc_count = 0;
    if (!cfg || !cfg->crypto_enabled)
        return;

    for (int pi = 0; pi < cfg->profile_count && pi < MAX_PROFILES; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];

        if (!p->enabled)
            continue;
        for (int j = 0; j < p->policy_count && j < MAX_CRYPTO_POLICIES; j++) {
            int idx = p->policy_indices[j];
            const struct crypto_policy *cp;
            struct arp_l2_pqc_entry *e;

            if (idx < 0 || idx >= cfg->policy_count)
                continue;
            cp = &cfg->policies[idx];
            if (cp->action != POLICY_ACTION_ENCRYPT_L2)
                continue;
            if (cp->crypto_mode != CRYPTO_MODE_PQC)
                continue;
            if (cp->protocol != POLICY_PROTO_ANY)
                continue;
            if (g_arp_l2_pqc_count >= MAX_CRYPTO_POLICIES)
                break;

            e = &g_arp_l2_pqc[g_arp_l2_pqc_count++];
            e->policy_index = idx;
            e->priority = cp->priority;
            e->wire_id = cp->id;
            e->db_id = cp->db_id;
            e->profile_id = p->id;
            e->src_any = cp->src_any;
            e->dst_any = cp->dst_any;
            e->src_negate = cp->src_negate;
            e->dst_negate = cp->dst_negate;
            e->src_net = cp->src_net;
            e->src_mask = cp->src_mask;
            e->dst_net = cp->dst_net;
            e->dst_mask = cp->dst_mask;
        }
    }

    fprintf(stderr, "[ARP] l2-pqc-any policies cached: %d\n", g_arp_l2_pqc_count);
}

static const struct arp_l2_pqc_entry *arp_bridge_match_policy(int profile_id,
                                                             uint32_t spa, uint32_t tpa)
{
    const struct arp_l2_pqc_entry *best = NULL;

    for (int i = 0; i < g_arp_l2_pqc_count; i++) {
        const struct arp_l2_pqc_entry *e = &g_arp_l2_pqc[i];

        if (profile_id > 0 && e->profile_id != profile_id)
            continue;
        if (!arp_entry_match_ips(e, spa, tpa))
            continue;
        if (!best ||
            e->priority < best->priority ||
            (e->priority == best->priority && e->wire_id < best->wire_id))
            best = e;
    }
    return best;
}

static const struct arp_l2_pqc_entry *arp_bridge_entry_by_wire_id(uint8_t wire_id)
{
    for (int i = 0; i < g_arp_l2_pqc_count; i++) {
        if (g_arp_l2_pqc[i].wire_id == (int)wire_id)
            return &g_arp_l2_pqc[i];
    }
    return NULL;
}

static struct ne_ring *arp_mid_to_local_ring(struct forwarder *fwd, int li)
{
    return &fwd->mid_to_local[li][dp_crypto_current_worker_idx()];
}

static struct ne_ring *arp_mid_to_wan_ring(struct forwarder *fwd, int wan_dp)
{
    return &fwd->mid_to_wan[wan_dp][dp_crypto_current_worker_idx()];
}

static int profile_pi_for_wan_dp(struct forwarder *fwd, int wan_dp)
{
    int cfg_idx;

    if (!fwd || !fwd->cfg)
        return -1;
    cfg_idx = config_wan_dp_to_cfg(fwd->cfg, wan_dp);
    if (cfg_idx < 0)
        return -1;

    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        const struct profile_config *p = &fwd->cfg->profiles[pi];

        if (!p->enabled)
            continue;
        for (int wi = 0; wi < p->wan_count; wi++) {
            if (p->wan_indices[wi] == cfg_idx)
                return pi;
        }
    }
    return -1;
}

/* bridges[].local_idx is cfg locals[] index — map to live fwd pair slot by ifname. */
static int bridge_fwd_local(struct forwarder *fwd, int cfg_local_idx)
{
    return mac_fwd_local_for_cfg_idx(fwd, cfg_local_idx);
}

static int resolve_wan_dp_for_fwd_local(struct forwarder *fwd,
                                        const struct profile_config *prof,
                                        int fwd_local_idx, int *wan_dp_out)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || !prof || !wan_dp_out || fwd_local_idx < 0 ||
        fwd_local_idx >= fwd->local_count)
        return -1;
    ifname = fwd->locals[fwd_local_idx].ifname;
    if (!ifname[0])
        return -1;

    for (int i = 0; i < prof->bridge_count; i++) {
        int ci = prof->bridges[i].local_idx;

        if (ci < 0 || ci >= fwd->cfg->local_count)
            continue;
        if (strcmp(fwd->cfg->locals[ci].ifname, ifname) != 0)
            continue;
        *wan_dp_out = prof->bridges[i].wan_dp;
        return 0;
    }
    return -1;
}

static int resolve_fwd_local_for_wan_dp(struct forwarder *fwd,
                                        const struct profile_config *prof,
                                        int ingress_wan_dp, int *fwd_local_out)
{
    if (!fwd || !prof || !fwd_local_out || ingress_wan_dp < 0)
        return -1;

    for (int i = 0; i < prof->bridge_count; i++) {
        int li;

        if (prof->bridges[i].wan_dp != ingress_wan_dp)
            continue;
        li = bridge_fwd_local(fwd, prof->bridges[i].local_idx);
        if (li < 0)
            return -1;
        *fwd_local_out = li;
        return 0;
    }
    return -1;
}

static const char *local_ifname(struct forwarder *fwd, int li)
{
    if (!fwd || li < 0 || li >= fwd->local_count)
        return "?";
    return fwd->locals[li].ifname;
}

static const char *wan_ifname(struct forwarder *fwd, int wan_dp)
{
    if (!fwd || wan_dp < 0 || wan_dp >= fwd->wan_count)
        return "?";
    return fwd->wans[wan_dp].ifname;
}

static int profile_pi_for_fwd_local(struct forwarder *fwd, int fwd_li)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || fwd_li < 0 || fwd_li >= fwd->local_count)
        return -1;
    ifname = fwd->locals[fwd_li].ifname;
    if (!ifname[0])
        return -1;

    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        const struct profile_config *p = &fwd->cfg->profiles[pi];

        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++) {
            int ci = p->local_indices[i];

            if (ci < 0 || ci >= fwd->cfg->local_count)
                continue;
            if (strcmp(fwd->cfg->locals[ci].ifname, ifname) == 0)
                return pi;
        }
    }
    return -1;
}

static int arp_try_encrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job,
                                  uint8_t *pkt, int profile_id)
{
    uint32_t spa = 0, tpa = 0;
    const struct arp_l2_pqc_entry *e;
    struct packet_crypto_ctx *pctx;
    uint8_t scratch[NE_FRAME];
    uint32_t orig_len;
    uint32_t len;

    if (!fwd || !fwd->cfg || !fwd->cfg->crypto_enabled || !job || !pkt)
        return 0;
    if (dp_parse_arp_ips(pkt, job->len, &spa, &tpa) != 0)
        return 0;

    e = arp_bridge_match_policy(profile_id, spa, tpa);
    if (!e)
        return 0;
    if (!fwd_crypto_policy_ready(e->policy_index))
        return 0;

    pctx = fwd_crypto_policy_ctx(e->policy_index);
    if (!pctx)
        return 0;

    orig_len = job->len;
    if (orig_len > NE_FRAME)
        return 0;
    memcpy(scratch, pkt, orig_len);
    len = orig_len;

    pctx->profile_id = profile_id;
    pctx->wire_id = (uint8_t)e->wire_id;
    pctx->policy_id = e->db_id;

    if (crypto_option_encrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP, pctx, pkt, &len) != 0) {
        memcpy(pkt, scratch, orig_len);
        job->len = orig_len;
        return 0;
    }
    job->len = len;
    return 1;
}

static int arp_try_decrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job, uint8_t *pkt)
{
    uint8_t wire_id = 0;
    const struct arp_l2_pqc_entry *e;
    struct packet_crypto_ctx *pctx;
    uint32_t len;

    if (!fwd || !fwd->cfg || !fwd->cfg->crypto_enabled || !job || !pkt)
        return -1;
    if (!crypto_eth_l2_has_marker(pkt, job->len))
        return 0;
    if (crypto_eth_l2_read_policy_id(pkt, job->len, &wire_id) != 0)
        return -1;

    e = arp_bridge_entry_by_wire_id(wire_id);
    if (!e)
        return -1;

    pctx = fwd_crypto_ctx_for_wire_id(wire_id);
    if (!pctx)
        return -1;

    len = job->len;
    if (crypto_option_decrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP, pctx, pkt, &len) != 0)
        return -1;
    if (!crypto_pkt_is_arp(pkt, len))
        return -1;
    job->len = len;
    return 1;
}

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE])
{
    int profile_pi;
    const struct profile_config *prof;
    int wan_dp;
    struct ne_ring *ring;
    uint8_t *mut;

    if (egress_ifname)
        egress_ifname[0] = '\0';

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    mut = ne_packet_data(&fwd->pair, job->addr);
    if (!mut)
        return -1;

    profile_pi = profile_pi_for_fwd_local(fwd, ingress_li);
    if (profile_pi < 0) {
        static uint64_t last_no_profile_ms;

        if (arp_log_fail_ratelimit(&last_no_profile_ms))
            fprintf(stderr, "[ARP] bridge local %s fail: no profile\n",
                    local_ifname(fwd, ingress_li));
        return -1;
    }

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_wan_dp_for_fwd_local(fwd, prof, ingress_li, &wan_dp) != 0) {
        static uint64_t last_no_pair_ms;

        if (arp_log_fail_ratelimit(&last_no_pair_ms))
            fprintf(stderr,
                    "[ARP] bridge local %s fail: no BE pair (profile=%s bridges=%d)\n",
                    local_ifname(fwd, ingress_li), prof->name, prof->bridge_count);
        return -1;
    }
    if (wan_dp < 0 || wan_dp >= fwd->wan_count)
        return -1;
    if (fwd_wan_is_stopped(wan_dp)) {
        static uint64_t last_wan_stopped_ms;

        if (arp_log_fail_ratelimit(&last_wan_stopped_ms))
            fprintf(stderr, "[ARP] bridge local %s -> wan %s fail: wan stopped\n",
                    local_ifname(fwd, ingress_li), wan_ifname(fwd, wan_dp));
        return -1;
    }

    (void)arp_try_encrypt_l2_pqc(fwd, job, mut, prof->id);

    ring = arp_mid_to_wan_ring(fwd, wan_dp);
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (dp_ring_push(fwd, ring, job) != 0) {
        static uint64_t last_ring_fail_ms;

        if (arp_log_fail_ratelimit(&last_ring_fail_ms))
            fprintf(stderr, "[ARP] bridge local %s -> wan %s fail: ring push\n",
                    local_ifname(fwd, ingress_li), wan_ifname(fwd, wan_dp));
        return -1;
    }
    if (egress_ifname)
        strncpy(egress_ifname, wan_ifname(fwd, wan_dp), IF_NAMESIZE - 1);
    return 0;
}

int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE])
{
    int profile_pi;
    const struct profile_config *prof;
    int local_idx;
    struct ne_ring *ring;
    uint8_t *mut;
    int dec;

    if (egress_ifname)
        egress_ifname[0] = '\0';

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    mut = ne_packet_data(&fwd->pair, job->addr);
    if (!mut)
        return -1;

    dec = arp_try_decrypt_l2_pqc(fwd, job, mut);
    if (dec < 0)
        return -1;

    profile_pi = profile_pi_for_wan_dp(fwd, ingress_wan_dp);
    if (profile_pi < 0) {
        static uint64_t last_no_profile_ms;

        if (arp_log_fail_ratelimit(&last_no_profile_ms))
            fprintf(stderr, "[ARP] bridge wan %s fail: no profile\n",
                    wan_ifname(fwd, ingress_wan_dp));
        return -1;
    }

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_fwd_local_for_wan_dp(fwd, prof, ingress_wan_dp, &local_idx) != 0) {
        static uint64_t last_no_pair_ms;

        if (arp_log_fail_ratelimit(&last_no_pair_ms))
            fprintf(stderr,
                    "[ARP] bridge wan %s fail: no BE pair (profile=%s bridges=%d)\n",
                    wan_ifname(fwd, ingress_wan_dp), prof->name, prof->bridge_count);
        return -1;
    }

    ring = arp_mid_to_local_ring(fwd, local_idx);
    job->dir = NE_DIR_LOCAL;
    job->local_idx = (uint8_t)local_idx;
    if (dp_ring_push(fwd, ring, job) != 0) {
        static uint64_t last_ring_fail_ms;

        if (arp_log_fail_ratelimit(&last_ring_fail_ms))
            fprintf(stderr, "[ARP] bridge wan %s -> local %s fail: ring push\n",
                    wan_ifname(fwd, ingress_wan_dp), local_ifname(fwd, local_idx));
        return -1;
    }
    if (egress_ifname)
        strncpy(egress_ifname, local_ifname(fwd, local_idx), IF_NAMESIZE - 1);
    return 0;
}
