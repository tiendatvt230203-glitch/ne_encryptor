#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/profile_iface_xdp.h"

#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/flow_table.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define WAN_DRAIN_GRACE_MS (FORWARDER_WAN_DRAIN_SEC * 1000u)

typedef struct {
    int active;
    int legacy_cfg_wan;
    int seed_weight;
    char ifname[IF_NAMESIZE];
    uint64_t start_ms;
    uint64_t until_ms;
} wan_drain_slot;

typedef struct {
    int active;
    int profile_id;
    int n;
    int wan_cfg[MAX_PROFILE_INTERFACES];
    int old_w[MAX_PROFILE_INTERFACES];
    int new_w[MAX_PROFILE_INTERFACES];
    uint64_t start_ms;
    uint64_t until_ms;
} wan_weight_blend;

static wan_drain_slot wan_drains[MAX_INTERFACES];
static int wan_active_dp_count;
static uint8_t wan_stopped[MAX_INTERFACES];
static wan_weight_blend wan_weight_blends[MAX_PROFILES];

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static int wan_seed_weight_from_cfg(const struct app_config *cfg, int cfg_wan)
{
    int best = 1;
    if (!cfg)
        return best;
    for (int pr = 0; pr < cfg->profile_count; pr++) {
        const struct profile_config *p = &cfg->profiles[pr];
        for (int wi = 0; wi < p->wan_count; wi++) {
            if (p->wan_indices[wi] != cfg_wan)
                continue;
            if (p->wan_bandwidth_weight[wi] > best)
                best = p->wan_bandwidth_weight[wi];
        }
    }
    return best;
}

static int wan_drain_taper_pct(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES || !wan_drains[dp].active)
        return 0;
    uint64_t now = monotonic_ms();
    if (now >= wan_drains[dp].until_ms)
        return 0;
    uint64_t left = wan_drains[dp].until_ms - now;
    if (WAN_DRAIN_GRACE_MS == 0)
        return 0;
    return (int)((left * 100ULL) / WAN_DRAIN_GRACE_MS);
}

int fwd_wan_dp_ok_for_new_traffic(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES || wan_stopped[dp])
        return 0;
    if (wan_drains[dp].active)
        return 0;
    return dp < wan_active_dp_count;
}

int fwd_wan_is_stopped(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES)
        return 1;
    return wan_stopped[dp] != 0;
}

void fwd_wan_mark_stopped(int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES)
        return;
    wan_stopped[dp] = 1;
}

int fwd_wan_ifname_dataplane_in_cfg(const struct app_config *cfg, const char *ifname)
{
    return config_wan_live_in_cfg(cfg, ifname);
}

uint32_t fwd_wan_flush_queue(struct forwarder *fwd, int wan_idx)
{
    struct ne_packet pkt;
    uint32_t dropped = 0;
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return 0;
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        while (ne_ring_try_pop(&fwd->mid_to_wan[wan_idx][w], &pkt) == 0) {
            ne_frame_free(&fwd->pair, pkt.addr);
            dropped++;
        }
    }
    return dropped;
}

int fwd_wan_has_tx_room(struct forwarder *fwd, int wan_idx)
{
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return 0;
    int wi = dp_crypto_current_worker_idx();
    struct ne_ring *r = &fwd->mid_to_wan[wan_idx][wi];
    return ne_ring_count(r) + NE_BATCH_SIZE < r->cap;
}

static void wan_drain_finish_slot(struct forwarder *fwd, int dp)
{
    if (dp < 0 || dp >= MAX_INTERFACES || !wan_drains[dp].active)
        return;

    uint32_t dropped = fwd_wan_flush_queue(fwd, dp);
    profile_iface_xdp_detach_wan(&fwd->pair, dp);
    wan_stopped[dp] = 1;
    wan_drains[dp].active = 0;
    fprintf(stderr,
            "[WAN-DRAIN] %s stopped (queue flushed %u pkts, XDP detached)\n",
            wan_drains[dp].ifname, dropped);
    fflush(stderr);
}

void fwd_wan_drain_tick(struct forwarder *fwd)
{
    if (!fwd)
        return;
    uint64_t now = monotonic_ms();
    int n = fwd->wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int dp = 0; dp < n; dp++) {
        if (!wan_drains[dp].active)
            continue;
        int taper = wan_drain_taper_pct(dp);
        if (taper > 0)
            continue;
        if (now < wan_drains[dp].until_ms)
            continue;
        wan_drain_finish_slot(fwd, dp);
    }
}

void fwd_wan_reset_on_init(struct forwarder *fwd)
{
    wan_active_dp_count = fwd ? fwd->wan_count : 0;
    memset(wan_drains, 0, sizeof(wan_drains));
    memset(wan_stopped, 0, sizeof(wan_stopped));
}

void fwd_wan_configure_removal_drains(struct forwarder *fwd,
                                      const struct app_config *old,
                                      const struct app_config *cfg)
{
    if (!fwd || !old || !cfg)
        return;

    int dp_n = fwd->wan_count;
    if (dp_n > MAX_INTERFACES)
        dp_n = MAX_INTERFACES;

    for (int dp = 0; dp < dp_n; dp++) {
        int ci = fwd->wan_cfg_idx[dp];
        if (ci < 0 || ci >= old->wan_count)
            continue;
        if (!config_wan_live(old, ci))
            continue;
        if (fwd_wan_ifname_dataplane_in_cfg(cfg, old->wans[ci].ifname))
            continue;

        wan_drains[dp].active = 1;
        wan_drains[dp].legacy_cfg_wan = ci;
        wan_drains[dp].seed_weight = wan_seed_weight_from_cfg(old, ci);
        snprintf(wan_drains[dp].ifname, sizeof(wan_drains[dp].ifname), "%s",
                 old->wans[ci].ifname);
        wan_drains[dp].start_ms = monotonic_ms();
        wan_drains[dp].until_ms = wan_drains[dp].start_ms + WAN_DRAIN_GRACE_MS;
        fprintf(stderr,
                "[WAN-DRAIN] %s taper %us (existing flows migrate, no new flows)\n",
                wan_drains[dp].ifname, (unsigned)(WAN_DRAIN_GRACE_MS / 1000u));
    }
    fflush(stderr);

    wan_active_dp_count = config_count_dataplane_wans(cfg);
    for (int dp = 0; dp < dp_n; dp++) {
        if (wan_drains[dp].active)
            continue;
        int ci = -1;
        const char *want = fwd->wans[dp].ifname;
        for (int i = 0; i < cfg->wan_count; i++) {
            if (!config_wan_live(cfg, i))
                continue;
            if (strcmp(cfg->wans[i].ifname, want) == 0) {
                ci = i;
                break;
            }
        }
        if (ci >= 0)
            fwd->wan_cfg_idx[dp] = ci;
    }
}

void fwd_wan_configure_live_drains(struct forwarder *fwd,
                                   const struct app_config *old,
                                   const struct app_config *cfg)
{
    if (!fwd || !old || !cfg)
        return;

    int dp_n = fwd->wan_count;
    if (dp_n > MAX_INTERFACES)
        dp_n = MAX_INTERFACES;

    for (int dp = 0; dp < dp_n; dp++) {
        int ci = fwd->wan_cfg_idx[dp];

        if (ci < 0 || ci >= old->wan_count)
            continue;
        if (!config_wan_live(old, ci) || config_wan_live(cfg, ci))
            continue;
        if (wan_drains[dp].active || wan_stopped[dp])
            continue;

        wan_drains[dp].active = 1;
        wan_drains[dp].legacy_cfg_wan = ci;
        wan_drains[dp].seed_weight = wan_seed_weight_from_cfg(old, ci);
        snprintf(wan_drains[dp].ifname, sizeof(wan_drains[dp].ifname), "%s",
                 old->wans[ci].ifname);
        wan_drains[dp].start_ms = monotonic_ms();
        wan_drains[dp].until_ms = wan_drains[dp].start_ms + WAN_DRAIN_GRACE_MS;
        fprintf(stderr,
                "[WAN-DRAIN] %s weight=0 — taper %us (bandwidth removed, no new flows)\n",
                wan_drains[dp].ifname, (unsigned)(WAN_DRAIN_GRACE_MS / 1000u));
    }
    fflush(stderr);
}

static int wan_weight_blend_progress(const wan_weight_blend *b)
{
    if (!b || !b->active)
        return 100;
    uint64_t now = monotonic_ms();
    if (now >= b->until_ms)
        return 100;
    uint64_t elapsed = now - b->start_ms;
    uint64_t total = b->until_ms - b->start_ms;
    if (total == 0)
        return 100;
    return (int)((elapsed * 100ULL) / total);
}

static int profile_wan_weight_blended(const struct profile_config *p, int cfg_wan,
                                      int nominal_weight)
{
    if (!p || nominal_weight <= 0)
        return nominal_weight;

    for (int bi = 0; bi < MAX_PROFILES; bi++) {
        const wan_weight_blend *b = &wan_weight_blends[bi];
        int pos;
        int blend;
        int w;

        if (!b->active || b->profile_id != p->id)
            continue;
        pos = -1;
        for (int i = 0; i < b->n; i++) {
            if (b->wan_cfg[i] == cfg_wan) {
                pos = i;
                break;
            }
        }
        if (pos < 0)
            return nominal_weight;

        blend = wan_weight_blend_progress(b);
        w = (b->old_w[pos] * (100 - blend) + b->new_w[pos] * blend) / 100;
        return w > 0 ? w : 1;
    }
    return nominal_weight;
}

void fwd_wan_weight_blend_tick(void)
{
    for (int bi = 0; bi < MAX_PROFILES; bi++) {
        if (!wan_weight_blends[bi].active)
            continue;
        if (wan_weight_blend_progress(&wan_weight_blends[bi]) >= 100)
            wan_weight_blends[bi].active = 0;
    }
}

void fwd_wan_weight_blend_begin(const struct app_config *old, const struct app_config *new,
                                int (*profile_slot_for_id)(int profile_id))
{
    if (!old || !new)
        return;

    for (int bi = 0; bi < MAX_PROFILES; bi++)
        wan_weight_blends[bi].active = 0;

    for (int pi = 0; pi < new->profile_count; pi++) {
        const struct profile_config *np = &new->profiles[pi];
        const struct profile_config *op = NULL;

        for (int oi = 0; oi < old->profile_count; oi++) {
            if (old->profiles[oi].id == np->id) {
                op = &old->profiles[oi];
                break;
            }
        }
        if (!op || op->wan_count != np->wan_count)
            continue;

        int changed = 0;
        for (int i = 0; i < np->wan_count; i++) {
            if (op->wan_indices[i] != np->wan_indices[i] ||
                op->wan_bandwidth_weight[i] != np->wan_bandwidth_weight[i]) {
                changed = 1;
                break;
            }
        }
        if (!changed)
            continue;

        int slot = profile_slot_for_id ? profile_slot_for_id(np->id) : -1;
        if (slot < 0)
            slot = pi % MAX_PROFILES;

        wan_weight_blend *b = &wan_weight_blends[slot];
        b->active = 1;
        b->profile_id = np->id;
        b->n = np->wan_count;
        b->start_ms = monotonic_ms();
        b->until_ms = b->start_ms + WAN_DRAIN_GRACE_MS;
        for (int i = 0; i < np->wan_count && i < MAX_PROFILE_INTERFACES; i++) {
            b->wan_cfg[i] = np->wan_indices[i];
            b->old_w[i] = op->wan_bandwidth_weight[i];
            b->new_w[i] = np->wan_bandwidth_weight[i];
        }
        fprintf(stderr,
                "[WAN-BALANCE] profile %d — WAN weights blend %us (old→new, flows migrate gradually)\n",
                np->id, (unsigned)(WAN_DRAIN_GRACE_MS / 1000u));
    }
    fflush(stderr);
}

int fwd_wan_build_profile_pool(struct forwarder *fwd, const struct profile_config *p,
                               int *allowed_wans, int *allowed_weights, int max_n)
{
    int n = 0;
    if (!p || !allowed_wans || !allowed_weights || max_n <= 0)
        return 0;

    for (int i = 0; i < p->wan_count && n < max_n; i++) {
        int wi = p->wan_indices[i];
        int dp = config_wan_cfg_to_dp(fwd->cfg, wi);
        if (dp < 0 || !fwd_wan_dp_ok_for_new_traffic(dp))
            continue;
        allowed_wans[n] = wi;
        allowed_weights[n] = profile_wan_weight_blended(
            p, wi, p->wan_bandwidth_weight[i]);
        n++;
    }

    int wan_n = fwd->wan_count;
    if (wan_n > MAX_INTERFACES)
        wan_n = MAX_INTERFACES;
    for (int dp = 0; dp < wan_n && n < max_n; dp++) {
        int taper;
        if (!wan_drains[dp].active || wan_stopped[dp])
            continue;
        taper = wan_drain_taper_pct(dp);
        if (taper <= 0)
            continue;
        allowed_wans[n] = wan_drains[dp].legacy_cfg_wan;
        allowed_weights[n] = (wan_drains[dp].seed_weight * taper) / 100;
        if (allowed_weights[n] <= 0)
            allowed_weights[n] = 1;
        n++;
    }
    return n;
}

int fwd_wan_dp_for_legacy_cfg(struct forwarder *fwd, int legacy_cfg_wan)
{
    int n = fwd->wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int dp = 0; dp < n; dp++) {
        if (!wan_drains[dp].active || wan_stopped[dp])
            continue;
        if (wan_drains[dp].legacy_cfg_wan != legacy_cfg_wan)
            continue;
        if (wan_drain_taper_pct(dp) <= 0)
            continue;
        return dp;
    }
    (void)fwd;
    return -1;
}

static int pick_least_loaded_wan(struct forwarder *fwd, int profile_idx, int selected)
{
    if (fwd_wan_has_tx_room(fwd, selected))
        return selected;

    int best = -1;
    uint32_t best_depth = UINT32_MAX;
    int profile_pool = 0;

    if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
        struct profile_config *p = &fwd->cfg->profiles[profile_idx];
        int sumw = 0;
        profile_pool = p->wan_count > 0;
        for (int i = 0; i < p->wan_count; i++)
            if (p->wan_bandwidth_weight[i] > 0)
                sumw += p->wan_bandwidth_weight[i];
        for (int i = 0; i < p->wan_count; i++) {
            if (sumw > 0 && p->wan_bandwidth_weight[i] <= 0)
                continue;
            int dp = config_wan_cfg_to_dp(fwd->cfg, p->wan_indices[i]);
            if (dp < 0 || !fwd_wan_dp_ok_for_new_traffic(dp) || !fwd_wan_has_tx_room(fwd, dp))
                continue;
            uint32_t d = fwd_mid_to_wan_depth(fwd, dp);
            if (d < best_depth) {
                best_depth = d;
                best = dp;
            }
        }
        if (best >= 0)
            return best;
    }

    if (profile_pool)
        return selected;

    for (int wi = 0; wi < fwd->wan_count; wi++) {
        if (!fwd_wan_dp_ok_for_new_traffic(wi) || !fwd_wan_has_tx_room(fwd, wi))
            continue;
        uint32_t d = fwd_mid_to_wan_depth(fwd, wi);
        if (d < best_depth) {
            best_depth = d;
            best = wi;
        }
    }
    return best >= 0 ? best : selected;
}

int fwd_wan_pick_for_local(struct forwarder *fwd, int profile_idx, int flow_ok,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint8_t proto, uint32_t pkt_len)
{
    if (!fwd || fwd->wan_count <= 0)
        return -1;
    if (profile_idx < 0 || profile_idx >= fwd->cfg->profile_count)
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    struct profile_config *p = &fwd->cfg->profiles[profile_idx];
    int allowed_wans[MAX_INTERFACES];
    int allowed_weights[MAX_INTERFACES];
    int pool_n = fwd_wan_build_profile_pool(fwd, p, allowed_wans, allowed_weights,
                                            MAX_INTERFACES);
    if (pool_n <= 0)
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    int slot = fwd_crypto_profile_slot_for_id(p->id);
    int wan_cfg = flow_ok && slot >= 0 && fwd_crypto_flow_table_ready(slot)
        ? flow_table_get_wan_profile(fwd_crypto_flow_table(slot),
                                     src_ip, dst_ip, src_port, dst_port, proto, pkt_len,
                                     allowed_wans, pool_n, allowed_weights)
        : flow_table_pick_wan_per_packet(allowed_wans, allowed_weights, pool_n);
    if (wan_cfg < 0)
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    int dp = config_wan_cfg_to_dp(fwd->cfg, wan_cfg);
    if (dp < 0)
        dp = fwd_wan_dp_for_legacy_cfg(fwd, wan_cfg);
    if (dp < 0 || dp >= fwd->wan_count || fwd_wan_is_stopped(dp))
        return pick_least_loaded_wan(fwd, profile_idx, 0);

    return dp;
}
