#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_wan.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define ARP_LOG_FAIL_INTERVAL_MS 30000ull

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

static int profile_owns_local(const struct profile_config *prof, int local_idx)
{
    if (!prof || local_idx < 0)
        return 0;
    for (int i = 0; i < prof->local_count; i++) {
        if (prof->local_indices[i] == local_idx)
            return 1;
    }
    return 0;
}

static int profile_owns_wan_cfg(const struct profile_config *prof, int wan_cfg_idx)
{
    if (!prof || wan_cfg_idx < 0)
        return 0;
    for (int i = 0; i < prof->wan_count; i++) {
        if (prof->wan_indices[i] == wan_cfg_idx)
            return 1;
    }
    return 0;
}

static int profile_local_slot(const struct profile_config *prof, int local_idx)
{
    if (!prof || local_idx < 0)
        return -1;
    for (int i = 0; i < prof->local_count; i++) {
        if (prof->local_indices[i] == local_idx)
            return i;
    }
    return -1;
}

static int profile_dataplane_wan_count(const struct app_config *cfg,
                                       const struct profile_config *prof)
{
    int n = 0;

    if (!cfg || !prof)
        return 0;
    for (int i = 0; i < prof->wan_count; i++) {
        if (config_wan_live(cfg, prof->wan_indices[i]))
            n++;
    }
    return n;
}

static int profile_dataplane_wan_cfg_at(const struct app_config *cfg,
                                        const struct profile_config *prof, int dp_slot)
{
    int seen = 0;

    if (!cfg || !prof || dp_slot < 0)
        return -1;
    for (int i = 0; i < prof->wan_count; i++) {
        int wi = prof->wan_indices[i];

        if (!config_wan_live(cfg, wi))
            continue;
        if (seen == dp_slot)
            return wi;
        seen++;
    }
    return -1;
}

static int profile_dataplane_wan_dp_at(const struct app_config *cfg,
                                       const struct profile_config *prof, int dp_slot)
{
    int wan_cfg = profile_dataplane_wan_cfg_at(cfg, prof, dp_slot);

    if (wan_cfg < 0)
        return -1;
    return config_wan_cfg_to_dp(cfg, wan_cfg);
}

static int profile_dataplane_wan_slot(const struct app_config *cfg,
                                      const struct profile_config *prof, int wan_cfg_idx)
{
    int seen = 0;

    if (!cfg || !prof || wan_cfg_idx < 0)
        return -1;
    for (int i = 0; i < prof->wan_count; i++) {
        int wi = prof->wan_indices[i];

        if (!config_wan_live(cfg, wi))
            continue;
        if (wi == wan_cfg_idx)
            return seen;
        seen++;
    }
    return -1;
}

/*
 * Resolve LAN -> WAN for ARP. Crypto policy is never consulted.
 * 1) bridge pair from kernel_bridge_refresh_profile_pairs (bridges[])
 * 2) fallback: same index in profile local_indices[] / wan_indices[]
 * 3) fallback: profile has exactly one LAN and one WAN
 */
static int resolve_wan_dp_for_local_arp(struct forwarder *fwd,
                                        const struct profile_config *prof,
                                        int ingress_li, int *wan_dp_out)
{
    int li_slot;
    int wan_cfg_idx;

    if (!fwd || !fwd->cfg || !prof || !wan_dp_out || ingress_li < 0)
        return -1;

    for (int i = 0; i < prof->bridge_count; i++) {
        if (prof->bridges[i].local_idx == ingress_li) {
            *wan_dp_out = prof->bridges[i].wan_dp;
            return 0;
        }
    }

    if (!profile_owns_local(prof, ingress_li))
        return -1;

    li_slot = profile_local_slot(prof, ingress_li);
    if (li_slot >= 0 &&
        prof->local_count == profile_dataplane_wan_count(fwd->cfg, prof) &&
        li_slot < profile_dataplane_wan_count(fwd->cfg, prof)) {
        *wan_dp_out = profile_dataplane_wan_dp_at(fwd->cfg, prof, li_slot);
        return (*wan_dp_out >= 0) ? 0 : -1;
    }

    if (prof->local_count != 1 || profile_dataplane_wan_count(fwd->cfg, prof) != 1)
        return -1;

    wan_cfg_idx = profile_dataplane_wan_cfg_at(fwd->cfg, prof, 0);
    *wan_dp_out = config_wan_cfg_to_dp(fwd->cfg, wan_cfg_idx);
    return (*wan_dp_out >= 0) ? 0 : -1;
}

/*
 * Resolve WAN -> LAN for ARP. Crypto policy is never consulted.
 */
static int resolve_local_for_wan_arp(struct forwarder *fwd,
                                     const struct profile_config *prof,
                                     int ingress_wan_dp, int *local_idx_out)
{
    int wan_cfg_idx;
    int dp_wan_slot;

    if (!fwd || !fwd->cfg || !prof || !local_idx_out || ingress_wan_dp < 0)
        return -1;

    for (int i = 0; i < prof->bridge_count; i++) {
        if (prof->bridges[i].wan_dp == ingress_wan_dp) {
            *local_idx_out = prof->bridges[i].local_idx;
            return 0;
        }
    }

    wan_cfg_idx = config_wan_dp_to_cfg(fwd->cfg, ingress_wan_dp);
    if (wan_cfg_idx < 0 || !profile_owns_wan_cfg(prof, wan_cfg_idx))
        return -1;

    dp_wan_slot = profile_dataplane_wan_slot(fwd->cfg, prof, wan_cfg_idx);
    if (dp_wan_slot >= 0 &&
        prof->local_count == profile_dataplane_wan_count(fwd->cfg, prof) &&
        dp_wan_slot < prof->local_count) {
        *local_idx_out = prof->local_indices[dp_wan_slot];
        return 0;
    }

    if (prof->local_count != 1 || profile_dataplane_wan_count(fwd->cfg, prof) != 1)
        return -1;

    *local_idx_out = prof->local_indices[0];
    return 0;
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

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li)
{
    int profile_pi;
    const struct profile_config *prof;
    int wan_dp;
    struct ne_ring *ring;

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    profile_pi = config_select_profile_for_local(fwd->cfg, ingress_li);
    if (profile_pi < 0) {
        static uint64_t last_no_profile_ms;

        if (arp_log_fail_ratelimit(&last_no_profile_ms))
            fprintf(stderr, "[ARP] bridge local %s fail: no profile\n",
                    local_ifname(fwd, ingress_li));
        return -1;
    }

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_wan_dp_for_local_arp(fwd, prof, ingress_li, &wan_dp) != 0) {
        static uint64_t last_no_pair_ms;

        if (arp_log_fail_ratelimit(&last_no_pair_ms))
            fprintf(stderr,
                    "[ARP] bridge local %s fail: no wan pair (profile=%s lan=%d wan=%d dp_wan=%d bridges=%d)\n",
                    local_ifname(fwd, ingress_li), prof->name,
                    prof->local_count, prof->wan_count,
                    profile_dataplane_wan_count(fwd->cfg, prof), prof->bridge_count);
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
    return 0;
}

int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp)
{
    int profile_pi;
    const struct profile_config *prof;
    int local_idx;
    struct ne_ring *ring;

    if (!fwd || !fwd->cfg || !job || !pkt)
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
    if (resolve_local_for_wan_arp(fwd, prof, ingress_wan_dp, &local_idx) != 0) {
        static uint64_t last_no_pair_ms;

        if (arp_log_fail_ratelimit(&last_no_pair_ms))
            fprintf(stderr, "[ARP] bridge wan %s fail: no local pair (profile=%s)\n",
                    wan_ifname(fwd, ingress_wan_dp), prof->name);
        return -1;
    }
    if (local_idx < 0 || local_idx >= fwd->local_count)
        return -1;

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
    return 0;
}
