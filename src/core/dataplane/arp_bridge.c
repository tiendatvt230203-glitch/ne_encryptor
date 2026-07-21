#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_wan.h"

#include <string.h>

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

/*
 * Resolve LAN -> WAN for ARP. Crypto policy is never consulted.
 * 1) bridge_interfaces pair from DB (bridges[])
 * 2) fallback: profile has exactly one LAN and one WAN
 */
static int resolve_wan_dp_for_local_arp(struct forwarder *fwd,
                                        const struct profile_config *prof,
                                        int ingress_li, int *wan_dp_out)
{
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
    if (prof->local_count != 1 || prof->wan_count != 1)
        return -1;

    *wan_dp_out = config_wan_cfg_to_dp(fwd->cfg, prof->wan_indices[0]);
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
    if (prof->local_count != 1 || prof->wan_count != 1)
        return -1;

    *local_idx_out = prof->local_indices[0];
    return 0;
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
    if (profile_pi < 0)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_wan_dp_for_local_arp(fwd, prof, ingress_li, &wan_dp) != 0)
        return -1;
    if (wan_dp < 0 || wan_dp >= fwd->wan_count)
        return -1;
    if (fwd_wan_is_stopped(wan_dp))
        return -1;

    ring = arp_mid_to_wan_ring(fwd, wan_dp);
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    return dp_ring_push(fwd, ring, job);
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
    if (profile_pi < 0)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_local_for_wan_arp(fwd, prof, ingress_wan_dp, &local_idx) != 0)
        return -1;
    if (local_idx < 0 || local_idx >= fwd->local_count)
        return -1;

    ring = arp_mid_to_local_ring(fwd, local_idx);
    job->dir = NE_DIR_LOCAL;
    job->local_idx = (uint8_t)local_idx;
    return dp_ring_push(fwd, ring, job);
}
