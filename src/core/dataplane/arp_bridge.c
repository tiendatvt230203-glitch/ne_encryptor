#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/interface.h"

#include <string.h>

static struct ne_ring *arp_mid_to_local_ring(struct forwarder *fwd, int li)
{
    int bwi = dp_bypass_current_worker_idx();

    if (bwi >= 0)
        return &fwd->mid_to_local_bypass[li][bwi];
    return &fwd->mid_to_local[li][dp_crypto_current_worker_idx()];
}

static struct ne_ring *arp_mid_to_wan_ring(struct forwarder *fwd, int wan_dp)
{
    int bwi = dp_bypass_current_worker_idx();

    if (bwi >= 0)
        return &fwd->mid_to_wan_bypass[wan_dp][bwi];
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

static const struct bridge_pair *bridge_pair_for_local(const struct profile_config *prof,
                                                       int ingress_li)
{
    if (!prof || !prof->bridge_enable || ingress_li < 0)
        return NULL;

    for (int i = 0; i < prof->bridge_count; i++) {
        if (prof->bridges[i].local_idx == ingress_li)
            return &prof->bridges[i];
    }
    return NULL;
}

static const struct bridge_pair *bridge_pair_for_wan(const struct profile_config *prof,
                                                     int ingress_wan_dp)
{
    if (!prof || !prof->bridge_enable || ingress_wan_dp < 0)
        return NULL;

    for (int i = 0; i < prof->bridge_count; i++) {
        if (prof->bridges[i].wan_dp == ingress_wan_dp)
            return &prof->bridges[i];
    }
    return NULL;
}

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li)
{
    int profile_pi;
    const struct profile_config *prof;
    const struct bridge_pair *bp;
    struct ne_ring *ring;

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    profile_pi = config_select_profile_for_local(fwd->cfg, ingress_li);
    if (profile_pi < 0)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    bp = bridge_pair_for_local(prof, ingress_li);
    if (!bp || bp->wan_dp < 0 || bp->wan_dp >= fwd->wan_count)
        return -1;
    if (fwd_wan_is_stopped(bp->wan_dp))
        return -1;

    ring = arp_mid_to_wan_ring(fwd, bp->wan_dp);
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)bp->wan_dp;
    if (ne_ring_try_push(ring, job) != 0)
        return -1;
    return 0;
}

int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp)
{
    int profile_pi;
    const struct profile_config *prof;
    const struct bridge_pair *bp;
    struct ne_ring *ring;

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    profile_pi = profile_pi_for_wan_dp(fwd, ingress_wan_dp);
    if (profile_pi < 0)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    bp = bridge_pair_for_wan(prof, ingress_wan_dp);
    if (!bp || bp->local_idx < 0 || bp->local_idx >= fwd->local_count)
        return -1;

    ring = arp_mid_to_local_ring(fwd, bp->local_idx);
    job->dir = NE_DIR_LOCAL;
    job->local_idx = (uint8_t)bp->local_idx;
    if (ne_ring_try_push(ring, job) != 0)
        return -1;
    return 0;
}
