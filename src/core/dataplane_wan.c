#include "../../inc/core/dataplane.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_crypto_runtime.h"

#include "../../inc/crypto/crypto_dispatch.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/crypto/packet_crypto.h"

#include "../../inc/core/fragment.h"
#include "../../inc/core/crypto_route.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/mac_learn.h"
#include "../../inc/core/dataplane_stats.h"

#include <string.h>

static const struct crypto_policy *fwd_l2_policy_by_wire_id(struct forwarder *fwd, uint8_t wire_id)
{
    if (!fwd || !fwd->cfg)
        return NULL;
    for (int i = 0; i < fwd->cfg->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[i];
        if (cp->action == POLICY_ACTION_ENCRYPT_L2 && (uint8_t)cp->id == wire_id)
            return cp;
    }
    return NULL;
}

static void wan_apply_l2_policy(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint8_t wire_id = 0;

    if (crypto_layer2_read_policy_id(pkt, len, &wire_id) != 0)
        return;
    const struct crypto_policy *cp = fwd_l2_policy_by_wire_id(fwd, wire_id);
    if (cp)
        crypto_apply_from_policy(cp);
}

static int wan_l2_plain_ipv4(const uint8_t *pkt, uint32_t len)
{
    return crypto_pkt_is_ipv4(pkt, len);
}

static int wan_is_bypass_plain(const uint8_t *pkt, uint32_t len)
{
    return wan_l2_plain_ipv4(pkt, len);
}

static int wan_has_crypto(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t pol = 0;

    if (!pkt)
        return 0;
    if (wan_is_bypass_plain(pkt, len))
        return 1;
    if (!fwd->cfg || !fwd->cfg->crypto_enabled)
        return 0;
    if (frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx) ||
        frag_is_fragment(fwd->cfg, pkt, len, &pid, &fidx) ||
        frag_is_fragment_l4(fwd->cfg, pkt, len, &pid, &fidx))
        return 1;
    if (fwd_crypto_has_l2_marker(pkt, len))
        return 1;
    if (crypto_l3_extract_policy_id(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return 1;
    if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return 1;
    return 0;
}

static int decrypt_l2(uint8_t *pkt, uint32_t *len)
{
    struct packet_crypto_ctx *ctx;
    uint8_t wire_id = 0;
    int n;

    if (!pkt || !len)
        return 0;
    if (!crypto_layer2_has_fake_ethertype(pkt, *len))
        return 0;
    if (crypto_layer2_read_policy_id(pkt, *len, &wire_id) != 0)
        return 0;
    ctx = fwd_crypto_ctx_for_wire_id(wire_id);
    if (!ctx)
        return -1;
    n = crypto_layer2_decrypt(ctx, pkt, *len);
    if (n < 0)
        return -1;
    *len = (uint32_t)n;
    return 0;
}

static int reassemble_l2(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    int slot, nd, rr;
    uint16_t opid;
    uint8_t ofidx;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    nd = crypto_layer2_decrypt_fragment(ctx, pkt, *len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    rr = frag_try_reassemble_l2(fwd_crypto_frag_l2(slot, dp_crypto_current_worker_idx()),
                                pkt, (uint32_t)nd, opid, ofidx, buf, &blen);
    if (rr == 0) {
        *pending = 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    memcpy(pkt, buf, blen);
    *len = blen;
    return 0;
}

static int reassemble_l3(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    int slot, nd, rr;
    uint16_t opid;
    uint8_t ofidx;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    nd = crypto_layer3_decrypt_fragment(ctx, pkt, *len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    rr = frag_try_reassemble(fwd_crypto_frag_l3(slot, dp_crypto_current_worker_idx()),
                             pkt, (uint32_t)nd, opid, ofidx, buf, &blen);
    if (rr == 0) {
        *pending = 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    memcpy(pkt, buf, blen);
    *len = blen;
    return 0;
}

static int reassemble_l4(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    int slot, nd, rr;
    uint16_t opid;
    uint8_t ofidx;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    nd = crypto_layer4_decrypt_fragment(ctx, pkt, *len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    rr = frag_try_reassemble_l4(fwd_crypto_frag_l4(slot, dp_crypto_current_worker_idx()),
                                pkt, (uint32_t)nd, opid, ofidx, buf, &blen);
    if (rr == 0) {
        *pending = 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    memcpy(pkt, buf, blen);
    *len = blen;
    return 0;
}

static int decrypt_wan(struct forwarder *fwd, struct ne_packet *job)
{
    uint8_t scratch[8192];
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t len = job->len;
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t pol = 0;
    int pending = 0;
    struct crypto_dispatch_ctx dctx;

    {
        int frag_mark = 0;
        int ns = PACKET_CRYPTO_NONCE_BYTES;
        int mark_off;
        uint32_t orig_len = len;
        uint8_t wire_pol = 0;

        wan_apply_l2_policy(fwd, pkt, len);
        mark_off = crypto_layer2_frag_magic_off(pkt, len, ns);
        if (mark_off >= 0 && len > (uint32_t)mark_off)
            frag_mark = (pkt[mark_off] == CRYPTO_L2_FRAG_MAGIC);

        int need_backup = frag_mark ||
            frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx);
        if (need_backup && orig_len <= sizeof(scratch))
            memcpy(scratch, pkt, orig_len);
        if (decrypt_l2(pkt, &len) != 0 || !wan_l2_plain_ipv4(pkt, len)) {
            if (need_backup)
                memcpy(pkt, scratch, orig_len);
            len = orig_len;
            if (frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx)) {
                if (crypto_layer2_read_policy_id(pkt, len, &wire_pol) != 0)
                    return -1;
                if (reassemble_l2(fwd, pkt, &len, wire_pol, &pending) != 0)
                    return -1;
            } else {
                return -1;
            }
        }
    }
    if (pending)
        return 1;

    if (!fwd->cfg->crypto_enabled) {
        job->len = len;
        return 0;
    }

    dctx = fwd_crypto_make_dispatch_ctx();
    if (frag_is_fragment(fwd->cfg, pkt, len, &pid, &fidx)) {
        if (crypto_l3_extract_policy_id(fwd->cfg, pkt, len, &pol) != 0)
            return -1;
        if (reassemble_l3(fwd, pkt, &len, pol, &pending) != 0)
            return -1;
    } else if (crypto_l3_extract_policy_id(fwd->cfg, pkt, len, &pol) == 0 &&
               crypto_decrypt_packet_auto_by_action(1, fwd->cfg, &dctx,
                                                    POLICY_ACTION_ENCRYPT_L3,
                                                    pkt, &len, scratch, sizeof(scratch)) != 0) {
        return -1;
    }
    if (pending)
        return 1;

    if (frag_is_fragment_l4(fwd->cfg, pkt, len, &pid, &fidx)) {
        if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, pkt, len, &pol) != 0)
            return -1;
        if (reassemble_l4(fwd, pkt, &len, pol, &pending) != 0)
            return -1;
    } else if (crypto_decrypt_packet_auto_by_action(1, fwd->cfg, &dctx,
                                                      POLICY_ACTION_ENCRYPT_L4,
                                                      pkt, &len, scratch,
                                                      sizeof(scratch)) != 0) {
        return -1;
    }
    if (pending)
        return 1;

    job->len = len;
    return 0;
}

static int eth_dmac_is_unicast(const uint8_t *pkt)
{
    return (pkt[0] & 0x01u) == 0;
}

static int profile_owns_local(const struct app_config *cfg, int profile_pi, int local_idx)
{
    const struct profile_config *prof;

    if (!cfg || profile_pi < 0 || profile_pi >= cfg->profile_count)
        return 0;
    prof = &cfg->profiles[profile_pi];
    if (!prof->enabled)
        return 0;
    for (int i = 0; i < prof->local_count; i++) {
        if (prof->local_indices[i] == local_idx)
            return 1;
    }
    return 0;
}

static int profile_pi_for_wire_policy(struct forwarder *fwd, uint8_t wire_id)
{
    int profile_id;

    if (!fwd || !fwd->cfg)
        return -1;
    profile_id = fwd_crypto_profile_id_for_wire_id(wire_id);
    if (profile_id < 0)
        return -1;
    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        if (fwd->cfg->profiles[pi].id == profile_id)
            return pi;
    }
    return -1;
}

static int flood_to_profile_locals(struct forwarder *fwd, struct ne_packet *job,
                                   const uint8_t *pkt, int profile_pi)
{
    const struct profile_config *prof;
    int wi;
    int sent = 0;
    uint16_t sent_mask = 0;

    if (!fwd || !job || !pkt || !fwd->cfg || profile_pi < 0 ||
        profile_pi >= fwd->cfg->profile_count)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled || prof->local_count <= 0)
        return -1;

    wi = dp_crypto_current_worker_idx();

    for (int i = 0; i < prof->local_count; i++) {
        int li = prof->local_indices[i];
        struct ne_ring *ring;

        if (li < 0 || li >= fwd->local_count)
            continue;
        if (li < (int)(sizeof(sent_mask) * 8) && (sent_mask & (1u << li)) != 0)
            continue;

        ring = &fwd->mid_to_local[li][wi];

        if (sent == 0) {
            job->dir = NE_DIR_LOCAL;
            job->local_idx = (uint8_t)li;
            if (ne_ring_try_push(ring, job) != 0)
                return -1;
            sent = 1;
        } else {
            struct ne_packet clone = {
                .len = job->len,
                .dir = NE_DIR_LOCAL,
                .local_idx = (uint8_t)li,
            };
            if (ne_frame_alloc(&fwd->pair, &clone.addr) != 0)
                return -1;
            memcpy(ne_packet_data(&fwd->pair, clone.addr), pkt, job->len);
            if (ne_ring_try_push(ring, &clone) != 0) {
                ne_frame_free(&fwd->pair, clone.addr);
                return -1;
            }
        }
        if (li < (int)(sizeof(sent_mask) * 8))
            sent_mask |= (1u << li);
    }
    return sent > 0 ? 0 : -1;
}

static int wan_profile_pi_bypass(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int best_pi = -1;
    int best_pri = 0x7fffffff;
    int best_id = 0x7fffffff;

    if (!fwd || !pkt || !fwd->cfg)
        return -1;
    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0)
        return -1;

    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        const struct profile_config *prof = &fwd->cfg->profiles[pi];
        const struct crypto_policy *cp;

        if (!prof->enabled)
            continue;
        cp = config_select_crypto_policy(fwd->cfg, pi, src_ip, dst_ip,
                                         src_port, dst_port, proto);
        if (!cp || cp->action != POLICY_ACTION_BYPASS)
            continue;
        if (best_pi < 0 || cp->priority < best_pri ||
            (cp->priority == best_pri && cp->id < best_id)) {
            best_pi = pi;
            best_pri = cp->priority;
            best_id = cp->id;
        }
    }
    return best_pi;
}

static int wan_profile_pi(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint8_t pol = 0;

    if (!fwd || !pkt || !fwd->cfg)
        return -1;
    if (fwd_crypto_has_l2_marker(pkt, len)) {
        uint8_t wire_pol = 0;

        if (crypto_layer2_read_policy_id(pkt, len, &wire_pol) != 0)
            return -1;
        return profile_pi_for_wire_policy(fwd, wire_pol);
    }
    if (crypto_l3_extract_policy_id(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return profile_pi_for_wire_policy(fwd, pol);
    if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return profile_pi_for_wire_policy(fwd, pol);
    return wan_profile_pi_bypass(fwd, pkt, len);
}

static int forward_wan_to_local(struct forwarder *fwd, struct ne_packet *job,
                                const uint8_t *wire_pkt, uint32_t wire_len)
{
    uint8_t *pkt;
    int profile_pi;
    int li;

    if (!fwd || !job || !wire_pkt || wire_len < 14u)
        return -1;
    pkt = ne_packet_data(&fwd->pair, job->addr);
    if (!pkt || job->len < 14u)
        return -1;
    if (!eth_dmac_is_unicast(pkt))
        return -1;

    profile_pi = wan_profile_pi(fwd, wire_pkt, wire_len);
    if (profile_pi < 0)
        return -1;

    li = mac_lookup(fwd, pkt);
    if (li >= 0 && profile_owns_local(fwd->cfg, profile_pi, li)) {
        job->dir = NE_DIR_LOCAL;
        job->local_idx = (uint8_t)li;
        return dp_ring_push(fwd, &fwd->mid_to_local[li][dp_crypto_current_worker_idx()], job);
    }

    return flood_to_profile_locals(fwd, job, pkt, profile_pi);
}

void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint8_t wire_buf[NE_FRAME];
    uint32_t wire_len;
    int dec;

    if (!fwd || !pkt)
        goto drop;

    wire_len = job.len;
    if (wire_len < 14u || wire_len > NE_FRAME)
        goto drop;
    memcpy(wire_buf, pkt, wire_len);

    if (!wan_has_crypto(fwd, pkt, job.len))
        goto drop;

    dec = decrypt_wan(fwd, &job);
    if (dec == 1) {
        ne_frame_free(&fwd->pair, job.addr);
        return;
    }
    if (dec != 0)
        goto drop;

    if (forward_wan_to_local(fwd, &job, wire_buf, wire_len) != 0)
        goto drop;
    ne_dp_stats_wan_fwd(1);
    return;

drop:
    ne_dp_stats_wan_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
}