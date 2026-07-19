#include "../../../inc/core/dataplane.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"

#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/packet_crypto.h"

#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/dataplane_stats.h"

#include <netinet/in.h>
#include <string.h>

static int wan_l2_plain_ipv4(const uint8_t *pkt, uint32_t len)
{
    return crypto_pkt_is_ipv4(pkt, len);
}

static int wire_action_for_layer(crypto_wire_layer layer)
{
    if (layer == CRYPTO_WIRE_L2)
        return POLICY_ACTION_ENCRYPT_L2;
    if (layer == CRYPTO_WIRE_L3)
        return POLICY_ACTION_ENCRYPT_L3;
    if (layer == CRYPTO_WIRE_L4)
        return POLICY_ACTION_ENCRYPT_L4;
    return POLICY_ACTION_BYPASS;
}

static int wire_resolve_opt(crypto_wire_layer layer, uint8_t policy_id,
                            crypto_option_id *opt_out, struct packet_crypto_ctx **ctx_out)
{
    const struct crypto_policy *cp;
    struct packet_crypto_ctx *ctx;
    int want = wire_action_for_layer(layer);

    if (!opt_out || !ctx_out || want == POLICY_ACTION_BYPASS)
        return -1;
    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    cp = fwd_crypto_policy_for_wire_id(policy_id);
    if (!cp || cp->action != want)
        return -1;
    *ctx_out = ctx;
    *opt_out = crypto_option_from_policy(cp);
    return 0;
}

static int reassemble_layer(crypto_wire_layer layer,
                            uint8_t policy_id, uint8_t *pkt, uint32_t *len, int *pending)
{
    struct packet_crypto_ctx *ctx;
    crypto_option_id opt;
    int slot, rr;
    uint8_t buf[4096];
    uint32_t blen = 0;

    if (wire_resolve_opt(layer, policy_id, &opt, &ctx) != 0)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    rr = crypto_option_reassemble(opt, CRYPTO_PROTO_UDP, slot, dp_crypto_current_worker_idx(),
                                  ctx, pkt, len, buf, &blen);
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

static int decrypt_wan_l2(struct forwarder *fwd, struct ne_packet *job,
                          const struct crypto_wire_info *wi)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t len = job->len;
    struct packet_crypto_ctx *ctx;
    crypto_option_id opt;
    uint8_t backup[NE_FRAME];
    uint32_t backup_len;
    int pending = 0;
    int maybe_frag = 0;
    int frag_off;

    (void)fwd;
    if (!pkt || len > NE_FRAME)
        return -1;
    if (wire_resolve_opt(CRYPTO_WIRE_L2, wi->policy_id, &opt, &ctx) != 0)
        return -1;

    frag_off = crypto_eth_l2_frag_magic_off(pkt, len, PACKET_CRYPTO_NONCE_BYTES);
    if (frag_off >= 0 && len > (uint32_t)frag_off &&
        pkt[frag_off] == L2_FRAG_MAGIC)
        maybe_frag = 1;

    backup_len = len;
    if (maybe_frag)
        memcpy(backup, pkt, backup_len);

    /* Decrypt-first: L2 frag magic overlaps ciphertext — never trust is_frag. */
    if (crypto_option_decrypt(opt, CRYPTO_PROTO_TCP, ctx, pkt, &len) == 0 &&
        wan_l2_plain_ipv4(pkt, len)) {
        job->len = len;
        return 0;
    }

    if (!maybe_frag)
        return -1;

    memcpy(pkt, backup, backup_len);
    len = backup_len;

    if (reassemble_layer(CRYPTO_WIRE_L2, wi->policy_id, pkt, &len, &pending) == 0) {
        if (pending)
            return 1;
        job->len = len;
        return 0;
    }

    memcpy(pkt, backup, backup_len);
    job->len = backup_len;
    return -1;
}

static int decrypt_wan(struct forwarder *fwd, struct ne_packet *job,
                       const struct crypto_wire_info *wi_in)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t len = job->len;
    struct crypto_wire_info wi;
    struct packet_crypto_ctx *ctx;
    crypto_option_id opt;
    crypto_proto_class pclass;
    int pending = 0;
    int l3_off;
    uint8_t ip_proto;

    if (!fwd || !pkt || !job)
        return -1;
    if (wi_in) {
        wi = *wi_in;
    } else if (crypto_wire_detach(pkt, len, &wi) != 0 || wi.layer == CRYPTO_WIRE_NONE) {
        return 0;
    }
    if (!fwd->cfg->crypto_enabled) {
        job->len = len;
        return 0;
    }

    if (wi.layer == CRYPTO_WIRE_L2)
        return decrypt_wan_l2(fwd, job, &wi);

    if (wi.is_frag) {
        if (reassemble_layer(wi.layer, wi.policy_id, pkt, &len, &pending) == 0) {
            if (pending)
                return 1;
            job->len = len;
            return 0;
        }
        return -1;
    }

    if (wire_resolve_opt(wi.layer, wi.policy_id, &opt, &ctx) != 0)
        return -1;

    /* L2/L3 share one wire shape (fake et / fake proto) → TCP ops.
     * L4 keeps real IP proto (6/17/1) → must pick matching ops. */
    pclass = CRYPTO_PROTO_TCP;
    if (wi.layer == CRYPTO_WIRE_L4) {
        l3_off = crypto_eth_ipv4_offset(pkt, len);
        if (l3_off < 0 || len < (uint32_t)(l3_off + 10))
            return -1;
        ip_proto = pkt[l3_off + 9];
        pclass = crypto_proto_classify(ip_proto);
        if (pclass == CRYPTO_PROTO_OTHER)
            return -1;
    }

    if (crypto_option_decrypt(opt, pclass, ctx, pkt, &len) != 0)
        return -1;

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

static int wan_tcp_is_syn(const uint8_t *pkt, uint32_t len)
{
    int l3_off;
    const uint8_t *ip;
    uint32_t ihl;

    l3_off = crypto_eth_ipv4_offset(pkt, len);
    if (l3_off < 0)
        return 0;
    if (len < (uint32_t)(l3_off + 20))
        return 0;
    ip = pkt + l3_off;
    if ((ip[0] & 0xF0) != 0x40 || ip[9] != IPPROTO_TCP)
        return 0;
    ihl = (uint32_t)(ip[0] & 0x0F) * 4u;
    if (ihl < 20 || len < (uint32_t)(l3_off + ihl + 14))
        return 0;
    return (ip[ihl + 13] & 0x02) != 0;
}

static void wan_clamp_tcp_mss(struct forwarder *fwd, uint8_t *pkt, uint32_t len,
                              const struct crypto_wire_info *wi)
{
    const struct crypto_policy *best = NULL;
    crypto_option_id opt;

    if (!fwd || !pkt || !fwd->cfg)
        return;
    if (!wan_tcp_is_syn(pkt, len))
        return;

    if (wi && wi->layer != CRYPTO_WIRE_NONE) {
        best = fwd_crypto_policy_for_wire_id(wi->policy_id);
        if (!best || best->action == POLICY_ACTION_BYPASS)
            return;
        opt = crypto_option_from_policy(best);
        (void)crypto_tcp_clamp_mss(pkt, len, CRYPTO_OPT_FRAG_MTU_DEFAULT,
                                   crypto_option_wire_overhead(opt));
        return;
    }

    {
        uint32_t src_ip = 0, dst_ip = 0;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t proto = 0;
        int best_pri = 0x7fffffff;
        int best_id = 0x7fffffff;

        if (dp_parse_flow(pkt, len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) != 0)
            return;
        if (proto != IPPROTO_TCP)
            return;

        for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
            const struct profile_config *prof = &fwd->cfg->profiles[pi];
            const struct crypto_policy *cp;

            if (!prof->enabled)
                continue;
            cp = config_select_crypto_policy(fwd->cfg, pi, src_ip, dst_ip,
                                             src_port, dst_port, proto);
            if (!cp || cp->action == POLICY_ACTION_BYPASS)
                continue;
            if (!best || cp->priority < best_pri ||
                (cp->priority == best_pri && cp->id < best_id)) {
                best = cp;
                best_pri = cp->priority;
                best_id = cp->id;
            }
        }
        if (!best)
            return;
        (void)crypto_tcp_clamp_mss(pkt, len, CRYPTO_OPT_FRAG_MTU_DEFAULT,
                                   crypto_option_wire_overhead(crypto_option_from_policy(best)));
    }
}

static int forward_wan_to_local(struct forwarder *fwd, struct ne_packet *job,
                                const struct crypto_wire_info *wi)
{
    uint8_t *pkt;
    int profile_pi;
    int li;

    if (!fwd || !job)
        return -1;
    pkt = ne_packet_data(&fwd->pair, job->addr);
    if (!pkt || job->len < 14u)
        return -1;
    if (!eth_dmac_is_unicast(pkt))
        return -1;

    if (wi && wi->layer != CRYPTO_WIRE_NONE)
        profile_pi = profile_pi_for_wire_policy(fwd, wi->policy_id);
    else
        profile_pi = wan_profile_pi_bypass(fwd, pkt, job->len);
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

static int wire_policy_matches_layer(crypto_wire_layer layer, uint8_t policy_id)
{
    const struct crypto_policy *cp = fwd_crypto_policy_for_wire_id(policy_id);

    if (!cp)
        return 0;
    if (layer == CRYPTO_WIRE_L2)
        return cp->action == POLICY_ACTION_ENCRYPT_L2;
    if (layer == CRYPTO_WIRE_L3)
        return cp->action == POLICY_ACTION_ENCRYPT_L3;
    if (layer == CRYPTO_WIRE_L4)
        return cp->action == POLICY_ACTION_ENCRYPT_L4;
    return 0;
}

void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    int dec;
    struct crypto_wire_info wi;
    int have_wire = 0;

    if (!fwd || !pkt)
        goto drop;

    if (job.len < 14u || job.len > NE_FRAME)
        goto drop;

    if (crypto_wire_detach(pkt, job.len, &wi) == 0 && wi.layer != CRYPTO_WIRE_NONE &&
        wire_policy_matches_layer(wi.layer, wi.policy_id)) {
        have_wire = 1;
        if (!fwd->cfg->crypto_enabled)
            goto drop;
        dec = decrypt_wan(fwd, &job, &wi);
        if (dec == 1) {
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec != 0)
            goto drop;
        wan_clamp_tcp_mss(fwd, pkt, job.len, &wi);
    } else {
        /* Plain / bypass, or L4 magic false-positive on TCP header. */
        wi.layer = CRYPTO_WIRE_NONE;
        wi.policy_id = 0;
        wi.is_frag = 0;
        if (!wan_l2_plain_ipv4(pkt, job.len))
            goto drop;
    }

    if (forward_wan_to_local(fwd, &job, have_wire ? &wi : NULL) != 0)
        goto drop;
    ne_dp_stats_wan_fwd(1);
    return;

drop:
    ne_dp_stats_wan_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
}
