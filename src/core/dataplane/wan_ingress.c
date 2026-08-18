#include "../../../inc/core/dataplane.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"

#include "../../../inc/crypto/eth_parse.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/packet_crypto.h"

#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/dataplane_stats.h"

#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <time.h>

/* L2 UDP fragment ONLY (need_split: pkt+35 > MTU 1500). Wire after nonce:
 *   [0x5B][pkt_id:2][frag_index:0|1][reserved:0][ciphertext...]
 * TCP / UDP that fits MTU never write this — that offset is ciphertext. */
#define WAN_L2_FRAG_MAGIC    0x5Bu
#define WAN_L2_FRAG_TAG_LEN  4u
#define WAN_DROP_LOG_INTERVAL_MS 3000ull

static uint64_t wan_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

static int wan_log_rl(uint64_t *last_ms)
{
    uint64_t now = wan_now_ms();

    if (!last_ms)
        return 0;
    if (*last_ms != 0 && now - *last_ms < WAN_DROP_LOG_INTERVAL_MS)
        return 0;
    *last_ms = now;
    return 1;
}

static const struct crypto_policy *fwd_policy_by_action_wire_id(struct forwarder *fwd, int action, uint8_t wire_id);

static uint8_t wan_first_l2_decrypt_logged[256];
static uint8_t wan_first_l3_decrypt_logged[256];
static uint8_t wan_first_l4_decrypt_logged[256];

static void wan_log_first_decrypt_ok(struct forwarder *fwd, int layer, uint8_t wire_id)
{
    uint8_t *mark = NULL;
    const struct crypto_policy *cp = NULL;

    if (layer == 2)
        mark = &wan_first_l2_decrypt_logged[wire_id];
    else if (layer == 3)
        mark = &wan_first_l3_decrypt_logged[wire_id];
    else if (layer == 4)
        mark = &wan_first_l4_decrypt_logged[wire_id];
    if (!mark || *mark)
        return;
    *mark = 1;

    if (layer == 2)
        cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L2, wire_id);
    else if (layer == 3)
        cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L3, wire_id);
    else if (layer == 4)
        cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L4, wire_id);
    fprintf(stderr,
            "[WAN-INGRESS] first-decrypt-ok layer=L%d wire_id=%u policy_db_id=%d mode=%d\n",
            layer, (unsigned)wire_id, cp ? cp->db_id : -1, cp ? cp->crypto_mode : -1);
}

static int wan_l2_is_udp_frag(const uint8_t *pkt, uint32_t len)
{
    int mark_off;
    uint8_t frag_index;
    uint8_t reserved;

    if (!pkt || !crypto_eth_l2_has_marker(pkt, len))
        return 0;
    mark_off = crypto_eth_l2_frag_magic_off(pkt, len, PACKET_CRYPTO_NONCE_BYTES);
    if (mark_off < 0)
        return 0;
    if (len < (uint32_t)mark_off + 1u + WAN_L2_FRAG_TAG_LEN)
        return 0;
    if (pkt[mark_off] != WAN_L2_FRAG_MAGIC)
        return 0;
    /* Same layout as opt_write_frag_tag / l2_udp_is_fragment */
    frag_index = pkt[mark_off + 3];
    reserved = pkt[mark_off + 4];
    return frag_index <= 1u && reserved == 0u;
}

static const struct crypto_policy *fwd_policy_by_action_wire_id(struct forwarder *fwd, int action, uint8_t wire_id)
{
    if (!fwd || !fwd->cfg)
        return NULL;
    for (int i = 0; i < fwd->cfg->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[i];
        if (cp->action == action && (uint8_t)cp->id == wire_id)
            return cp;
    }
    return NULL;
}


static int wan_l2_plain_ipv4(const uint8_t *pkt, uint32_t len)
{
    return crypto_pkt_is_ipv4(pkt, len);
}

static int wan_l2_plain_ok(const uint8_t *pkt, uint32_t len)
{
    return crypto_pkt_is_ipv4(pkt, len) || crypto_pkt_is_arp(pkt, len);
}

/* Encrypted NE wire: L2 marker / L3 fake-proto / L4 tunnel / frag — not plain bypass. */
static int wan_wire_is_encrypted(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t pol = 0;

    if (!pkt || !fwd || !fwd->cfg)
        return 0;
    if (fwd_crypto_has_l2_marker(pkt, len))
        return 1;
    if (crypto_option_is_any_fragment(fwd->cfg, pkt, len, &pid, &fidx))
        return 1;
    if (crypto_l3_extract_policy_id(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return 1;
    if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return 1;
    return 0;
}

static int decrypt_l2(struct forwarder *fwd, uint8_t *pkt, uint32_t *len)
{
    struct packet_crypto_ctx *ctx;
    const struct crypto_policy *cp;
    crypto_option_id opt;
    uint8_t wire_id = 0;
    uint8_t scratch[NE_FRAME];
    uint32_t orig_len;

    if (!pkt || !len)
        return 0;
    if (!crypto_eth_l2_has_marker(pkt, *len))
        return 0;
    if (crypto_eth_l2_read_policy_id(pkt, *len, &wire_id) != 0)
        return 0;
    ctx = fwd_crypto_ctx_for_wire_id(wire_id);
    if (!ctx) {
        static uint64_t last_missing_ctx_ms;
        if (wan_log_rl(&last_missing_ctx_ms))
            fprintf(stderr, "[WAN-INGRESS] drop missing-ctx layer=L2 wire_id=%u\n", (unsigned)wire_id);
        return -1;
    }
    cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L2, wire_id);
    opt = cp ? crypto_option_from_policy(cp) : CRYPTO_OPT_L2_GCM128;

    orig_len = *len;
    if (orig_len > NE_FRAME)
        return -1;
    memcpy(scratch, pkt, orig_len);

    if (crypto_option_decrypt(opt, CRYPTO_PROTO_TCP, ctx, pkt, len) == 0 &&
        crypto_pkt_is_ipv4(pkt, *len)) {
        wan_log_first_decrypt_ok(fwd, 2, wire_id);
        return 0;
    }

    memcpy(pkt, scratch, orig_len);
    *len = orig_len;
    {
        static uint64_t last_l2_dec_fail_ms;
        if (wan_log_rl(&last_l2_dec_fail_ms))
            fprintf(stderr, "[WAN-INGRESS] drop decrypt-fail layer=L2 wire_id=%u\n", (unsigned)wire_id);
    }
    return -1;
}

static int reassemble_l2(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, uint64_t addr, int *pending)
{
    struct packet_crypto_ctx *ctx;
    const struct crypto_policy *cp;
    crypto_option_id opt;
    int slot, rr;
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L2, policy_id);
    opt = cp ? crypto_option_from_policy(cp) : CRYPTO_OPT_L2_GCM128;
    crypto_l2_pqc_reasm_set_addr(addr);
    rr = crypto_option_reassemble(opt, CRYPTO_PROTO_UDP, slot, dp_crypto_current_worker_idx(),
                                  ctx, pkt, len, pkt, &blen);
    if (rr == 0) {
        *pending = crypto_l2_pqc_reasm_held() ? 2 : 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    *len = blen;
    return 0;
}

/*
 * 0x5B = UDP mảnh (vượt MTU). Không có 0x5B = gói đủ → decrypt bình thường.
 * Không drop ở đây. Ráp không được (ciphertext trùng 0x5B) cũng trả 0 cho decrypt_l2.
 */
static int wan_try_l2_pqc_frag(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                               uint64_t addr, int *pending)
{
    const struct crypto_policy *cp;
    uint8_t wire_pol = 0;
    uint8_t scratch[NE_FRAME];
    uint32_t orig_len;

    if (!wan_l2_is_udp_frag(pkt, *len))
        return 0;

    if (crypto_eth_l2_read_policy_id(pkt, *len, &wire_pol) != 0)
        return 0;

    cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L2, wire_pol);
    if (!cp || cp->crypto_mode != CRYPTO_MODE_PQC)
        return 0;

    if (!fwd_crypto_ctx_for_wire_id(wire_pol))
        return 0;

    orig_len = *len;
    if (orig_len > NE_FRAME)
        return 0;
    memcpy(scratch, pkt, orig_len);
    if (reassemble_l2(fwd, pkt, len, wire_pol, addr, pending) != 0) {
        memcpy(pkt, scratch, orig_len);
        *len = orig_len;
        if (pending)
            *pending = 0;
        return 0;
    }
    return 1;
}

/* L2 UDP fragment on wire: profile lookup only needs L2 header + policy_id. */
static int wan_l2_is_frag(const uint8_t *pkt, uint32_t len)
{
    return wan_l2_is_udp_frag(pkt, len);
}

static int reassemble_l3(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    const struct crypto_policy *cp;
    crypto_option_id opt;
    int slot, rr;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L3, policy_id);
    opt = cp ? crypto_option_from_policy(cp) : CRYPTO_OPT_L3_GCM128;
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

static int reassemble_l4(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    const struct crypto_policy *cp;
    crypto_option_id opt;
    int slot, rr;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_wire_id(policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_wire_id(policy_id));
    if (slot < 0)
        return -1;
    cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L4, policy_id);
    opt = cp ? crypto_option_from_policy(cp) : CRYPTO_OPT_L4_GCM128;
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

static int decrypt_wan(struct forwarder *fwd, struct ne_packet *job)
{
    uint8_t scratch[8192];
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t len = job->len;
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t pol = 0;
    int pending = 0;

    if (!fwd || !pkt || !job)
        return -1;
    /* Caller must only invoke this for encrypted wire; plain bypass never enters. */
    if (!wan_wire_is_encrypted(fwd, pkt, len))
        return 0;

    {
        int l2_fast = wan_try_l2_pqc_frag(fwd, pkt, &len, job->addr, &pending);

        if (l2_fast < 0)
            return -1;
        if (l2_fast == 1) {
            uint64_t out_addr;

            if (pending == 2)
                return 2;
            if (pending)
                return 1;
            out_addr = crypto_l2_pqc_reasm_out_addr();
            if (out_addr && out_addr != job->addr) {
                ne_frame_free(&fwd->pair, job->addr);
                job->addr = out_addr;
            }
            job->len = len;
            return 0;
        }
        if (l2_fast == 0) {
            uint32_t orig_len = len;
            uint8_t wire_pol = 0;
            int need_backup = wan_l2_is_udp_frag(pkt, len) ||
                crypto_option_is_fragment(CRYPTO_OPT_L2_CTR128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                crypto_option_is_fragment(CRYPTO_OPT_L2_CTR256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                crypto_option_is_fragment(CRYPTO_OPT_L2_GCM128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                crypto_option_is_fragment(CRYPTO_OPT_L2_GCM256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                crypto_option_is_fragment(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx);
            if (need_backup && orig_len <= sizeof(scratch))
                memcpy(scratch, pkt, orig_len);
            if (decrypt_l2(fwd, pkt, &len) != 0 || !wan_l2_plain_ok(pkt, len)) {
                if (need_backup)
                    memcpy(pkt, scratch, orig_len);
                len = orig_len;
                if (crypto_option_is_fragment(CRYPTO_OPT_L2_CTR128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                    crypto_option_is_fragment(CRYPTO_OPT_L2_CTR256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                    crypto_option_is_fragment(CRYPTO_OPT_L2_GCM128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                    crypto_option_is_fragment(CRYPTO_OPT_L2_GCM256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
                    crypto_option_is_fragment(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx)) {
                    if (crypto_eth_l2_read_policy_id(pkt, len, &wire_pol) != 0)
                        return -1;
                    if (reassemble_l2(fwd, pkt, &len, wire_pol, job->addr, &pending) != 0)
                        return -1;
                } else {
                    return -1;
                }
            }
        }
    }
    if (pending == 2)
        return 2;
    if (pending)
        return 1;

    if (!fwd->cfg->crypto_enabled) {
        job->len = len;
        return 0;
    }

    if (crypto_option_is_fragment(CRYPTO_OPT_L3_CTR128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L3_CTR256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L3_GCM128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L3_GCM256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L3_PQC, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx)) {
        if (crypto_l3_extract_policy_id(fwd->cfg, pkt, len, &pol) != 0)
            return -1;
        if (reassemble_l3(fwd, pkt, &len, pol, &pending) != 0)
            return -1;
    } else if (crypto_l3_extract_policy_id(fwd->cfg, pkt, len, &pol) == 0) {
        const struct crypto_policy *cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L3, pol);
        struct packet_crypto_ctx *ctx = fwd_crypto_ctx_for_wire_id(pol);
        crypto_option_id opt = cp ? crypto_option_from_policy(cp) : CRYPTO_OPT_L3_GCM128;
        if (!ctx) {
            static uint64_t last_l3_missing_ctx_ms;
            if (wan_log_rl(&last_l3_missing_ctx_ms))
                fprintf(stderr, "[WAN-INGRESS] drop missing-ctx layer=L3 wire_id=%u\n", (unsigned)pol);
            return -1;
        }
        if (crypto_option_decrypt(opt, CRYPTO_PROTO_TCP, ctx, pkt, &len) != 0) {
            static uint64_t last_l3_dec_fail_ms;
            if (wan_log_rl(&last_l3_dec_fail_ms))
                fprintf(stderr, "[WAN-INGRESS] drop decrypt-fail layer=L3 wire_id=%u\n", (unsigned)pol);
            return -1;
        }
        wan_log_first_decrypt_ok(fwd, 3, pol);
    }
    if (pending)
        return 1;

    if (crypto_option_is_fragment(CRYPTO_OPT_L4_CTR128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L4_CTR256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L4_GCM128, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L4_GCM256, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx) ||
        crypto_option_is_fragment(CRYPTO_OPT_L4_PQC, CRYPTO_PROTO_UDP, fwd->cfg, pkt, len, &pid, &fidx)) {
        if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, pkt, len, &pol) != 0)
            return -1;
        if (reassemble_l4(fwd, pkt, &len, pol, &pending) != 0)
            return -1;
    } else if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, pkt, len, &pol) == 0) {
        const struct crypto_policy *cp = fwd_policy_by_action_wire_id(fwd, POLICY_ACTION_ENCRYPT_L4, pol);
        struct packet_crypto_ctx *ctx = fwd_crypto_ctx_for_wire_id(pol);
        crypto_option_id opt = cp ? crypto_option_from_policy(cp) : CRYPTO_OPT_L4_GCM128;
        if (!ctx) {
            static uint64_t last_l4_missing_ctx_ms;
            if (wan_log_rl(&last_l4_missing_ctx_ms))
                fprintf(stderr, "[WAN-INGRESS] drop missing-ctx layer=L4 wire_id=%u\n", (unsigned)pol);
            return -1;
        }
        if (crypto_option_decrypt(opt, CRYPTO_PROTO_TCP, ctx, pkt, &len) != 0) {
            static uint64_t last_l4_dec_fail_ms;
            if (wan_log_rl(&last_l4_dec_fail_ms))
                fprintf(stderr, "[WAN-INGRESS] drop decrypt-fail layer=L4 wire_id=%u\n", (unsigned)pol);
            return -1;
        }
        wan_log_first_decrypt_ok(fwd, 4, pol);
    }
    if (pending)
        return 1;

    {
        uint64_t out_addr = crypto_l2_pqc_reasm_out_addr();

        if (out_addr && out_addr != job->addr) {
            ne_frame_free(&fwd->pair, job->addr);
            job->addr = out_addr;
        }
    }
    job->len = len;
    return 0;
}

static int eth_dmac_is_unicast(const uint8_t *pkt)
{
    return (pkt[0] & 0x01u) == 0;
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

static int profile_owns_local(struct forwarder *fwd, int profile_pi, int fwd_local_idx)
{
    const struct profile_config *prof;
    const char *ifname;

    if (!fwd || !fwd->cfg || profile_pi < 0 || profile_pi >= fwd->cfg->profile_count)
        return 0;
    if (fwd_local_idx < 0 || fwd_local_idx >= fwd->local_count)
        return 0;
    if (!ne_pair_local_live(&fwd->pair, fwd_local_idx))
        return 0;

    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled)
        return 0;

    ifname = fwd->locals[fwd_local_idx].ifname;
    if (!ifname[0])
        return 0;

    for (int i = 0; i < prof->local_count; i++) {
        int ci = prof->local_indices[i];

        if (ci < 0 || ci >= fwd->cfg->local_count)
            continue;
        if (strcmp(fwd->cfg->locals[ci].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

/* Data path only (tcp/udp/icmp/ospf): never floods — FDB miss drops. */

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

static void wan_clamp_tcp_mss(struct forwarder *fwd, uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    const struct crypto_policy *best = NULL;
    int best_pri = 0x7fffffff;
    int best_id = 0x7fffffff;

    if (!fwd || !pkt || !fwd->cfg)
        return;
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

static int wan_profile_pi(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint8_t pol = 0;

    if (!fwd || !pkt || !fwd->cfg)
        return -1;
    if (fwd_crypto_has_l2_marker(pkt, len)) {
        uint8_t wire_pol = 0;

        if (crypto_eth_l2_read_policy_id(pkt, len, &wire_pol) != 0)
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
                                const uint8_t *wire_pkt, uint32_t wire_len,
                                int ingress_wan_dp)
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
    if (li < 0 || !profile_owns_local(fwd, profile_pi, li)) {
        if (ingress_wan_dp >= 0)
            li = mac_fwd_local_for_wan_dp(fwd, profile_pi, ingress_wan_dp);
    }
    if (li >= 0 && profile_owns_local(fwd, profile_pi, li)) {
        job->dir = NE_DIR_LOCAL;
        job->local_idx = (uint8_t)li;
        return dp_ring_push(fwd, &fwd->mid_to_local[li][dp_crypto_current_worker_idx()], job);
    }

    return -1;
}

void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint8_t wire_buf[NE_FRAME];
    uint32_t wire_len;
    int dec;
    int encrypted;

    if (!fwd || !pkt)
        goto drop;

    wire_len = job.len;
    if (wire_len < 14u || wire_len > NE_FRAME)
        goto drop;
    /* L2 frag pending is freed after decrypt; snapshot header only (policy_id). */
    if (wan_l2_is_frag(pkt, wire_len)) {
        uint32_t snap = wire_len < 64u ? wire_len : 64u;

        memcpy(wire_buf, pkt, snap);
        wire_len = snap;
    } else {
        memcpy(wire_buf, pkt, wire_len);
    }

    if (crypto_eth_l2_has_arp_marker(pkt, job.len) || dp_pkt_is_arp(pkt, job.len)) {
        int wan_dp = job.wan_idx < fwd->wan_count ? (int)job.wan_idx : -1;
        int bridged = -1;

        if (wan_dp >= 0)
            bridged = arp_bridge_from_wan(fwd, &job, pkt, wan_dp, NULL);

        if (bridged == 0)
            return;
        goto drop;
    }

    encrypted = wan_wire_is_encrypted(fwd, pkt, job.len);
    if (encrypted) {
        if (!fwd->cfg->crypto_enabled) {
            static uint64_t last_crypto_off_ms;
            if (wan_log_rl(&last_crypto_off_ms))
                fprintf(stderr, "[WAN-INGRESS] drop encrypted-wire while crypto-disabled\n");
            goto drop;
        }
        dec = decrypt_wan(fwd, &job);
        if (dec == 1) {
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec == 2)
            return;
        if (dec != 0) {
            static uint64_t last_decrypt_fail_ms;
            if (wan_log_rl(&last_decrypt_fail_ms))
                fprintf(stderr, "[WAN-INGRESS] drop decrypt-fail on encrypted wire\n");
            goto drop;
        }
        pkt = ne_packet_data(&fwd->pair, job.addr);
        wan_clamp_tcp_mss(fwd, pkt, job.len);
    } else {

        if (!wan_l2_plain_ipv4(pkt, job.len)) {
            static uint64_t last_plain_reject_ms;
            if (wan_log_rl(&last_plain_reject_ms))
                fprintf(stderr, "[WAN-INGRESS] drop plain-non-ipv4 frame\n");
            goto drop;
        }
    }

    if (forward_wan_to_local(fwd, &job, wire_buf, wire_len,
                             job.wan_idx < fwd->wan_count ? (int)job.wan_idx : -1) != 0) {
        static uint64_t last_no_route_ms;
        if (wan_log_rl(&last_no_route_ms))
            fprintf(stderr, "[WAN-INGRESS] drop no-local-route/fdb-miss/profile-miss\n");
        goto drop;
    }
    ne_dp_stats_wan_fwd(1);
    return;

drop:
    ne_dp_stats_wan_drop(1);
    ne_frame_free(&fwd->pair, job.addr);
}