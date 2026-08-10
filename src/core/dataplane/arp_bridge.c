#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/wan_failover.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <net/if.h>

#define ARP_LOG_FAIL_INTERVAL_MS 30000ull
#define ARP_DEFAULT_WIRE_ID      250u
#define ARP_DEFAULT_AES_BITS     256
#define ARP_ETH_HDR_LEN          14u

/* 1 = mã hóa ARP L2-PQC (key/option riêng), 0 = bridge ARP plaintext.
 * Decrypt vẫn chạy nếu wire có ARP marker (peer vẫn encrypt). */
#ifndef ARP_ENCRYPT_ENABLE
#define ARP_ENCRYPT_ENABLE 1
#endif

static struct packet_crypto_ctx g_arp_crypto_ctx;
static int g_arp_crypto_ctx_ready;
static int g_arp_key_loaded;
static uint8_t g_arp_default_master_key[AES_MAX_KEY_SIZE];

/* 32-byte ARP master key: paste 64 hex chars (0-9a-f). Both peers must match. */
static const char g_arp_hardcoded_master_key_hex[] =
    "73214a9ce15d2fb816c73b90ad44f26e580da137cb7f2495ee6318d489ba05cf";

static uint64_t arp_monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

static void arp_crypto_ctx_init(const struct app_config *cfg)
{
    if (!cfg || !cfg->crypto_enabled)
        return;
    if (!g_arp_key_loaded) {
        if (parse_hex_bytes_pub(g_arp_hardcoded_master_key_hex,
                                g_arp_default_master_key, AES_MAX_KEY_SIZE) != 0) {
            fprintf(stderr,
                    "[ARP] bad key hex (need %d hex chars, got %zu): %s\n",
                    AES_MAX_KEY_SIZE * 2,
                    strlen(g_arp_hardcoded_master_key_hex),
                    g_arp_hardcoded_master_key_hex);
            return;
        }
        g_arp_key_loaded = 1;
    }
    if (g_arp_crypto_ctx_ready)
        return;
    if (packet_crypto_init(&g_arp_crypto_ctx, g_arp_default_master_key,
                           ARP_DEFAULT_AES_BITS) != 0)
        return;
    g_arp_crypto_ctx.initialized = true;
    g_arp_crypto_ctx.crypto_mode = CRYPTO_MODE_PQC;
    g_arp_crypto_ctx.wire_id = (uint8_t)ARP_DEFAULT_WIRE_ID;
    g_arp_crypto_ctx.policy_id = 0;
    g_arp_crypto_ctx.profile_id = 0;
    g_arp_crypto_ctx_ready = 1;
}

static int arp_log_fail_ratelimit(uint64_t *last_ms)
{
    uint64_t now = arp_monotonic_ms();

    if (!last_ms || now - *last_ms < ARP_LOG_FAIL_INTERVAL_MS)
        return 0;
    *last_ms = now;
    return 1;
}

/* Backup path: always log — không rate-limit (debug failover ARP). */
static void arp_log_backup_line(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

static void arp_format_ipv4_be32(uint32_t ip_be, char *buf, size_t bufsz)
{
    uint8_t b[4];

    memcpy(b, &ip_be, 4);
    snprintf(buf, bufsz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void arp_format_mac(const uint8_t mac[MAC_LEN], char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int arp_eth_dmac_is_broadcast(const uint8_t *pkt, uint32_t len)
{
    static const uint8_t bcast[MAC_LEN] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    if (!pkt || len < ARP_ETH_HDR_LEN)
        return 0;
    return memcmp(pkt, bcast, MAC_LEN) == 0;
}

static int arp_eth_dmac_is_multicast(const uint8_t *pkt, uint32_t len)
{
    if (!pkt || len < ARP_ETH_HDR_LEN)
        return 0;
    return (pkt[0] & 0x01u) != 0;
}

void arp_bridge_reload_policies(struct app_config *cfg)
{
    if (!cfg)
        return;
    arp_crypto_ctx_init(cfg);
    fprintf(stderr,
            "[ARP] mode=mac-fdb+flood-bcast | arp_encrypt=%d | key=arp-default | opt=L2-PQC/ARP\n",
            ARP_ENCRYPT_ENABLE);
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

static int arp_wan_dp_usable(int wan_dp)
{
    if (wan_dp < 0)
        return 0;
    return fwd_wan_dp_ok_for_new_traffic(wan_dp) ? 1 : 0;
}

static int arp_wan_is_bridge_peer(const struct profile_config *prof, int wan_dp)
{
    if (!prof || wan_dp < 0)
        return 0;
    for (int i = 0; i < prof->bridge_count; i++) {
        if (prof->bridges[i].wan_dp == wan_dp)
            return 1;
    }
    return 0;
}

/* Prefer other UP bridge WANs; else least-loaded live WAN in profile pool. */
static int arp_pick_backup_wan_dp(struct forwarder *fwd,
                                  const struct profile_config *prof,
                                  int primary_wan_dp)
{
    int best_bridge = -1;
    uint32_t best_bridge_depth = UINT32_MAX;
    int best_any = -1;
    uint32_t best_any_depth = UINT32_MAX;

    if (!fwd || !prof)
        return -1;

    for (int i = 0; i < prof->wan_count; i++) {
        int cfg_wan = prof->wan_indices[i];
        int dp;
        uint32_t depth;

        dp = fwd_wan_live_dp_for_cfg(fwd, cfg_wan);
        if (dp < 0)
            dp = fwd_wan_dp_for_legacy_cfg(fwd, cfg_wan);
        if (dp < 0 || dp == primary_wan_dp)
            continue;
        if (!arp_wan_dp_usable(dp) || !fwd_wan_has_tx_room(fwd, dp))
            continue;

        depth = fwd_mid_to_wan_depth(fwd, dp);
        if (arp_wan_is_bridge_peer(prof, dp)) {
            if (depth < best_bridge_depth) {
                best_bridge_depth = depth;
                best_bridge = dp;
            }
        } else if (depth < best_any_depth) {
            best_any_depth = depth;
            best_any = dp;
        }
    }

    return best_bridge >= 0 ? best_bridge : best_any;
}

static int arp_select_egress_wan(struct forwarder *fwd,
                                 const struct profile_config *prof,
                                 int primary_wan_dp, int *used_backup)
{
    if (used_backup)
        *used_backup = 0;

    if (arp_wan_dp_usable(primary_wan_dp) && !fwd_wan_is_stopped(primary_wan_dp))
        return primary_wan_dp;

    if (!wan_failover_enabled())
        return -1;

    {
        int backup = arp_pick_backup_wan_dp(fwd, prof, primary_wan_dp);

        if (backup < 0)
            return -1;
        if (used_backup)
            *used_backup = 1;
        return backup;
    }
}

static int arp_profile_owns_local(struct forwarder *fwd, int profile_pi, int fwd_local_idx)
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

/* who-has (ffff) or unicast FDB miss: clone to every live LAN in the profile.
 * lans_out: optional "lan1,lan2,..." of interfaces that actually got a copy. */
static int arp_flood_to_profile_locals(struct forwarder *fwd, struct ne_packet *job,
                                       const uint8_t *pkt, int profile_pi,
                                       char *lans_out, size_t lans_out_sz)
{
    const struct profile_config *prof;
    int wi;
    int sent = 0;
    uint16_t sent_mask = 0;
    size_t lans_len = 0;

    if (lans_out && lans_out_sz > 0)
        lans_out[0] = '\0';

    if (!fwd || !job || !pkt || !fwd->cfg || profile_pi < 0 ||
        profile_pi >= fwd->cfg->profile_count)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled || prof->local_count <= 0)
        return -1;

    wi = dp_crypto_current_worker_idx();

    for (int i = 0; i < prof->local_count; i++) {
        int li = mac_fwd_local_for_cfg_idx(fwd, prof->local_indices[i]);
        struct ne_ring *ring;
        const char *lif;

        if (li < 0 || li >= fwd->local_count)
            continue;
        if (li < (int)(sizeof(sent_mask) * 8) && (sent_mask & (1u << li)) != 0)
            continue;

        ring = &fwd->mid_to_local[li][wi];
        lif = fwd->locals[li].ifname[0] ? fwd->locals[li].ifname : "?";

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
                break;
            memcpy(ne_packet_data(&fwd->pair, clone.addr), pkt, job->len);
            if (ne_ring_try_push(ring, &clone) != 0) {
                ne_frame_free(&fwd->pair, clone.addr);
                break;
            }
        }
        if (li < (int)(sizeof(sent_mask) * 8))
            sent_mask |= (1u << li);

        if (lans_out && lans_out_sz > 1) {
            int n = snprintf(lans_out + lans_len, lans_out_sz - lans_len,
                             "%s%s", lans_len ? "," : "", lif);
            if (n < 0 || (size_t)n >= lans_out_sz - lans_len)
                lans_len = lans_out_sz - 1;
            else
                lans_len += (size_t)n;
        }
    }
    return sent > 0 ? 0 : -1;
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

/* BR name for LAN (fwd local) in profile; "-" if not in a bridge pair. */
static const char *arp_br_name_for_lan(struct forwarder *fwd,
                                       const struct profile_config *prof,
                                       int fwd_local_idx)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || !prof || fwd_local_idx < 0 ||
        fwd_local_idx >= fwd->local_count)
        return "-";
    ifname = fwd->locals[fwd_local_idx].ifname;
    if (!ifname[0])
        return "-";

    for (int i = 0; i < prof->bridge_count; i++) {
        int ci = prof->bridges[i].local_idx;

        if (ci < 0 || ci >= fwd->cfg->local_count)
            continue;
        if (strcmp(fwd->cfg->locals[ci].ifname, ifname) != 0)
            continue;
        if (prof->bridges[i].ifname[0])
            return prof->bridges[i].ifname;
        return "(unnamed)";
    }
    return "-";
}

/* BR name for WAN dp in profile. */
static const char *arp_br_name_for_wan(const struct profile_config *prof, int wan_dp)
{
    if (!prof || wan_dp < 0)
        return "-";
    for (int i = 0; i < prof->bridge_count; i++) {
        if (prof->bridges[i].wan_dp != wan_dp)
            continue;
        if (prof->bridges[i].ifname[0])
            return prof->bridges[i].ifname;
        return "(unnamed)";
    }
    return "-";
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

/* Returns 1 if encrypted, 0 if plaintext. Never blocks ARP forwarding. */
static int arp_try_encrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job,
                                  uint8_t *pkt, int profile_idx,
                                  const char **skip_why)
{
    uint8_t scratch[NE_FRAME];
    uint32_t orig_len;
    uint32_t len;

    if (skip_why)
        *skip_why = NULL;

    if (!fwd || !fwd->cfg || !job || !pkt) {
        if (skip_why)
            *skip_why = "bad-args";
        return 0;
    }
    if (!ARP_ENCRYPT_ENABLE) {
        if (skip_why)
            *skip_why = "arp-encrypt-disabled";
        return 0;
    }
    if (!fwd->cfg->crypto_enabled) {
        if (skip_why)
            *skip_why = "crypto-disabled";
        return 0;
    }
    arp_crypto_ctx_init(fwd->cfg);
    if (!g_arp_crypto_ctx_ready) {
        if (skip_why)
            *skip_why = "arp-crypto-not-ready";
        return 0;
    }

    orig_len = job->len;
    if (orig_len > NE_FRAME) {
        if (skip_why)
            *skip_why = "frame-too-big";
        return 0;
    }
    memcpy(scratch, pkt, orig_len);
    len = orig_len;

    g_arp_crypto_ctx.profile_id = profile_idx >= 0 ? profile_idx : 0;
    g_arp_crypto_ctx.policy_id = 0;
    g_arp_crypto_ctx.wire_id = (uint8_t)ARP_DEFAULT_WIRE_ID;

    if (crypto_option_encrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                              &g_arp_crypto_ctx, pkt, &len) != 0) {
        memcpy(pkt, scratch, orig_len);
        job->len = orig_len;
        if (skip_why)
            *skip_why = "encrypt-error";
        return 0;
    }
    job->len = len;
    return 1;
}

static int arp_try_decrypt_l2_pqc(struct forwarder *fwd, struct ne_packet *job, uint8_t *pkt)
{
    uint32_t len;
    const char *fail_why = NULL;

    if (!fwd || !job || !pkt)
        return -1;

    if (crypto_pkt_is_arp(pkt, job->len))
        return 0; /* plain ARP — bridge as-is */

    if (!crypto_eth_l2_has_arp_marker(pkt, job->len))
        return -1; /* not ARP wire */

    if (!fwd->cfg || !fwd->cfg->crypto_enabled) {
        fail_why = "crypto-disabled";
        goto decrypt_fail;
    }
    arp_crypto_ctx_init(fwd->cfg);
    if (!g_arp_crypto_ctx_ready) {
        fail_why = "arp-crypto-not-ready";
        goto decrypt_fail;
    }
    len = job->len;
    if (crypto_option_decrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                              &g_arp_crypto_ctx, pkt, &len) != 0) {
        fail_why = "decrypt-error";
        goto decrypt_fail;
    }
    if (!crypto_pkt_is_arp(pkt, len)) {
        fail_why = "not-arp-after-decrypt";
        goto decrypt_fail;
    }
    job->len = len;
    {
        static uint64_t last_dec_ok_ms;

        if (arp_log_fail_ratelimit(&last_dec_ok_ms))
            fprintf(stderr, "[ARP] decrypt ok (arp-default-key)\n");
    }
    return 1;

decrypt_fail:
    {
        static uint64_t last_dec_fail_ms;

        if (arp_log_fail_ratelimit(&last_dec_fail_ms))
            fprintf(stderr, "[ARP] decrypt fail why=%s\n",
                    fail_why ? fail_why : "unknown");
    }
    return -1;
}

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE])
{
    int profile_pi;
    const struct profile_config *prof;
    int primary_wan_dp;
    int wan_dp;
    int used_backup = 0;
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
    if (resolve_wan_dp_for_fwd_local(fwd, prof, ingress_li, &primary_wan_dp) != 0) {
        static uint64_t last_no_pair_ms;

        if (arp_log_fail_ratelimit(&last_no_pair_ms))
            fprintf(stderr,
                    "[ARP] bridge local %s fail: no BE pair (profile=%s bridges=%d)\n",
                    local_ifname(fwd, ingress_li), prof->name, prof->bridge_count);
        return -1;
    }
    if (primary_wan_dp < 0 || primary_wan_dp >= fwd->wan_count)
        return -1;

    wan_dp = arp_select_egress_wan(fwd, prof, primary_wan_dp, &used_backup);
    if (wan_dp < 0) {
        static uint64_t last_wan_stopped_ms;

        if (arp_log_fail_ratelimit(&last_wan_stopped_ms))
            fprintf(stderr,
                    "[ARP] bridge local %s fail: primary %s down, no backup WAN\n",
                    local_ifname(fwd, ingress_li), wan_ifname(fwd, primary_wan_dp));
        return -1;
    }

    {
        uint32_t spa = 0, tpa = 0;
        const char *skip_why = NULL;
        int encrypted;
        int is_req;
        char spa_s[16], tpa_s[16], dmac_s[24], smac_s[24];

        if (job->len < ARP_ETH_HDR_LEN ||
            dp_parse_arp_ips(pkt, job->len, &spa, &tpa) != 0) {
            static uint64_t last_parse_ms;

            if (arp_log_fail_ratelimit(&last_parse_ms))
                fprintf(stderr, "[ARP-TX] FAIL parse lan=%s\n",
                        local_ifname(fwd, ingress_li));
            return -1;
        }
        encrypted = arp_try_encrypt_l2_pqc(fwd, job, mut, profile_pi, &skip_why);

        is_req = arp_eth_dmac_is_broadcast(pkt, job->len) ||
                 arp_eth_dmac_is_multicast(pkt, job->len);
        arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
        arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
        arp_format_mac(pkt, dmac_s, sizeof(dmac_s));
        arp_format_mac(pkt + MAC_LEN, smac_s, sizeof(smac_s));

        if (is_req) {
            if (used_backup)
                arp_log_backup_line(
                    "[ARP-TX] REQUEST (who-has) dmac=%s\n"
                    "         lan=%s (br=%s) primary_wan=%s(DOWN) -> BACKUP wan=%s (br=%s)\n"
                    "         spa=%s tpa=%s smac=%s encrypted=%d%s%s\n",
                    dmac_s,
                    local_ifname(fwd, ingress_li),
                    arp_br_name_for_lan(fwd, prof, ingress_li),
                    wan_ifname(fwd, primary_wan_dp),
                    wan_ifname(fwd, wan_dp),
                    arp_br_name_for_wan(prof, wan_dp),
                    spa_s, tpa_s, smac_s, encrypted,
                    (!encrypted && skip_why) ? " why=" : "",
                    (!encrypted && skip_why) ? skip_why : "");
            else
                arp_log_backup_line(
                    "[ARP-TX] REQUEST (who-has) dmac=%s\n"
                    "         lan=%s (br=%s) -> wan=%s (br=%s) [PRIMARY]\n"
                    "         spa=%s tpa=%s smac=%s encrypted=%d%s%s\n",
                    dmac_s,
                    local_ifname(fwd, ingress_li),
                    arp_br_name_for_lan(fwd, prof, ingress_li),
                    wan_ifname(fwd, wan_dp),
                    arp_br_name_for_wan(prof, wan_dp),
                    spa_s, tpa_s, smac_s, encrypted,
                    (!encrypted && skip_why) ? " why=" : "",
                    (!encrypted && skip_why) ? skip_why : "");
        } else {
            if (used_backup)
                arp_log_backup_line(
                    "[ARP-TX] REPLY dmac=%s\n"
                    "         lan=%s (br=%s) primary_wan=%s(DOWN) -> BACKUP wan=%s (br=%s)\n"
                    "         spa=%s tpa=%s smac=%s encrypted=%d%s%s\n",
                    dmac_s,
                    local_ifname(fwd, ingress_li),
                    arp_br_name_for_lan(fwd, prof, ingress_li),
                    wan_ifname(fwd, primary_wan_dp),
                    wan_ifname(fwd, wan_dp),
                    arp_br_name_for_wan(prof, wan_dp),
                    spa_s, tpa_s, smac_s, encrypted,
                    (!encrypted && skip_why) ? " why=" : "",
                    (!encrypted && skip_why) ? skip_why : "");
            else
                arp_log_backup_line(
                    "[ARP-TX] REPLY dmac=%s\n"
                    "         lan=%s (br=%s) -> wan=%s (br=%s) [PRIMARY]\n"
                    "         spa=%s tpa=%s smac=%s encrypted=%d%s%s\n",
                    dmac_s,
                    local_ifname(fwd, ingress_li),
                    arp_br_name_for_lan(fwd, prof, ingress_li),
                    wan_ifname(fwd, wan_dp),
                    arp_br_name_for_wan(prof, wan_dp),
                    spa_s, tpa_s, smac_s, encrypted,
                    (!encrypted && skip_why) ? " why=" : "",
                    (!encrypted && skip_why) ? skip_why : "");
        }
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
    if (egress_ifname)
        strncpy(egress_ifname, wan_ifname(fwd, wan_dp), IF_NAMESIZE - 1);
    return 0;
}

int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE])
{
    int profile_pi;
    uint8_t *mut;
    int dec;
    int was_plain;
    int had_marker;
    uint32_t spa = 0, tpa = 0;
    int have_ips = 0;
    int is_bcast;
    int deliver_li = -1;
    char spa_s[16] = "?", tpa_s[16] = "?", dmac_s[24], smac_s[24] = "?";
    char flood_lans[256] = "";
    const char *crypto_state;

    if (egress_ifname)
        egress_ifname[0] = '\0';

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    mut = ne_packet_data(&fwd->pair, job->addr);
    if (!mut)
        return -1;

    was_plain = crypto_pkt_is_arp(mut, job->len);
    had_marker = crypto_eth_l2_has_arp_marker(mut, job->len);
    if (was_plain)
        have_ips = (dp_parse_arp_ips(mut, job->len, &spa, &tpa) == 0);

    dec = arp_try_decrypt_l2_pqc(fwd, job, mut);
    if (dec < 0) {
        static uint64_t last_wan_dec_fail_ms;

        if (arp_log_fail_ratelimit(&last_wan_dec_fail_ms))
            fprintf(stderr,
                    "[ARP] wan %s crypto=decrypt-fail bridge=drop\n",
                    wan_ifname(fwd, ingress_wan_dp));
        return -1;
    }

    if (dec == 1)
        have_ips = (dp_parse_arp_ips(mut, job->len, &spa, &tpa) == 0);

    profile_pi = profile_pi_for_wan_dp(fwd, ingress_wan_dp);
    if (profile_pi < 0) {
        static uint64_t last_no_profile_ms;

        if (arp_log_fail_ratelimit(&last_no_profile_ms))
            fprintf(stderr, "[ARP] bridge wan %s fail: no profile\n",
                    wan_ifname(fwd, ingress_wan_dp));
        return -1;
    }

    if (job->len < ARP_ETH_HDR_LEN) {
        static uint64_t last_short_ms;

        if (arp_log_fail_ratelimit(&last_short_ms))
            fprintf(stderr, "[ARP] wan %s fail: frame too short\n",
                    wan_ifname(fwd, ingress_wan_dp));
        return -1;
    }

    is_bcast = arp_eth_dmac_is_broadcast(mut, job->len) ||
               arp_eth_dmac_is_multicast(mut, job->len);
    arp_format_mac(mut, dmac_s, sizeof(dmac_s));
    arp_format_mac(mut + MAC_LEN, smac_s, sizeof(smac_s));
    if (have_ips) {
        arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
        arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
    }

    if (dec == 1)
        crypto_state = "decrypted";
    else if (was_plain)
        crypto_state = "plain";
    else if (had_marker)
        crypto_state = "decrypted";
    else
        crypto_state = "plain";

    if (is_bcast) {
        const struct profile_config *prof = &fwd->cfg->profiles[profile_pi];

        if (arp_flood_to_profile_locals(fwd, job, mut, profile_pi,
                                        flood_lans, sizeof(flood_lans)) != 0) {
            static uint64_t last_flood_fail_ms;

            if (arp_log_fail_ratelimit(&last_flood_fail_ms))
                fprintf(stderr,
                        "[ARP-RX] REQUEST FLOOD FAIL from_wan=%s spa=%s tpa=%s\n",
                        wan_ifname(fwd, ingress_wan_dp), spa_s, tpa_s);
            return -1;
        }
        arp_log_backup_line(
            "[ARP-RX] REQUEST (who-has) dmac=%s\n"
            "         from_wan=%s (br=%s) -> FLOOD lans=[%s]\n"
            "         spa=%s tpa=%s smac=%s crypto=%s\n",
            dmac_s,
            wan_ifname(fwd, ingress_wan_dp),
            arp_br_name_for_wan(prof, ingress_wan_dp),
            flood_lans[0] ? flood_lans : "-",
            spa_s, tpa_s, smac_s, crypto_state);
    } else {
        const struct profile_config *prof = &fwd->cfg->profiles[profile_pi];

        deliver_li = mac_lookup(fwd, mut);
        if (deliver_li >= 0 && arp_profile_owns_local(fwd, profile_pi, deliver_li)) {
            struct ne_ring *ring = arp_mid_to_local_ring(fwd, deliver_li);

            job->dir = NE_DIR_LOCAL;
            job->local_idx = (uint8_t)deliver_li;
            if (dp_ring_push(fwd, ring, job) != 0) {
                static uint64_t last_ring_fail_ms;

                if (arp_log_fail_ratelimit(&last_ring_fail_ms))
                    fprintf(stderr,
                            "[ARP-RX] REPLY FDB FAIL from_wan=%s lan=%s "
                            "smac=%s dmac=%s\n",
                            wan_ifname(fwd, ingress_wan_dp),
                            local_ifname(fwd, deliver_li),
                            smac_s, dmac_s);
                return -1;
            }
            arp_log_backup_line(
                "[ARP-RX] REPLY dmac=%s\n"
                "         from_wan=%s (br=%s) -> lan=%s (br=%s) [MAC-FDB]\n"
                "         spa=%s tpa=%s smac=%s crypto=%s\n",
                dmac_s,
                wan_ifname(fwd, ingress_wan_dp),
                arp_br_name_for_wan(prof, ingress_wan_dp),
                local_ifname(fwd, deliver_li),
                arp_br_name_for_lan(fwd, prof, deliver_li),
                spa_s, tpa_s, smac_s, crypto_state);
        } else {
            if (arp_flood_to_profile_locals(fwd, job, mut, profile_pi,
                                            flood_lans, sizeof(flood_lans)) != 0) {
                static uint64_t last_flood_miss_ms;

                if (arp_log_fail_ratelimit(&last_flood_miss_ms))
                    fprintf(stderr,
                            "[ARP-RX] REPLY FLOOD-MISS FAIL from_wan=%s "
                            "smac=%s dmac=%s\n",
                            wan_ifname(fwd, ingress_wan_dp), smac_s, dmac_s);
                return -1;
            }
            arp_log_backup_line(
                "[ARP-RX] REPLY dmac=%s [MAC miss -> FLOOD]\n"
                "         from_wan=%s (br=%s) -> FLOOD lans=[%s]\n"
                "         spa=%s tpa=%s smac=%s crypto=%s\n",
                dmac_s,
                wan_ifname(fwd, ingress_wan_dp),
                arp_br_name_for_wan(prof, ingress_wan_dp),
                flood_lans[0] ? flood_lans : "-",
                spa_s, tpa_s, smac_s, crypto_state);
        }
    }

    if (egress_ifname) {
        if (deliver_li >= 0)
            strncpy(egress_ifname, local_ifname(fwd, deliver_li), IF_NAMESIZE - 1);
        else
            strncpy(egress_ifname, "*", IF_NAMESIZE - 1);
    }
    return 0;
}