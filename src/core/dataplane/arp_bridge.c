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
#include <stdint.h>
#include <limits.h>
#include <stdarg.h>
#include <pthread.h>
#include <net/if.h>

#define ARP_LOG_FAIL_INTERVAL_MS 30000ull
#define ARP_BACKUP_SOFT_MAX      64
#define ARP_BACKUP_SOFT_TTL_MS   3000ull
#define ARP_DEFAULT_WIRE_ID      250u
#define ARP_DEFAULT_AES_BITS     256

/* 1 = mã hóa ARP L2-PQC (key/option riêng), 0 = bridge ARP plaintext.
 * Decrypt vẫn chạy nếu wire có ARP marker (peer vẫn encrypt). */
#ifndef ARP_ENCRYPT_ENABLE
#define ARP_ENCRYPT_ENABLE 1
#endif

struct arp_backup_soft_entry {
    int used;
    int backup_wan_dp;
    int return_local_idx;
    uint32_t spa;
    uint32_t tpa;
    uint64_t expire_ms;
};

static struct arp_backup_soft_entry g_arp_backup_soft[ARP_BACKUP_SOFT_MAX];
static pthread_spinlock_t g_arp_backup_soft_lock;
static int g_arp_backup_soft_lock_ready;
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

static void arp_backup_soft_lock_init(void)
{
    if (g_arp_backup_soft_lock_ready)
        return;
    pthread_spin_init(&g_arp_backup_soft_lock, PTHREAD_PROCESS_PRIVATE);
    g_arp_backup_soft_lock_ready = 1;
}

static void arp_backup_remember(int backup_wan_dp, uint32_t spa, uint32_t tpa,
                                int return_local_idx)
{
    uint64_t now;
    int free_slot = -1;
    int oldest = 0;
    uint64_t oldest_exp = UINT64_MAX;

    if (backup_wan_dp < 0 || return_local_idx < 0)
        return;

    arp_backup_soft_lock_init();
    now = arp_monotonic_ms();
    pthread_spin_lock(&g_arp_backup_soft_lock);

    for (int i = 0; i < ARP_BACKUP_SOFT_MAX; i++) {
        struct arp_backup_soft_entry *e = &g_arp_backup_soft[i];

        if (e->used && e->expire_ms <= now) {
            e->used = 0;
        }
        if (e->used &&
            e->backup_wan_dp == backup_wan_dp &&
            e->spa == spa && e->tpa == tpa) {
            e->return_local_idx = return_local_idx;
            e->expire_ms = now + ARP_BACKUP_SOFT_TTL_MS;
            pthread_spin_unlock(&g_arp_backup_soft_lock);
            return;
        }
        if (!e->used && free_slot < 0)
            free_slot = i;
        if (!e->used)
            continue;
        if (e->expire_ms < oldest_exp) {
            oldest_exp = e->expire_ms;
            oldest = i;
        }
    }

    {
        int slot = free_slot >= 0 ? free_slot : oldest;
        struct arp_backup_soft_entry *e = &g_arp_backup_soft[slot];

        e->used = 1;
        e->backup_wan_dp = backup_wan_dp;
        e->return_local_idx = return_local_idx;
        e->spa = spa;
        e->tpa = tpa;
        e->expire_ms = now + ARP_BACKUP_SOFT_TTL_MS;
    }
    pthread_spin_unlock(&g_arp_backup_soft_lock);
}

/* Match request (spa,tpa) or reply (spa↔tpa). Returns return_local_idx or -1. */
static int arp_backup_lookup(int ingress_wan_dp, uint32_t spa, uint32_t tpa)
{
    uint64_t now;
    int hit = -1;

    if (ingress_wan_dp < 0)
        return -1;

    arp_backup_soft_lock_init();
    now = arp_monotonic_ms();
    pthread_spin_lock(&g_arp_backup_soft_lock);

    for (int i = 0; i < ARP_BACKUP_SOFT_MAX; i++) {
        struct arp_backup_soft_entry *e = &g_arp_backup_soft[i];

        if (!e->used)
            continue;
        if (e->expire_ms <= now) {
            e->used = 0;
            continue;
        }
        if (e->backup_wan_dp != ingress_wan_dp)
            continue;
        if ((e->spa == spa && e->tpa == tpa) ||
            (e->spa == tpa && e->tpa == spa)) {
            hit = e->return_local_idx;
            break;
        }
    }
    pthread_spin_unlock(&g_arp_backup_soft_lock);
    return hit;
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

void arp_bridge_reload_policies(struct app_config *cfg)
{
    if (!cfg)
        return;
    arp_crypto_ctx_init(cfg);
    fprintf(stderr,
            "[ARP] mode=allow-all | arp_encrypt=%d | key=arp-default | opt=L2-PQC/ARP\n",
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

/*
 * LAN whose primary bridge WAN is down/held/CFM-excluded.
 * One candidate → that LAN. If many candidates exist, avoid guessing.
 */
static int arp_resolve_backup_local(struct forwarder *fwd,
                                    const struct profile_config *prof,
                                    int profile_pi,
                                    uint32_t spa, uint32_t tpa, int have_ips)
{
    int candidates[MAX_INTERFACES];
    int n = 0;
    (void)profile_pi;
    (void)spa;
    (void)tpa;
    (void)have_ips;

    if (!fwd || !fwd->cfg || !prof)
        return -1;

    for (int i = 0; i < prof->bridge_count; i++) {
        int li;
        int wan_dp = prof->bridges[i].wan_dp;

        if (arp_wan_dp_usable(wan_dp))
            continue;
        li = bridge_fwd_local(fwd, prof->bridges[i].local_idx);
        if (li < 0)
            continue;
        if (n < MAX_INTERFACES)
            candidates[n++] = li;
    }

    if (n == 0)
        return -1;
    if (n == 1)
        return candidates[0];
    return -1;
}

static int arp_select_egress_wan(struct forwarder *fwd,
                                 const struct profile_config *prof,
                                 int primary_wan_dp, int *used_backup)
{
    if (used_backup)
        *used_backup = 0;

    if (arp_wan_dp_usable(primary_wan_dp) && !fwd_wan_is_stopped(primary_wan_dp))
        return primary_wan_dp;

    {
        int backup = arp_pick_backup_wan_dp(fwd, prof, primary_wan_dp);

        if (backup < 0)
            return -1;
        if (used_backup)
            *used_backup = 1;
        return backup;
    }
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
        static uint64_t last_local_policy_ms;

        if (dp_parse_arp_ips(pkt, job->len, &spa, &tpa) != 0) {
            static uint64_t last_parse_ms;

            if (arp_log_fail_ratelimit(&last_parse_ms))
                fprintf(stderr, "[ARP] local %s parse-fail bridge=drop\n",
                        local_ifname(fwd, ingress_li));
            return -1;
        }
        encrypted = arp_try_encrypt_l2_pqc(fwd, job, mut, profile_pi, &skip_why);

        if (used_backup)
            arp_backup_remember(wan_dp, spa, tpa, ingress_li);

        {
            char spa_s[16], tpa_s[16];

            arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
            arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
            if (used_backup) {
                const char *br_of_backup = "?";
                int bl = -1;

                if (resolve_fwd_local_for_wan_dp(fwd, prof, wan_dp, &bl) == 0)
                    br_of_backup = local_ifname(fwd, bl);

                arp_log_backup_line(
                    "[ARP] BACKUP-EGRESS pkt: origin_lan=%s "
                    "primary_wan=%s(DOWN) actual_egress_wan=%s "
                    "reply_must_deliver_lan=%s "
                    "br_of_actual_wan=%s(IGNORE-br-sai) "
                    "spa=%s tpa=%s encrypted=%d\n",
                    local_ifname(fwd, ingress_li),
                    wan_ifname(fwd, primary_wan_dp),
                    wan_ifname(fwd, wan_dp),
                    local_ifname(fwd, ingress_li),
                    br_of_backup,
                    spa_s, tpa_s, encrypted);
            } else if (arp_log_fail_ratelimit(&last_local_policy_ms)) {
                if (encrypted)
                    fprintf(stderr,
                            "[ARP] path=primary dir=lan->wan "
                            "origin_lan=%s primary_wan=%s egress_wan=%s "
                            "spa=%s tpa=%s mode=encrypt-l2-default-key "
                            "enc_wire_id=%d encrypted=%d%s%s\n",
                            local_ifname(fwd, ingress_li),
                            wan_ifname(fwd, wan_dp), wan_ifname(fwd, wan_dp),
                            spa_s, tpa_s,
                            ARP_DEFAULT_WIRE_ID, encrypted,
                            (!encrypted && skip_why) ? " why=" : "",
                            (!encrypted && skip_why) ? skip_why : "");
                else
                    fprintf(stderr,
                            "[ARP] path=primary dir=lan->wan "
                            "origin_lan=%s primary_wan=%s egress_wan=%s "
                            "spa=%s tpa=%s mode=plain encrypted=0%s%s\n",
                            local_ifname(fwd, ingress_li),
                            wan_ifname(fwd, wan_dp), wan_ifname(fwd, wan_dp),
                            spa_s, tpa_s,
                            skip_why ? " why=" : "",
                            skip_why ? skip_why : "");
                fflush(stderr);
            }
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
    const struct profile_config *prof;
    int local_idx;
    struct ne_ring *ring;
    uint8_t *mut;
    int dec;
    int was_plain;
    int had_marker;
    uint32_t spa = 0, tpa = 0;
    int have_ips = 0;

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

    prof = &fwd->cfg->profiles[profile_pi];
    {
        int bridge_local = -1;
        int soft_local = -1;
        int backup_local = -1;
        int used_backup = 0;

        if (have_ips)
            soft_local = arp_backup_lookup(ingress_wan_dp, spa, tpa);

        if (soft_local >= 0) {
            local_idx = soft_local;
            used_backup = 1;
            if (resolve_fwd_local_for_wan_dp(fwd, prof, ingress_wan_dp,
                                            &bridge_local) != 0)
                bridge_local = -1;
        } else {
            bridge_local = -1;
            if (resolve_fwd_local_for_wan_dp(fwd, prof, ingress_wan_dp, &bridge_local) != 0)
                bridge_local = -1;

            if (bridge_local >= 0) {
                /* Normal pair — do not steal with primary-down heuristic. */
                local_idx = bridge_local;
            } else {
                /* WAN has no Br pair: fall back to LAN whose primary is down. */
                backup_local = arp_resolve_backup_local(fwd, prof, profile_pi,
                                                        spa, tpa, have_ips);
                if (backup_local < 0) {
                    static uint64_t last_no_pair_ms;

                    if (arp_log_fail_ratelimit(&last_no_pair_ms))
                        fprintf(stderr,
                                "[ARP] bridge wan %s fail: no BE pair "
                                "(profile=%s bridges=%d)\n",
                                wan_ifname(fwd, ingress_wan_dp), prof->name,
                                prof->bridge_count);
                    return -1;
                }
                local_idx = backup_local;
                used_backup = 1;
            }
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

        {
            static uint64_t last_wan_bridge_ms;
            const char *crypto_state;
            char spa_s[16] = "?", tpa_s[16] = "?";

            if (dec == 1)
                crypto_state = "decrypted";
            else if (was_plain)
                crypto_state = "plain";
            else if (had_marker)
                crypto_state = "decrypted";
            else
                crypto_state = "plain";

            if (have_ips) {
                arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
                arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
            }

            if (used_backup && soft_local >= 0) {
                const char *br_would = bridge_local >= 0
                    ? local_ifname(fwd, bridge_local) : "none";

                arp_log_backup_line(
                    "[ARP] BACKUP-RETURN pkt: ingress_wan=%s "
                    "br_of_ingress_wan=%s(IGNORE-br-sai) "
                    "deliver_lan=%s(LAN-goc-tu-soft-state) "
                    "spa=%s tpa=%s crypto=%s\n",
                    wan_ifname(fwd, ingress_wan_dp), br_would,
                    local_ifname(fwd, local_idx),
                    spa_s, tpa_s, crypto_state);
            } else if (used_backup) {
                arp_log_backup_line(
                    "[ARP] BACKUP-RETURN pkt: ingress_wan=%s "
                    "deliver_lan=%s(LAN-goc-heuristic) "
                    "spa=%s tpa=%s crypto=%s\n",
                    wan_ifname(fwd, ingress_wan_dp),
                    local_ifname(fwd, local_idx),
                    spa_s, tpa_s, crypto_state);
            } else if (arp_log_fail_ratelimit(&last_wan_bridge_ms)) {
                fprintf(stderr,
                        "[ARP] path=primary dir=wan->lan "
                        "ingress_wan=%s deliver_lan=%s spa=%s tpa=%s crypto=%s\n",
                        wan_ifname(fwd, ingress_wan_dp),
                        local_ifname(fwd, local_idx),
                        spa_s, tpa_s, crypto_state);
                fflush(stderr);
            }
        }

        if (egress_ifname)
            strncpy(egress_ifname, local_ifname(fwd, local_idx), IF_NAMESIZE - 1);
        return 0;
    }
}