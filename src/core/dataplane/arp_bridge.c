#include "../../../inc/core/arp_bridge.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/crypto_route.h"
#include "../../../inc/core/dataplane_util.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <net/if.h>

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


static void arp_crypto_ctx_init(const struct app_config *cfg)
{
    if (!cfg || !cfg->crypto_enabled)
        return;
    if (!g_arp_key_loaded) {
        if (parse_hex_bytes_pub(g_arp_hardcoded_master_key_hex,
                                g_arp_default_master_key, AES_MAX_KEY_SIZE) != 0)
            return;
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


static void arp_log_line(const char *fmt, ...)
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

void arp_bridge_reload_policies(struct app_config *cfg)
{
    if (!cfg)
        return;
    arp_crypto_ctx_init(cfg);
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

int bridge_fwd_local_for_wan_dp(struct forwarder *fwd,
                                const struct profile_config *prof,
                                int wan_dp)
{
    const char *lif;

    if (!fwd || !fwd->cfg || !prof || wan_dp < 0)
        return -1;

    for (int i = 0; i < prof->bridge_count; i++) {
        int ci;

        if (prof->bridges[i].wan_dp != wan_dp)
            continue;
        ci = prof->bridges[i].local_idx;
        if (ci < 0 || ci >= fwd->cfg->local_count)
            return -1;
        lif = fwd->cfg->locals[ci].ifname;
        if (!lif[0])
            return -1;
        for (int li = 0; li < fwd->local_count; li++) {
            if (fwd->locals[li].ifname[0] && strcmp(fwd->locals[li].ifname, lif) == 0)
                return li;
        }
        return -1;
    }
    return -1;
}

static int arp_wan_dp_usable(int wan_dp)
{
    if (wan_dp < 0)
        return 0;
    return fwd_wan_dp_ok_for_new_traffic(wan_dp) ? 1 : 0;
}

static int arp_push_to_local(struct forwarder *fwd, struct ne_packet *job, int li)
{
    struct ne_ring *ring;

    if (!fwd || !job || li < 0 || li >= fwd->local_count)
        return -1;
    ring = arp_mid_to_local_ring(fwd, li);
    job->dir = NE_DIR_LOCAL;
    job->local_idx = (uint8_t)li;
    return dp_ring_push(fwd, ring, job);
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

    if (!fwd || !job || !pkt)
        return -1;

    if (crypto_pkt_is_arp(pkt, job->len))
        return 0; /* plain ARP — bridge as-is */

    if (!crypto_eth_l2_has_arp_marker(pkt, job->len))
        return -1; /* not ARP wire */

    if (!fwd->cfg || !fwd->cfg->crypto_enabled)
        return -1;
    arp_crypto_ctx_init(fwd->cfg);
    if (!g_arp_crypto_ctx_ready)
        return -1;
    len = job->len;
    if (crypto_option_decrypt(CRYPTO_OPT_L2_PQC, CRYPTO_PROTO_ARP,
                              &g_arp_crypto_ctx, pkt, &len) != 0)
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
    if (profile_pi < 0)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (resolve_wan_dp_for_fwd_local(fwd, prof, ingress_li, &wan_dp) != 0)
        return -1;
    if (wan_dp < 0 || wan_dp >= fwd->wan_count)
        return -1;

    if (!arp_wan_dp_usable(wan_dp) || fwd_wan_is_stopped(wan_dp))
        return -1;

    {
        uint32_t spa = 0, tpa = 0;
        const char *skip_why = NULL;
        char spa_s[16], tpa_s[16], dmac_s[24], smac_s[24];

        if (job->len < ARP_ETH_HDR_LEN ||
            dp_parse_arp_ips(pkt, job->len, &spa, &tpa) != 0)
            return -1;

        /* Client ARP từ LAN: học SMAC → LAN (vĩnh viễn, không TTL). */
        mac_learn(fwd, ingress_li, pkt, job->len);

        (void)arp_try_encrypt_l2_pqc(fwd, job, mut, profile_pi, &skip_why);
        arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
        arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
        arp_format_mac(pkt, dmac_s, sizeof(dmac_s));
        arp_format_mac(pkt + MAC_LEN, smac_s, sizeof(smac_s));
        arp_log_line(
            "[ARP-TX] lan=%s (br=%s) -> wan=%s (br=%s) "
            "dmac=%s smac=%s spa=%s tpa=%s\n",
            local_ifname(fwd, ingress_li),
            arp_br_name_for_lan(fwd, prof, ingress_li),
            wan_ifname(fwd, wan_dp),
            arp_br_name_for_wan(prof, wan_dp),
            dmac_s, smac_s, spa_s, tpa_s);
    }

    ring = arp_mid_to_wan_ring(fwd, wan_dp);
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (dp_ring_push(fwd, ring, job) != 0)
        return -1;
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
    uint8_t *mut;
    int dec;
    uint32_t spa = 0, tpa = 0;
    int have_ips = 0;
    int deliver_li;
    char spa_s[16] = "?", tpa_s[16] = "?", dmac_s[24], smac_s[24] = "?";

    if (egress_ifname)
        egress_ifname[0] = '\0';

    if (!fwd || !fwd->cfg || !job || !pkt)
        return -1;

    mut = ne_packet_data(&fwd->pair, job->addr);
    if (!mut)
        return -1;

    if (crypto_pkt_is_arp(mut, job->len))
        have_ips = (dp_parse_arp_ips(mut, job->len, &spa, &tpa) == 0);

    dec = arp_try_decrypt_l2_pqc(fwd, job, mut);
    if (dec < 0)
        return -1;

    if (dec == 1)
        have_ips = (dp_parse_arp_ips(mut, job->len, &spa, &tpa) == 0);

    profile_pi = profile_pi_for_wan_dp(fwd, ingress_wan_dp);
    if (profile_pi < 0)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];

    if (job->len < ARP_ETH_HDR_LEN)
        return -1;

    deliver_li = bridge_fwd_local_for_wan_dp(fwd, prof, ingress_wan_dp);
    if (deliver_li < 0)
        return -1;

    arp_format_mac(mut, dmac_s, sizeof(dmac_s));
    arp_format_mac(mut + MAC_LEN, smac_s, sizeof(smac_s));
    if (have_ips) {
        arp_format_ipv4_be32(spa, spa_s, sizeof(spa_s));
        arp_format_ipv4_be32(tpa, tpa_s, sizeof(tpa_s));
    }

    if (arp_push_to_local(fwd, job, deliver_li) != 0)
        return -1;

    arp_log_line(
        "[ARP-RX] from_wan=%s (br=%s) -> lan=%s (br=%s) "
        "dmac=%s smac=%s spa=%s tpa=%s\n",
        wan_ifname(fwd, ingress_wan_dp),
        arp_br_name_for_wan(prof, ingress_wan_dp),
        local_ifname(fwd, deliver_li),
        arp_br_name_for_lan(fwd, prof, deliver_li),
        dmac_s, smac_s, spa_s, tpa_s);

    if (egress_ifname)
        strncpy(egress_ifname, local_ifname(fwd, deliver_li), IF_NAMESIZE - 1);
    return 0;
}