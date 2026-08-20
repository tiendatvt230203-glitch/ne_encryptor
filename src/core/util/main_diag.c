#include <stdio.h>
#include <string.h>

#include "../../../inc/core/config.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/crypto/pqc_handshake.h"

#define DIAG_KEY_PREFIX_LEN 9
#define NE_PQC_LOG_SLOTS    64

typedef struct {
    int profile_id;
    int policy_id;
    uint8_t traffic_prefix[4];
    int valid;
} ne_pqc_log_slot_t;

static ne_pqc_log_slot_t ne_pqc_log_cache[NE_PQC_LOG_SLOTS];

static int key_prefix_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

static void policy_ne_key_prefix_loaded(char *out, size_t outsz, int policy_index)
{
    struct packet_crypto_ctx *live_ctx = NULL;
    const uint8_t *key;

    if (policy_index < 0 || !fwd_crypto_policy_ready(policy_index)) {
        out[0] = '\0';
        return;
    }

    live_ctx = fwd_crypto_policy_ctx(policy_index);
    if (!live_ctx || !live_ctx->initialized) {
        out[0] = '\0';
        return;
    }

    key = packet_crypto_get_key(live_ctx, KEY_SLOT_CURRENT);
    if (!key_prefix_nonzero(key, 4)) {
        out[0] = '\0';
        return;
    }

    snprintf(out, outsz, "%02X%02X%02X%02X", key[0], key[1], key[2], key[3]);
}

static void print_system_table(const struct app_config *cfg, const char *event)
{
    mac_learn_log_runtime_table(NULL, cfg, event);
}

void main_diag_log_ne_policy_key(int policy_index, int db_id)
{
    char prefix[DIAG_KEY_PREFIX_LEN];

    policy_ne_key_prefix_loaded(prefix, sizeof(prefix), policy_index);
    if (!prefix[0])
        return;

    fprintf(stderr, "[NE-KEY] policy db_id=%d Key prefix: %s\n", db_id, prefix);
    fflush(stderr);
}

static void key_prefix_hex(char *out, size_t outsz, const uint8_t *key)
{
    snprintf(out, outsz, "%02X%02X%02X%02X", key[0], key[1], key[2], key[3]);
}

static int ne_pqc_log_already_seen(int profile_id, int policy_id, const uint8_t *traffic_key)
{
    for (int i = 0; i < NE_PQC_LOG_SLOTS; i++) {
        if (!ne_pqc_log_cache[i].valid)
            continue;
        if (ne_pqc_log_cache[i].profile_id != profile_id ||
            ne_pqc_log_cache[i].policy_id != policy_id)
            continue;
        if (memcmp(ne_pqc_log_cache[i].traffic_prefix, traffic_key, 4) == 0)
            return 1;
    }
    return 0;
}

static void ne_pqc_log_remember(int profile_id, int policy_id, const uint8_t *traffic_key)
{
    int slot = -1;

    for (int i = 0; i < NE_PQC_LOG_SLOTS; i++) {
        if (!ne_pqc_log_cache[i].valid) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        slot = (profile_id ^ policy_id ^ traffic_key[0]) % NE_PQC_LOG_SLOTS;

    ne_pqc_log_cache[slot].profile_id = profile_id;
    ne_pqc_log_cache[slot].policy_id = policy_id;
    memcpy(ne_pqc_log_cache[slot].traffic_prefix, traffic_key, 4);
    ne_pqc_log_cache[slot].valid = 1;
}

void main_diag_log_ne_pqc_traffic_key(int profile_id, int policy_id,
                                      const uint8_t traffic_key[32])
{
    uint8_t hs_key[PQC_TRAFFIC_KEY_SZ];
    char traffic_px[DIAG_KEY_PREFIX_LEN];
    char hs_px[DIAG_KEY_PREFIX_LEN];
    int hs_ok;

    if (!traffic_key || !key_prefix_nonzero(traffic_key, 4))
        return;
    if (ne_pqc_log_already_seen(profile_id, policy_id, traffic_key))
        return;

    key_prefix_hex(traffic_px, sizeof(traffic_px), traffic_key);
    hs_ok = (sig_pqc_diversify_key(profile_id, policy_id, hs_key) == 0);
    if (hs_ok)
        key_prefix_hex(hs_px, sizeof(hs_px), hs_key);
    else
        snprintf(hs_px, sizeof(hs_px), "--------");

    if (hs_ok && memcmp(traffic_key, hs_key, PQC_TRAFFIC_KEY_SZ) == 0) {
        fprintf(stderr,
                "[NE-KEY] profile=%d policy_id=%d traffic=%s pqc_hs=%s MATCH\n",
                profile_id, policy_id, traffic_px, hs_px);
    } else if (hs_ok) {
        fprintf(stderr,
                "[NE-KEY] profile=%d policy_id=%d traffic=%s pqc_hs=%s MISMATCH\n",
                profile_id, policy_id, traffic_px, hs_px);
    } else {
        fprintf(stderr,
                "[NE-KEY] profile=%d policy_id=%d traffic=%s pqc_hs=%s PQC_NOT_READY\n",
                profile_id, policy_id, traffic_px, hs_px);
    }
    fflush(stderr);
    ne_pqc_log_remember(profile_id, policy_id, traffic_key);
}

void main_diag_log_no_update(int trigger_profile_id, const struct app_config *cfg) {
    if (!cfg)
        return;

    fprintf(stderr,
            "\n[DB] profile %d — no update (DB same as running, reload skipped)\n",
            trigger_profile_id);
    fprintf(stderr, "  unchanged: LAN=%d WAN=%d policies=%d\n",
            cfg->local_count, cfg->wan_count, cfg->policy_count);
    print_system_table(cfg, "db-no-update");
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_db_apply(const struct app_config *cfg, int trigger_profile_id,
                            const struct app_config *prev_cfg) {
    if (!cfg)
        return;

    fprintf(stderr, "\n[DB] profile %d — loaded from Postgres", trigger_profile_id);
    if (prev_cfg) {
        fprintf(stderr, " | delta LAN %d->%d WAN %d->%d policies %d->%d",
                prev_cfg->local_count, cfg->local_count,
                prev_cfg->wan_count, cfg->wan_count,
                prev_cfg->policy_count, cfg->policy_count);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "| profiles: %-3d | policies: %-3d |\n",
            cfg->profile_count, cfg->policy_count);
    print_system_table(cfg, "db-load");
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_db_policy_apply(const struct app_config *cfg, int trigger_profile_id,
                                   const struct app_config *prev_cfg) {
    if (!cfg)
        return;

    fprintf(stderr,
            "\n[DB] profile %d — policy update from Postgres\n",
            trigger_profile_id);
    if (prev_cfg) {
        fprintf(stderr, "  policies %d -> %d (LAN/WAN ifaces unchanged)\n",
                prev_cfg->policy_count, cfg->policy_count);
    }
    fprintf(stderr, "| profiles: %-3d | policies: %-3d |\n",
            cfg->profile_count, cfg->policy_count);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_config_summary(struct app_config *cfg, int trigger_profile_id,
                                  int is_reload, int policy_only) {
    if (!cfg)
        return;

    fprintf(stderr, "\n");
    if (is_reload) {
        fprintf(stderr, "+-- RELOAD profile %d (dataplane up, decrypt grace 3s) --+\n",
                trigger_profile_id);
    } else {
        fprintf(stderr, "+-- CONFIG profile %d --+\n", trigger_profile_id);
    }
    fprintf(stderr, "| profiles: %-3d | policies: %-3d |\n",
            cfg->profile_count, cfg->policy_count);
    if (!policy_only)
        print_system_table(cfg, is_reload ? "reload" : "config");
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_dataplane_ready(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;

    fprintf(stderr, "+-- DATAPLANE ready --+\n");
    fprintf(stderr,
            "| mode: single-profile (1 UMEM/process; multi-profile UMEM later) |\n");
    mac_learn_refresh_iface_macs(fwd);
    mac_learn_log_runtime_table(fwd, fwd->cfg, "dataplane-ready");
    fprintf(stderr, "\n");
    fflush(stderr);
}