#include <stdio.h>
#include <string.h>

#include "../../../inc/core/config.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/crypto/packet_crypto.h"

#define DIAG_KEY_PREFIX_LEN 9

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
