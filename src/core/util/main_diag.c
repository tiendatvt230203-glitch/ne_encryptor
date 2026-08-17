#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../../../inc/core/config.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/forwarder_crypto_runtime.h"
#include "../../../inc/core/mac_learn.h"
#include "../../../inc/crypto/packet_crypto.h"

#define DIAG_TBL_N     12
#define DIAG_KEY_PREFIX_LEN 9
#define DIAG_CIDR_LEN  24

static void tbl_hline(const int *w, int n) {
    fputc('+', stderr);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < w[i] + 2; j++)
            fputc('-', stderr);
        fputc('+', stderr);
    }
    fputc('\n', stderr);
}

static void tbl_row(const int *w, int n, const char *cols[]) {
    fputc('|', stderr);
    for (int i = 0; i < n; i++) {
        fprintf(stderr, " %-*s |", w[i], cols[i] ? cols[i] : "");
    }
    fputc('\n', stderr);
}

static const char *policy_action_name(int action) {
    switch (action) {
    case POLICY_ACTION_BYPASS: return "bypass";
    case POLICY_ACTION_ENCRYPT_L2: return "L2";
    case POLICY_ACTION_ENCRYPT_L3: return "L3";
    case POLICY_ACTION_ENCRYPT_L4: return "L4";
    default: return "?";
    }
}

static const char *policy_proto_str(uint8_t proto) {
    if (proto == POLICY_PROTO_ANY) return "any";
    if (proto == POLICY_PROTO_TCP_UDP) return "tcp/udp";
    if (proto == 1) return "icmp";
    if (proto == 6) return "tcp";
    if (proto == 17) return "udp";
    if (proto == 89) return "ospf";
    return "?";
}

static int ipv4_netmask_to_prefix(uint32_t mask_be) {
    uint32_t m = ntohl(mask_be);
    int p = 0;
    while (m & 0x80000000U) {
        p++;
        m <<= 1;
    }
    return p;
}

static void ipv4_format_cidr(char *out, size_t outsz, uint32_t net_be, uint32_t mask_be) {
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = net_be };
    int prefix = ipv4_netmask_to_prefix(mask_be);

    if (prefix < 0)
        prefix = 0;
    else if (prefix > 32)
        prefix = 32;

    if (!inet_ntop(AF_INET, &a, ip, sizeof(ip))) {
        snprintf(out, outsz, "?");
        return;
    }
    snprintf(out, outsz, "%.*s/%d",
             outsz > 5 ? (int)outsz - 5 : 0, ip, prefix);
}

static void policy_port_str(char *out, size_t outsz, int from, int to) {
    if (from < 0 || to < 0)
        snprintf(out, outsz, "*");
    else if (from == to)
        snprintf(out, outsz, "%d", from);
    else
        snprintf(out, outsz, "%d-%d", from, to);
}

static void policy_cidr_field(char *out, size_t outsz, int any, int negate,
                              uint32_t net_be, uint32_t mask_be) {
    if (any) {
        snprintf(out, outsz, "*");
        return;
    }
    char cidr[DIAG_CIDR_LEN];
    ipv4_format_cidr(cidr, sizeof(cidr), net_be, mask_be);
    if (negate)
        snprintf(out, outsz, "!%.*s", (int)(outsz > 2 ? outsz - 2 : 0), cidr);
    else
        snprintf(out, outsz, "%.*s", (int)(outsz > 1 ? outsz - 1 : 0), cidr);
}

static int key_prefix_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

static void format_key_prefix_hex(char *out, size_t outsz, const uint8_t *key, size_t key_len)
{
    if (!key || key_len < 4 || !key_prefix_nonzero(key, 4)) {
        snprintf(out, outsz, "-");
        return;
    }
    snprintf(out, outsz, "%02X%02X%02X%02X",
             key[0], key[1], key[2], key[3]);
}

static void policy_ne_key_prefix(char *out, size_t outsz, const struct crypto_policy *cp,
                                 int policy_index)
{
    struct packet_crypto_ctx *live_ctx = NULL;

    if (cp->action == POLICY_ACTION_BYPASS) {
        snprintf(out, outsz, "-");
        return;
    }

    if (policy_index >= 0 && fwd_crypto_policy_ready(policy_index))
        live_ctx = fwd_crypto_policy_ctx(policy_index);

    if (!live_ctx || !live_ctx->initialized) {
        snprintf(out, outsz, "n/a");
        return;
    }

    format_key_prefix_hex(out, outsz,
                          packet_crypto_get_key(live_ctx, KEY_SLOT_CURRENT),
                          AES_KEY_LEN);
}

static void policy_crypto_label(const struct crypto_policy *cp, char *out, size_t outsz) {
    if (cp->action == POLICY_ACTION_BYPASS) {
        snprintf(out, outsz, "bypass");
        return;
    }
    if (cp->crypto_mode == CRYPTO_MODE_PQC) {
        snprintf(out, outsz, "pqc");
        return;
    }
    snprintf(out, outsz, "%s-%u",
             cp->crypto_mode == CRYPTO_MODE_GCM ? "gcm" : "ctr",
             (unsigned)cp->aes_bits);
}

static void print_system_table(const struct app_config *cfg, const char *event)
{
    mac_learn_log_runtime_table(NULL, cfg, event);
}

static void print_policy_table(const struct app_config *cfg) {
    static const int w[DIAG_TBL_N] = {
        6, 8, 7, 6, 10, 8, 18, 18, 7, 7, 8, 0
    };
    static const char *hdr[DIAG_TBL_N] = {
        "db_id", "priority", "pkt_tag", "layer", "crypto", "proto",
        "src", "dst", "sport", "dport", "key", ""
    };
    const int ncol = 11;

    fprintf(stderr, "\n  [policies] count=%d\n", cfg->policy_count);
    fprintf(stderr,
            "  priority = match order (lower first); pkt_tag = ID in encrypted packet (not DB id)\n");
    fprintf(stderr,
            "  key = NE dataplane KEY_SLOT_CURRENT (8 hex); compare with [PQC-HS] Key prefix\n");
    fprintf(stderr,
            "        n/a = ctx not loaded; - = ctx loaded but key empty (likely PQC/NE mismatch)\n");
    tbl_hline(w, ncol);
    tbl_row(w, ncol, hdr);
    tbl_hline(w, ncol);

    for (int pr = 0; pr < cfg->profile_count; pr++) {
        const struct profile_config *p = &cfg->profiles[pr];
        for (int j = 0; j < p->policy_count; j++) {
            int pix = p->policy_indices[j];
            if (pix < 0 || pix >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pix];
            char c0[8], c1[8], c2[8], c3[12], c4[8], c5[12];
            char c8[12], c9[12], c10[DIAG_KEY_PREFIX_LEN];
            char src_c[DIAG_CIDR_LEN], dst_c[DIAG_CIDR_LEN];

            snprintf(c0, sizeof(c0), "%d", cp->db_id);
            snprintf(c1, sizeof(c1), "%d", cp->priority);
            snprintf(c2, sizeof(c2), "%d", cp->id);
            snprintf(c3, sizeof(c3), "%s", policy_action_name(cp->action));
            policy_crypto_label(cp, c4, sizeof(c4));
            snprintf(c5, sizeof(c5), "%s", policy_proto_str(cp->protocol));
            policy_cidr_field(src_c, sizeof(src_c), cp->src_any, cp->src_negate,
                              cp->src_net, cp->src_mask);
            policy_cidr_field(dst_c, sizeof(dst_c), cp->dst_any, cp->dst_negate,
                              cp->dst_net, cp->dst_mask);
            policy_port_str(c8, sizeof(c8), cp->src_port_from, cp->src_port_to);
            policy_port_str(c9, sizeof(c9), cp->dst_port_from, cp->dst_port_to);
            policy_ne_key_prefix(c10, sizeof(c10), cp, pix);

            const char *row[DIAG_TBL_N] = {
                c0, c1, c2, c3, c4, c5, src_c, dst_c, c8, c9, c10, ""
            };
            tbl_row(w, ncol, row);
        }
    }
    tbl_hline(w, ncol);
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
    print_policy_table(cfg);
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
    print_policy_table(cfg);
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
    print_policy_table(cfg);
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
    print_policy_table(cfg);
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
    print_policy_table(fwd->cfg);
    fprintf(stderr, "\n");
    fflush(stderr);
}