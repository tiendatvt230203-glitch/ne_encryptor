#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../../inc/core/config.h"

#define DIAG_TBL_N     12
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

static void print_iface_table(const struct app_config *cfg) {
    static const int w[DIAG_TBL_N] = { 14, 12, 0, 0, 0, 0, 0, 0 };
    static const char *hdr[DIAG_TBL_N] = {
        "role", "interface", "", "", "", "", "", ""
    };

    fprintf(stderr, "\n  [interfaces]\n");
    tbl_hline(w, 2);
    tbl_row(w, 2, hdr);
    tbl_hline(w, 2);

    for (int i = 0; i < cfg->local_count; i++) {
        char c0[32], c1[32];
        snprintf(c0, sizeof(c0), "lan");
        snprintf(c1, sizeof(c1), "%s", cfg->locals[i].ifname);
        const char *row[DIAG_TBL_N] = { c0, c1, "", "", "", "", "", "" };
        tbl_row(w, 2, row);
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        char c0[32], c1[32];
        snprintf(c0, sizeof(c0), cfg->wans[i].dataplane ? "wan" : "wan(hs)");
        snprintf(c1, sizeof(c1), "%s", cfg->wans[i].ifname);
        const char *row[DIAG_TBL_N] = { c0, c1, "", "", "", "", "", "" };
        tbl_row(w, 2, row);
    }
    tbl_hline(w, 2);
}

static void print_policy_table(const struct app_config *cfg) {
    static const int w[DIAG_TBL_N] = {
        6, 8, 7, 6, 10, 8, 18, 18, 7, 7, 0, 0
    };
    static const char *hdr[DIAG_TBL_N] = {
        "db_id", "priority", "pkt_tag", "layer", "crypto", "proto",
        "src", "dst", "sport", "dport", "", ""
    };

    fprintf(stderr, "\n  [policies] count=%d\n", cfg->policy_count);
    fprintf(stderr,
            "  priority = match order (lower first); pkt_tag = ID in encrypted packet (not DB id)\n");
    tbl_hline(w, 10);
    tbl_row(w, 10, hdr);
    tbl_hline(w, 10);

    for (int pr = 0; pr < cfg->profile_count; pr++) {
        const struct profile_config *p = &cfg->profiles[pr];
        for (int j = 0; j < p->policy_count; j++) {
            int pix = p->policy_indices[j];
            if (pix < 0 || pix >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pix];
            char c0[8], c1[8], c2[8], c3[12], c4[8], c5[12];
            char c8[12], c9[12];
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

            const char *row[DIAG_TBL_N] = {
                c0, c1, c2, c3, c4, c5, src_c, dst_c, c8, c9, "", ""
            };
            tbl_row(w, 10, row);
        }
    }
    tbl_hline(w, 10);
}

void main_diag_log_no_update(int trigger_profile_id, const struct app_config *cfg) {
    if (!cfg)
        return;

    fprintf(stderr,
            "\n[DB] profile %d — no update (DB same as running, reload skipped)\n",
            trigger_profile_id);
    fprintf(stderr, "  unchanged: LAN=%d WAN=%d policies=%d\n",
            cfg->local_count, cfg->wan_count, cfg->policy_count);
    print_iface_table(cfg);
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
    print_iface_table(cfg);
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
        print_iface_table(cfg);
    print_policy_table(cfg);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_dataplane_ready(struct app_config *cfg) {
    if (!cfg)
        return;

    fprintf(stderr, "+-- DATAPLANE ready --+\n");
    print_iface_table(cfg);
    fprintf(stderr, "\n");
    fflush(stderr);
}