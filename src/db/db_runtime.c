#include "../../inc/db/db_runtime.h"
#include "../../inc/crypto/pqc_handshake.h"

#include "../../inc/crypto/eth_parse.h"
#include "../../inc/db/db_config.h"
#include "../../inc/db/db_env.h"

#include <libpq-fe.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int ne_profile_id_exists(int profile_id) {
    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
                                 "SELECT 1 FROM ne_profiles WHERE id = $1",
                                 1, NULL, params, NULL, NULL, 0);
    int ok = 0;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
        ok = 1;

    PQclear(res);
    PQfinish(conn);
    return ok ? 0 : -1;
}

int ne_list_profile_ids(int *ids, int max_ids, int *out_count) {
    if (!ids || !out_count || max_ids <= 0)
        return -1;

    *out_count = 0;

    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    PGresult *res = PQexec(conn, "SELECT id FROM ne_profiles ORDER BY id");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] list ne_profiles failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return -1;
    }

    int rows = PQntuples(res);
    int n = 0;
    for (int i = 0; i < rows; i++) {
        if (n >= max_ids) {
            fprintf(stderr,
                    "[WARN] ne_profiles has %d rows, loading only first %d\n",
                    rows, max_ids);
            break;
        }
        const char *val = PQgetvalue(res, i, 0);
        if (!val || !*val)
            continue;
        char *end = NULL;
        long v = strtol(val, &end, 10);
        if (!end || *end != '\0' || v <= 0 || v > INT_MAX) {
            fprintf(stderr, "[WARN] skipping invalid ne_profiles.id: \"%s\"\n", val);
            continue;
        }
        ids[n++] = (int)v;
    }

    PQclear(res);
    PQfinish(conn);
    *out_count = n;
    return 0;
}

int run_db_check(const char *const *keywords, const char *const *values, int only_id) {
    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[CHECK] DB connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    char where_buf[64] = {0};
    if (only_id >= 0)
        snprintf(where_buf, sizeof(where_buf), "WHERE p.id = %d", only_id);

    char sql[4096];
    snprintf(sql, sizeof(sql),
             "SELECT p.id, "
             "COUNT(DISTINCT pol.id) AS policies, "
             "COUNT(DISTINCT lan.id) AS lan_rows, "
             "COUNT(DISTINCT wan.id) AS wan_rows "
             "FROM ne_profiles p "
             "LEFT JOIN ne_policies pol ON pol.profile_id = p.id "
             "LEFT JOIN ne_lan lan ON lan.profile_id = p.id "
             "LEFT JOIN ne_wan wan ON wan.profile_id = p.id "
             "%s "
             "GROUP BY p.id "
             "ORDER BY p.id;",
             where_buf);

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] summary query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    int rows = PQntuples(res);
    if (rows == 0) {
        fprintf(stderr, "[CHECK] no ne_profiles row%s\n", (only_id >= 0) ? " for requested id" : "");
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    fprintf(stdout, "[CHECK] NE profile summary:\n");
    for (int i = 0; i < rows; i++) {
        fprintf(stdout,
                "  profile_id=%s policies=%s lan=%s wan=%s\n",
                PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                PQgetvalue(res, i, 3));
    }
    PQclear(res);

    snprintf(sql, sizeof(sql),
             "SELECT id, COUNT(*) AS c FROM ne_policies GROUP BY id HAVING COUNT(*) > 1 ORDER BY id;");
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] duplicate ne_policies.id query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    if (PQntuples(res) > 0) {
        fprintf(stdout, "[CHECK][WARN] duplicated ne_policies.id:\n");
        for (int i = 0; i < PQntuples(res); i++)
            fprintf(stdout, "  id=%s count=%s\n", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
    } else {
        fprintf(stdout, "[CHECK] ne_policies.id uniqueness: OK\n");
    }
    PQclear(res);

    PQfinish(conn);
    return 0;
}

static int find_local_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int find_wan_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

/* Return owning profile id if LAN index already bound to another profile. */
static int lan_owner_profile(const struct app_config *cfg, int local_idx, int skip_profile_id)
{
    return config_local_owner_profile(cfg, local_idx, skip_profile_id);
}

static int append_local_unique(struct app_config *dst, const struct local_config *src_loc) {
    int idx = find_local_by_ifname(dst, src_loc->ifname);
    if (idx >= 0)
        return idx;
    if (dst->local_count >= MAX_INTERFACES)
        return -1;
    dst->locals[dst->local_count] = *src_loc;
    return dst->local_count++;
}

static int append_wan_unique(struct app_config *dst, const struct wan_config *src_wan) {
    int idx = find_wan_by_ifname(dst, src_wan->ifname);
    if (idx >= 0)
        return idx;
    if (dst->wan_count >= MAX_INTERFACES)
        return -1;
    dst->wans[dst->wan_count] = *src_wan;
    return dst->wan_count++;
}

static int policy_db_id_in_cfg(const struct app_config *cfg, int db_id, int before_count)
{
    if (!cfg || db_id <= 0)
        return 0;
    for (int i = 0; i < before_count && i < cfg->policy_count; i++) {
        if (cfg->policies[i].db_id == db_id)
            return 1;
    }
    return 0;
}

static int merge_append_policies(struct app_config *dst, const struct app_config *src,
                                 int src_profile_id, int *policy_map)
{
    int base = dst->policy_count;

    for (int i = 0; i < src->policy_count; i++) {
        const struct crypto_policy *cp = &src->policies[i];

        if (policy_db_id_in_cfg(dst, cp->db_id, base)) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: duplicate policy db_id=%d (already in merged config)\n",
                    src_profile_id, cp->db_id);
            return -1;
        }
    }

    if (dst->policy_count + src->policy_count > MAX_CRYPTO_POLICIES) {
        fprintf(stderr,
                "[VALIDATE] profile %d: policy table full (need %d slots)\n",
                src_profile_id, src->policy_count);
        return -1;
    }

    for (int i = 0; i < src->policy_count; i++) {
        policy_map[i] = dst->policy_count;
        dst->policies[dst->policy_count++] = src->policies[i];
    }
    return 0;
}

static int merge_one_config(struct app_config *dst, const struct app_config *src) {
    int local_map[MAX_INTERFACES];
    int wan_map[MAX_INTERFACES];
    memset(local_map, -1, sizeof(local_map));
    memset(wan_map, -1, sizeof(wan_map));

    int src_profile_id = src->profile_count > 0 ? src->profiles[0].id : -1;

    for (int i = 0; i < src->local_count; i++) {
        local_map[i] = append_local_unique(dst, &src->locals[i]);
        if (local_map[i] < 0)
            return -1;
    }
    for (int i = 0; i < src->wan_count; i++) {
        wan_map[i] = append_wan_unique(dst, &src->wans[i]);
        if (wan_map[i] < 0)
            return -1;
    }

    for (int pi = 0; pi < src->profile_count; pi++) {
        if (dst->profile_count >= MAX_PROFILES)
            return -1;
        struct profile_config *dp = &dst->profiles[dst->profile_count++];
        const struct profile_config *sp = &src->profiles[pi];
        int policy_map[MAX_CRYPTO_POLICIES];
        int iface_validate_failed = 0;

        memset(dp, 0, sizeof(*dp));
        memset(policy_map, -1, sizeof(policy_map));
        dp->id = sp->id;
        strncpy(dp->name, sp->name, sizeof(dp->name) - 1);
        dp->enabled = sp->enabled;

        for (int i = 0; i < sp->local_count; i++) {
            int sli = sp->local_indices[i];
            int merged_li;
            const char *ifname;

            if (sli < 0 || sli >= src->local_count) {
                iface_validate_failed = 1;
                continue;
            }
            merged_li = local_map[sli];
            if (merged_li < 0 || merged_li >= dst->local_count) {
                iface_validate_failed = 1;
                continue;
            }
            ifname = dst->locals[merged_li].ifname;
            if (if_nametoindex(ifname) == 0) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: skip LAN %s (interface not found)\n",
                        src_profile_id, ifname);
                iface_validate_failed = 1;
                continue;
            }
            if (lan_owner_profile(dst, merged_li, src_profile_id) > 0) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: skip LAN %s (already used by another profile)\n",
                        src_profile_id, ifname);
                iface_validate_failed = 1;
                continue;
            }
            if (dp->local_count >= MAX_PROFILE_INTERFACES) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: skip LAN %s (MAX_PROFILE_INTERFACES)\n",
                        src_profile_id, ifname);
                iface_validate_failed = 1;
                break;
            }
            dp->local_indices[dp->local_count++] = merged_li;
        }
        for (int i = 0; i < sp->wan_count; i++) {
            int swi = sp->wan_indices[i];
            int merged_wi;
            int owner;
            const char *ifname;

            if (swi < 0 || swi >= src->wan_count) {
                iface_validate_failed = 1;
                continue;
            }
            merged_wi = wan_map[swi];
            if (merged_wi < 0 || merged_wi >= dst->wan_count) {
                iface_validate_failed = 1;
                continue;
            }
            ifname = dst->wans[merged_wi].ifname;
            if (if_nametoindex(ifname) == 0) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: skip WAN %s (interface not found)\n",
                        src_profile_id, ifname);
                iface_validate_failed = 1;
                continue;
            }
            owner = config_wan_owner_profile(dst, merged_wi, src_profile_id);
            if (owner > 0) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: WAN %s already used by profile %d\n",
                        src_profile_id, ifname, owner);
                iface_validate_failed = 1;
                continue;
            }
            if (dp->wan_count >= MAX_PROFILE_INTERFACES) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: skip WAN %s (MAX_PROFILE_INTERFACES)\n",
                        src_profile_id, ifname);
                iface_validate_failed = 1;
                break;
            }
            dp->wan_indices[dp->wan_count] = merged_wi;
            dp->wan_bandwidth_weight[dp->wan_count] = sp->wan_bandwidth_weight[i];
            dp->wan_count++;
        }

        dp->bridge_enable = sp->bridge_enable;
        for (int bi = 0; bi < sp->bridge_count; bi++) {
            int src_li = sp->bridges[bi].local_idx;
            int src_wan_dp = sp->bridges[bi].wan_dp;
            int src_wi;
            int merged_li;
            int merged_wi;
            int merged_wan_dp;

            if (src_li < 0 || src_li >= src->local_count)
                continue;
            merged_li = local_map[src_li];
            if (merged_li < 0 || merged_li >= dst->local_count)
                continue;

            src_wi = config_wan_dp_to_cfg(src, src_wan_dp);
            if (src_wi < 0 || src_wi >= src->wan_count)
                continue;
            merged_wi = wan_map[src_wi];
            if (merged_wi < 0 || merged_wi >= dst->wan_count)
                continue;

            merged_wan_dp = config_wan_cfg_to_dp(dst, merged_wi);
            if (merged_wan_dp < 0)
                continue;
            if (dp->bridge_count >= MAX_BRIDGES_PER_PROFILE)
                break;

            dp->bridges[dp->bridge_count].local_idx = merged_li;
            dp->bridges[dp->bridge_count].wan_dp = merged_wan_dp;
            dp->bridge_count++;
        }

        if (iface_validate_failed) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: merge failed (duplicate or invalid LAN/WAN)\n",
                    src_profile_id);
            return -1;
        }

        if (merge_append_policies(dst, src, src_profile_id, policy_map) != 0)
            return -1;

        for (int i = 0; i < sp->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
            int spi = sp->policy_indices[i];
            if (spi < 0 || spi >= src->policy_count)
                continue;
            int mpi = policy_map[spi];
            if (mpi < 0)
                continue;
            if (dp->policy_count >= MAX_CRYPTO_POLICIES)
                break;
            dp->policy_indices[dp->policy_count++] = mpi;
        }
    }
    return 0;
}

int build_merged_config(struct app_config *out_cfg, const int *ids, int id_count, const char *db_pass) {
    (void)db_pass;
    sig_pqc_prepare_reload();
    struct app_config merged;
    memset(&merged, 0, sizeof(merged));
    strncpy(merged.bpf_file, "lib/lan.o", sizeof(merged.bpf_file) - 1);
    strncpy(merged.bpf_wan_file, "lib/wan.o", sizeof(merged.bpf_wan_file) - 1);

    for (int i = 0; i < id_count; i++) {
        struct app_config tmp;
        if (config_load_from_db(&tmp, ids[i], NULL) != 0)
            return -1;
        if (merge_one_config(&merged, &tmp) != 0)
            return -1;
    }

    if (config_apply_crypto_from_policies(&merged) != 0)
        return -1;

    if (config_validate(&merged) != 0)
        return -1;
    *out_cfg = merged;
    sig_pqc_finalize_reload();
    return 0;
}