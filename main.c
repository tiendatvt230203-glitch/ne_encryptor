#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>
#include <pthread.h>

#include "config.h"
#include "db_env.h"
#include "db_runtime.h"
#include "forwarder.h"
#include "forwarder_reload.h"
#include "interface.h"
#include "main_diag.h"
#include "profile_iface_xdp.h"
#include "pqc_handshake.h"
#include "traffic_crypto.h"
#define NOTIFY_CHANNEL "xdp_start"
#define MAX_ACTIVE_PROFILE_IDS 32

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_stop_logged = 0;
static volatile sig_atomic_t g_stop_signal_count = 0;

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop_signal_count++;
    g_stop_requested = 1;
    forwarder_stop();
    if (!g_stop_logged) {
        g_stop_logged = 1;
        fprintf(stderr, "\n[STOP] shutting down (Ctrl+C / SIGTERM)\n");
    }
    if (g_stop_signal_count >= 2) {
        fprintf(stderr, "[STOP] shutdown in progress (do not spam Ctrl+C)\n");
    }
}

static int parse_notify_profile_id(const char *payload) {
    if (!payload || !*payload)
        return -1;
    char *end = NULL;
    long v = strtol(payload, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > INT_MAX)
        return -1;
    return (int)v;
}

struct runtime_state {
    pthread_t thread;
    int has_thread;
    int running;
    struct forwarder fwd;
    struct app_config cfg_slots[2];
    int active_slot;
};

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s               # daemon mode (LISTEN %s)\n"
            "  %s -gi            # generate new identity key and load into RAM\n"
            "  %s -check-identity # check PQC DB identity integrity and link to RAM cache\n"
            "  %s -id <ID>       # notify daemon to apply config already stored in DB\n"
            "  %s -check [ID]    # check database config consistency\n"
            "  %s -r <policy_id> # trigger manual handshake retry for policy\n",
            prog, NOTIFY_CHANNEL, prog, prog, prog, prog, prog);
}

static int parse_profile_id_token(const char *token, int *out_id) {
    if (!token || !*token)
        return -1;
    char *end = NULL;
    long v = strtol(token, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > INT_MAX)
        return -1;
    *out_id = (int)v;
    return 0;
}

static int parse_startup_profile_id(int argc, char **argv, int *out_id) {
    *out_id = -1;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "-id") == 0) {
            if (*out_id >= 0) {
                fprintf(stderr, "[FATAL] -id specified more than once\n");
                return -1;
            }
            if (i + 1 >= argc) {
                fprintf(stderr, "[FATAL] -id requires ne_profiles.id\n");
                return -1;
            }
            if (parse_profile_id_token(argv[++i], out_id) != 0) {
                fprintf(stderr, "[FATAL] invalid ne_profiles.id: %s\n", argv[i]);
                return -1;
            }
            continue;
        }

        if (strncmp(arg, "-id=", 4) == 0) {
            if (*out_id >= 0) {
                fprintf(stderr, "[FATAL] -id specified more than once\n");
                return -1;
            }
            const char *id_str = arg + 4;
            if (parse_profile_id_token(id_str, out_id) != 0) {
                fprintf(stderr, "[FATAL] invalid ne_profiles.id: %s\n", id_str);
                return -1;
            }
            continue;
        }

        fprintf(stderr, "[FATAL] unknown option: %s\n", arg);
        return -1;
    }
    return 0;
}

/* 1 = newly added, 0 = already in set, -1 = error (set full) */
static int active_ids_add(int *active_ids, int *active_id_count, int id) {
    for (int i = 0; i < *active_id_count; i++) {
        if (active_ids[i] == id)
            return 0;
    }
    if (*active_id_count >= MAX_ACTIVE_PROFILE_IDS) {
        fprintf(stderr, "[WARN] active profile set is full, ignoring id=%d\n", id);
        return -1;
    }
    active_ids[(*active_id_count)++] = id;
    return 1;
}

static int active_ids_remove(int *active_ids, int *active_id_count, int id) {
    int w = 0;
    int removed = 0;

    for (int i = 0; i < *active_id_count; i++) {
        if (active_ids[i] == id) {
            removed = 1;
            continue;
        }
        active_ids[w++] = active_ids[i];
    }
    *active_id_count = w;
    return removed;
}

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format,
                               va_list args) {
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static int notify_profile_load(int profile_id) {
    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[ERR] DB: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT pg_notify('%s', '%d')", NOTIFY_CHANNEL, profile_id);
    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[ERR] pg_notify failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return -1;
    }
    PQclear(res);
    PQfinish(conn);
    return 0;
}

static void *forwarder_thread_main(void *arg) {
    forwarder_pin_cpu();
    struct runtime_state *rt = (struct runtime_state *)arg;
    if (forwarder_init(&rt->fwd, &rt->cfg_slots[rt->active_slot]) != 0) {
        forwarder_cleanup(&rt->fwd);
        if (forwarder_should_stop()) {
            fprintf(stderr, "[STOP] forwarder init aborted\n");
        } 
        else {
            fprintf(stderr, "[FATAL] forwarder_init failed\n");
        }
        rt->running = 0;
        return NULL;
    }
    if (forwarder_should_stop()) {
        fprintf(stderr, "[STOP] forwarder init aborted\n");
        forwarder_cleanup(&rt->fwd);
        rt->running = 0;
        return NULL;
    }
    if (forwarder_should_stop()) {
        forwarder_cleanup(&rt->fwd);
        rt->running = 0;
        return NULL;
    }
    rt->running = 1;
    forwarder_run(&rt->fwd);
    rt->running = 0;
    return NULL;
}

static int runtime_start(struct runtime_state *rt, const struct app_config *cfg) {
    rt->active_slot = 0;
    rt->cfg_slots[rt->active_slot] = *cfg;
    rt->running = 0;
    if (pthread_create(&rt->thread, NULL, forwarder_thread_main, rt) != 0) {
        fprintf(stderr, "[FATAL] failed to create forwarder thread\n");
        return -1;
    }
    rt->has_thread = 1;
    return 0;
}

static int runtime_stop_forwarder(struct runtime_state *rt);

static int policy_fields_equal(const struct crypto_policy *a,
                               const struct crypto_policy *b)
{
    return a->id == b->id &&
           a->db_id == b->db_id &&
           a->priority == b->priority &&
           a->action == b->action &&
           a->protocol == b->protocol &&
           a->src_port_from == b->src_port_from &&
           a->src_port_to == b->src_port_to &&
           a->dst_port_from == b->dst_port_from &&
           a->dst_port_to == b->dst_port_to &&
           a->src_any == b->src_any &&
           a->dst_any == b->dst_any &&
           a->src_negate == b->src_negate &&
           a->dst_negate == b->dst_negate &&
           a->src_net == b->src_net &&
           a->src_mask == b->src_mask &&
           a->dst_net == b->dst_net &&
           a->dst_mask == b->dst_mask &&
           a->crypto_mode == b->crypto_mode &&
           a->aes_bits == b->aes_bits &&
           memcmp(a->key, b->key, AES_KEY_LEN) == 0;
}

static const struct crypto_policy *policy_by_db_id(const struct app_config *cfg,
                                                   int db_id)
{
    for (int i = 0; i < cfg->policy_count; i++) {
        if (cfg->policies[i].db_id == db_id)
            return &cfg->policies[i];
    }
    return NULL;
}

static void log_policy_db_ids(const char *tag, const struct app_config *cfg)
{
    if (!cfg)
        return;
    fprintf(stderr, "%s policy db_ids(%d):", tag, cfg->policy_count);
    for (int i = 0; i < cfg->policy_count; i++)
        fprintf(stderr, " %d", cfg->policies[i].db_id);
    fprintf(stderr, "\n");
}

static int policies_db_unchanged(const struct app_config *old,
                                 const struct app_config *new)
{
    if (old->policy_count != new->policy_count)
        return 0;
    for (int i = 0; i < old->policy_count; i++) {
        int db_id = old->policies[i].db_id;
        const struct crypto_policy *np = policy_by_db_id(new, db_id);
        if (!np || !policy_fields_equal(&old->policies[i], np))
            return 0;
    }
    for (int i = 0; i < new->policy_count; i++) {
        int db_id = new->policies[i].db_id;
        const struct crypto_policy *op = policy_by_db_id(old, db_id);
        if (!op || !policy_fields_equal(op, &new->policies[i]))
            return 0;
    }
    return 1;
}

static const struct local_config *local_by_ifname(const struct app_config *cfg,
                                                  const char *ifname)
{
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return &cfg->locals[i];
    }
    return NULL;
}

static int local_db_equal(const struct local_config *a, const struct local_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0;
}

static const struct wan_config *wan_by_ifname(const struct app_config *cfg,
                                              const char *ifname)
{
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return &cfg->wans[i];
    }
    return NULL;
}

static int wan_db_equal(const struct wan_config *a, const struct wan_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0 &&
           a->dst_ip == b->dst_ip &&
           a->window_size == b->window_size &&
           a->dataplane == b->dataplane;
}

static int profile_db_unchanged(const struct profile_config *old,
                                const struct profile_config *new,
                                const struct app_config *ocfg,
                                const struct app_config *ncfg)
{
    if (old->id != new->id ||
        old->enabled != new->enabled ||
        old->policy_count != new->policy_count ||
        old->local_count != new->local_count ||
        old->wan_count != new->wan_count ||
        strcmp(old->name, new->name) != 0 ||
        strcmp(old->local_identity_fingerprint, new->local_identity_fingerprint) != 0 ||
        strcmp(old->peer_fingerprint, new->peer_fingerprint) != 0 ||
        old->pqc_is_initiator != new->pqc_is_initiator ||
        old->has_pqc_identity != new->has_pqc_identity ||
        strcmp(old->pqc_peer_pub, new->pqc_peer_pub) != 0)
        return 0;

    for (int i = 0; i < old->policy_count; i++) {
        int odb = ocfg->policies[old->policy_indices[i]].db_id;
        int found = 0;
        for (int j = 0; j < new->policy_count; j++) {
            int ndb = ncfg->policies[new->policy_indices[j]].db_id;
            if (odb == ndb) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    for (int j = 0; j < new->policy_count; j++) {
        int ndb = ncfg->policies[new->policy_indices[j]].db_id;
        int found = 0;
        for (int i = 0; i < old->policy_count; i++) {
            int odb = ocfg->policies[old->policy_indices[i]].db_id;
            if (odb == ndb) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }

    for (int i = 0; i < old->local_count; i++) {
        if (old->local_indices[i] != new->local_indices[i])
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        if (old->wan_indices[i] != new->wan_indices[i] ||
            old->wan_bandwidth_weight[i] != new->wan_bandwidth_weight[i])
            return 0;
    }
    return 1;
}

static int config_db_unchanged(const struct app_config *old,
                               const struct app_config *new)
{
    if (!old || !new)
        return 0;

    if (old->local_count != new->local_count ||
        old->wan_count != new->wan_count ||
        old->policy_count != new->policy_count ||
        old->profile_count != new->profile_count ||
        old->crypto_enabled != new->crypto_enabled ||
        old->encrypt_layer != new->encrypt_layer ||
        old->fake_protocol != new->fake_protocol ||
        old->fake_ethertype_ipv4 != new->fake_ethertype_ipv4 ||
        old->crypto_mode != new->crypto_mode ||
        old->aes_bits != new->aes_bits ||
        memcmp(old->crypto_key, new->crypto_key, AES_KEY_LEN) != 0 ||
        strcmp(old->bpf_file, new->bpf_file) != 0 ||
        strcmp(old->bpf_wan_file, new->bpf_wan_file) != 0)
        return 0;

    for (int i = 0; i < old->local_count; i++) {
        const struct local_config *nl =
            local_by_ifname(new, old->locals[i].ifname);
        if (!nl || !local_db_equal(&old->locals[i], nl))
            return 0;
    }

    for (int i = 0; i < old->wan_count; i++) {
        const struct wan_config *nw = wan_by_ifname(new, old->wans[i].ifname);
        if (!nw || !wan_db_equal(&old->wans[i], nw))
            return 0;
    }

    if (!policies_db_unchanged(old, new))
        return 0;

    for (int i = 0; i < old->profile_count; i++) {
        const struct profile_config *op = &old->profiles[i];
        const struct profile_config *np = NULL;
        for (int j = 0; j < new->profile_count; j++) {
            if (new->profiles[j].id == op->id) {
                np = &new->profiles[j];
                break;
            }
        }
        if (!np || !profile_db_unchanged(op, np, old, new))
            return 0;
    }

    return 1;
}

static int profiles_fully_unchanged(const struct app_config *old,
                                    const struct app_config *new)
{
    if (old->profile_count != new->profile_count)
        return 0;
    for (int i = 0; i < old->profile_count; i++) {
        const struct profile_config *op = &old->profiles[i];
        const struct profile_config *np = NULL;
        for (int j = 0; j < new->profile_count; j++) {
            if (new->profiles[j].id == op->id) {
                np = &new->profiles[j];
                break;
            }
        }
        if (!np || !profile_db_unchanged(op, np, old, new))
            return 0;
    }
    return 1;
}

/* LAN/WAN rows from Postgres unchanged (client MAC is not stored in DB). */
static int lan_wan_db_unchanged(const struct app_config *old,
                                const struct app_config *new)
{
    if (!old || !new)
        return 0;
    if (old->local_count != new->local_count ||
        old->wan_count != new->wan_count)
        return 0;

    for (int i = 0; i < old->local_count; i++) {
        const struct local_config *nl =
            local_by_ifname(new, old->locals[i].ifname);
        if (!nl || !local_db_equal(&old->locals[i], nl))
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        const struct wan_config *nw = wan_by_ifname(new, old->wans[i].ifname);
        if (!nw || !wan_db_equal(&old->wans[i], nw))
            return 0;
    }
    return 1;
}

/* Same ifnames; only WAN window tuning changed — no policy/profile traffic change. */
static int runtime_tuning_only_change(const struct app_config *old,
                                      const struct app_config *new)
{
    if (!old || !new || lan_wan_db_unchanged(old, new))
        return 0;
    if (!forwarder_same_topology(old, new))
        return 0;
    if (!policies_db_unchanged(old, new))
        return 0;
    return profiles_fully_unchanged(old, new);
}

static int apply_active_configs(struct runtime_state *rt, const int *active_ids,
                                int active_id_count, int trigger_id) {
    struct app_config *merged_cfg = calloc(1, sizeof(*merged_cfg));
    if (!merged_cfg) {
        fprintf(stderr, "[FATAL] out of memory building merged config\n");
        return -1;
    }
    if (build_merged_config(merged_cfg, active_ids, active_id_count, NULL) != 0) {
        fprintf(stderr,
                "[ERR] profile %d: failed to load config from Postgres (see [DB] lines above)\n",
                trigger_id);
        free(merged_cfg);
        return -1;
    }

    if (!rt->has_thread) {
        fprintf(stderr, "[LOAD] active:");
        for (int i = 0; i < active_id_count; i++)
            fprintf(stderr, " %d", active_ids[i]);
        fprintf(stderr, "\n");
        main_diag_log_db_apply(merged_cfg, trigger_id, NULL);
        int rc = runtime_start(rt, merged_cfg);
        free(merged_cfg);
        return rc != 0 ? -1 : 0;
    }

    int next_slot = 1 - rt->active_slot;
    const struct app_config *prev_cfg = &rt->cfg_slots[rt->active_slot];

    rt->cfg_slots[next_slot] = *merged_cfg;
    free(merged_cfg);

    if (config_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot])) {
        fprintf(stderr,
                "[DB] profile %d — no change on first read (Postgres may not have committed yet), retry...\n",
                trigger_id);
        fflush(stderr);
        usleep(500000);
        if (build_merged_config(&rt->cfg_slots[next_slot], active_ids,
                                active_id_count, NULL) != 0) {
            fprintf(stderr,
                    "[ERR] profile %d: DB reload retry failed (see [DB] lines above)\n",
                    trigger_id);
            return -1;
        }
    }

    if (config_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot])) {
        log_policy_db_ids("[DB] Postgres", &rt->cfg_slots[next_slot]);
        log_policy_db_ids("[DB] running", prev_cfg);
        main_diag_log_no_update(trigger_id, prev_cfg);
        return 0;
    }

    int policy_only = lan_wan_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot]);
    int topo_ok = forwarder_same_topology(prev_cfg, &rt->cfg_slots[next_slot]);

    if (policy_only)
        main_diag_log_db_policy_apply(&rt->cfg_slots[next_slot], trigger_id, prev_cfg);
    else
        main_diag_log_db_apply(&rt->cfg_slots[next_slot], trigger_id, prev_cfg);

    if (!topo_ok) {
        struct app_config *new_cfg = &rt->cfg_slots[next_slot];
        int incremental_ok = 0;

        if (profile_iface_xdp_is_add_only(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[RELOAD] profile %d — incremental LAN/WAN attach (add-only)\n",
                    trigger_id);
            fflush(stderr);
            /* #region agent log */
            fprintf(stderr, "[RELOAD-DBG] C path_add_only trigger=%d\n", trigger_id);
            fflush(stderr);
            /* #endregion */
            if (profile_iface_xdp_apply_add(&rt->fwd, new_cfg, trigger_id) == 0)
                incremental_ok = 1;
            else
                fprintf(stderr,
                        "[RELOAD] incremental attach failed — keeping current dataplane\n");
        } else if (profile_iface_xdp_can_delta(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[RELOAD] profile %d — incremental LAN/WAN delta\n",
                    trigger_id);
            fflush(stderr);
            /* #region agent log */
            fprintf(stderr, "[RELOAD-DBG] C path_delta trigger=%d\n", trigger_id);
            fflush(stderr);
            /* #endregion */
            if (profile_iface_xdp_apply_delta(&rt->fwd, new_cfg, trigger_id) == 0)
                incremental_ok = 1;
            else
                fprintf(stderr,
                        "[RELOAD] incremental delta failed — keeping current dataplane\n");
        } else if (profile_iface_xdp_can_add(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[RELOAD] profile %d — incremental LAN/WAN attach\n",
                    trigger_id);
            fflush(stderr);
            /* #region agent log */
            fprintf(stderr, "[RELOAD-DBG] C path_add trigger=%d\n", trigger_id);
            fflush(stderr);
            /* #endregion */
            if (profile_iface_xdp_apply_add(&rt->fwd, new_cfg, trigger_id) == 0)
                incremental_ok = 1;
            else
                fprintf(stderr,
                        "[RELOAD] incremental attach failed — keeping current dataplane\n");
        } else if (profile_iface_xdp_can_remove(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[RELOAD] profile %d — incremental LAN/WAN detach\n",
                    trigger_id);
            fflush(stderr);
            /* #region agent log */
            fprintf(stderr, "[RELOAD-DBG] C path_remove trigger=%d\n", trigger_id);
            fflush(stderr);
            /* #endregion */
            if (profile_iface_xdp_apply_remove(&rt->fwd, new_cfg, trigger_id) == 0)
                incremental_ok = 1;
            else
                fprintf(stderr,
                        "[RELOAD] incremental detach failed — keeping current dataplane\n");
        } else if (forwarder_is_wan_only_removal(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[RELOAD] profile %d — WAN removed, drain %.1fs then detach (no hard cut)\n",
                    trigger_id, (double)FORWARDER_WAN_DRAIN_SEC);
            fflush(stderr);
            if (forwarder_reload_wan_removal(&rt->fwd, new_cfg) == 0)
                incremental_ok = 1;
            else
                fprintf(stderr,
                        "[RELOAD] WAN drain reload failed — keeping current dataplane\n");
        }

        if (incremental_ok) {
            rt->active_slot = next_slot;
            fprintf(stderr, "[RELOAD] OK profile %d — applied (incremental)\n", trigger_id);
            main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
            fflush(stderr);
            return 0;
        }

        if (profile_iface_xdp_can_add(prev_cfg, new_cfg) ||
            profile_iface_xdp_can_remove(prev_cfg, new_cfg) ||
            profile_iface_xdp_can_delta(prev_cfg, new_cfg) ||
            forwarder_is_wan_only_removal(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[ERR] profile %d: incremental reload failed — running dataplane unchanged\n",
                    trigger_id);
            fflush(stderr);
            return -1;
        }

        fprintf(stderr,
                "[RELOAD] profile %d — LAN/WAN topology changed — full dataplane restart\n",
                trigger_id);
        fflush(stderr);
        rt->active_slot = next_slot;
        if (runtime_stop_forwarder(rt) != 0)
            return -1;
        if (g_stop_requested)
            return -1;
        if (runtime_start(rt, &rt->cfg_slots[rt->active_slot]) != 0)
            return -1;
        fprintf(stderr, "[RELOAD] OK profile %d — applied (full restart)\n", trigger_id);
        main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
        fflush(stderr);
        return 0;
    }

    if (!policy_only) {
        if (runtime_tuning_only_change(prev_cfg, &rt->cfg_slots[next_slot])) {
            fprintf(stderr,
                    "[RELOAD] profile %d — LAN/WAN tuning only (hot reload, traffic continues)\n",
                    trigger_id);
            fflush(stderr);
            if (forwarder_reload_config(&rt->fwd, &rt->cfg_slots[next_slot]) == 0) {
                rt->active_slot = next_slot;
                fprintf(stderr,
                        "[RELOAD] OK profile %d — applied (tuning hot reload)\n",
                        trigger_id);
                main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot],
                                             trigger_id, 1, 0);
                fflush(stderr);
                return 0;
            }
            fprintf(stderr,
                    "[RELOAD] tuning hot reload failed; full dataplane restart\n");
            fflush(stderr);
        } else {
            fprintf(stderr,
                    "[RELOAD] profile %d — LAN/WAN settings changed — full dataplane restart\n",
                    trigger_id);
            fflush(stderr);
        }
        rt->active_slot = next_slot;
        if (runtime_stop_forwarder(rt) != 0)
            return -1;
        if (g_stop_requested)
            return -1;
        if (runtime_start(rt, &rt->cfg_slots[rt->active_slot]) != 0)
            return -1;
        fprintf(stderr, "[RELOAD] OK profile %d — applied (full restart)\n", trigger_id);
        main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
        fflush(stderr);
        return 0;
    }

    fprintf(stderr,
            "[RELOAD] profile %d — policies/crypto only (LAN/WAN ifaces unchanged)\n",
            trigger_id);
    fflush(stderr);

    if (forwarder_reload_config(&rt->fwd, &rt->cfg_slots[next_slot]) == 0) {
        rt->active_slot = next_slot;
        fprintf(stderr, "[RELOAD] OK profile %d — applied (hot reload)\n", trigger_id);
        fprintf(stderr, "[RELOAD] active:");
        for (int i = 0; i < active_id_count; i++)
            fprintf(stderr, " %d", active_ids[i]);
        fprintf(stderr, "\n");
        main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 1);
        fflush(stderr);
        return 0;
    }
    fprintf(stderr,
            "[RELOAD] hot reload failed (see lines above); full dataplane restart\n");
    fflush(stderr);
    if (runtime_stop_forwarder(rt) != 0)
        return -1;
    if (g_stop_requested)
        return -1;
    rt->active_slot = next_slot;
    if (runtime_start(rt, &rt->cfg_slots[rt->active_slot]) != 0)
        return -1;
    fprintf(stderr, "[RELOAD] OK profile %d — applied (full restart)\n", trigger_id);
    main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
    fflush(stderr);
    return 0;
}

static const struct app_config *runtime_active_cfg(struct runtime_state *rt)
{
    if (rt->fwd.cfg)
        return rt->fwd.cfg;
    return &rt->cfg_slots[rt->active_slot];
}

static int runtime_stop_forwarder(struct runtime_state *rt) {
    if (!rt->has_thread)
        return 0;

    const struct app_config *cfg = runtime_active_cfg(rt);
    fprintf(stderr, "[STOP] profile-xdp detach (all LAN/WAN)...\n");
    fflush(stderr);
    profile_iface_xdp_detach_config(cfg);

    fprintf(stderr, "[STOP] stopping dataplane...\n");
    fflush(stderr);
    forwarder_stop();
    forwarder_shutdown_resources();
    pthread_join(rt->thread, NULL);
    forwarder_cleanup(&rt->fwd);
    profile_iface_xdp_detach_config(cfg);
    interface_promisc_off_config(cfg);
    fprintf(stderr, "[STOP] done\n");
    fflush(stderr);
    rt->has_thread = 0;
    rt->running = 0;
    return 0;
}


static int load_profile_and_run(struct runtime_state *rt,
                                int *active_ids,
                                int *active_id_count,
                                int profile_id) {
    if (!rt->has_thread)
        *active_id_count = 0;

    int added = active_ids_add(active_ids, active_id_count, profile_id);
    if (added < 0)
        return -1;
    /* Even if profile is already active, force rebuild to apply DB updates. */
    if (apply_active_configs(rt, active_ids, *active_id_count, profile_id) != 0) {
        if (added == 1)
            active_ids_remove(active_ids, active_id_count, profile_id);
        return -1;
    }
    return 0;
}

static int handle_profile_notify(struct runtime_state *rt,
                                 int *active_ids,
                                 int *active_id_count,
                                 int profile_id) {
    if (g_stop_requested)
        return 0;

    if (ne_profile_id_exists(profile_id) == 0) {
        int lr = load_profile_and_run(rt, active_ids, active_id_count, profile_id);
        if (lr != 0) {
            fprintf(stderr, "[ERR] profile %d: load failed\n", profile_id);
            return -1;
        }
        return 0;
    }

    if (!active_ids_remove(active_ids, active_id_count, profile_id)) {
        fprintf(stderr, "[DELETE] profile %d (not in DB)\n", profile_id);
        return 0;
    }

    fprintf(stderr, "[DELETE] profile %d removed\n", profile_id);

    if (*active_id_count == 0)
        return runtime_stop_forwarder(rt);

    if (apply_active_configs(rt, active_ids, *active_id_count, profile_id) != 0) {
        fprintf(stderr, "[ERR] profile %d: unload reload failed\n", profile_id);
        return -1;
    }
    return 0;
}
static void handle_shutdown_signal(int sig) {
    (void)sig;
    sig_pqc_cleanup_ipc();
    exit(0);
}

int main(int argc, char **argv) {
    int ipc_rc = sig_pqc_handle_ipc_cli(argc, argv);
    if (ipc_rc >= 0) {
        return ipc_rc;
    }

    if (argc > 1 && strcmp(argv[1], "-gi") == 0) {
        sig_pqc_handle_gen_identity();
        return 0;
    }

    setbuf(stderr, NULL);
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "[FATAL] trf_pqc_init_global failed\n");
        return 1;
    }
    sig_pqc_load_keys_from_disk();
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        fprintf(stderr, "network-encryptor\n");
        return 0;
    }

    int profile_id = -1;
    if (parse_startup_profile_id(argc, argv, &profile_id) != 0) {
        usage(argv[0]);
        return 1;
    }

    if (profile_id >= 0) {
        if (load_ne_env() != 0) {
            fprintf(stderr, "[FATAL] DB env not loaded from " NE_ENV_FILE "\n");
            return 1;
        }
        int exists = (ne_profile_id_exists(profile_id) == 0);
        if (notify_profile_load(profile_id) != 0)
            return 1;
        if (exists) {
            fprintf(stderr,
                    "[NOTIFY] sent profile %d to channel %s (OK — not an error)\n",
                    profile_id, NOTIFY_CHANNEL);
            fprintf(stderr,
                    "  Reload logs print on the **daemon** terminal (%s with no -id), not here.\n",
                    argv[0]);
            fprintf(stderr,
                    "  If daemon shows nothing: start daemon, or DB unchanged / daemon hung on reload.\n");
        } else {
            fprintf(stderr, "[DELETE] notify profile %d (not in DB)\n", profile_id);
        }
        return 0;
    }

    if (argc > 1) {
        fprintf(stderr, "[FATAL] unknown arguments (got %d)\n", argc - 1);
        usage(argv[0]);
        return 1;
    }

    if (load_ne_env() != 0) {
        fprintf(stderr, "[FATAL] DB env not loaded from " NE_ENV_FILE "\n");
        return 1;
    }

    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0) {
        fprintf(stderr,
                "[FATAL] Missing POSTGRES_SERVER/PORT/USER/DB/PASSWORD in " NE_ENV_FILE "\n");
        return 1;
    }
    signal(SIGTERM, handle_shutdown_signal);
    signal(SIGINT, handle_shutdown_signal);

    sig_pqc_start_ipc_server();
    libbpf_set_print(libbpf_print_silent);
    fprintf(stderr, "[NE-BUILD] umem-rehome-v2 DRV-only (journal marker — verify deploy)\n");
    fflush(stderr);

    struct sigaction sa = { .sa_handler = on_stop_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    forwarder_pin_cpu();
    PGconn *listen_conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(listen_conn));
        fprintf(stderr,
                "[DB] tried host=%s port=%s dbname=%s user=%s (from " NE_ENV_FILE ")\n",
                pg.values[0], pg.values[1], pg.values[2], pg.values[3]);
        PQfinish(listen_conn);
        return 1;
    }
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    fprintf(stderr, "[DAEMON] listening %s — use %s -id <id>\n", NOTIFY_CHANNEL, argv[0]);

    struct runtime_state *rt = calloc(1, sizeof(*rt));
    if (!rt) {
        fprintf(stderr, "[FATAL] out of memory for runtime state\n");
        PQfinish(listen_conn);
        return 1;
    }

    int active_ids[MAX_ACTIVE_PROFILE_IDS];
    int active_id_count = 0;

    while (!g_stop_requested) {
        int pq_fd = PQsocket(listen_conn);
        if (pq_fd < 0) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
            usleep(200000);
            continue;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        struct timeval tv = { .tv_sec = g_stop_requested ? 0 : 1,
                              .tv_usec = g_stop_requested ? 200000 : 0 };
        int sr = select(pq_fd + 1, &rfds, NULL, NULL, &tv);
        if (sr < 0) {
            if (errno == EINTR) {
                if (g_stop_requested)
                    break;
                continue;
            }
            usleep(200000);
            continue;
        }
        if (sr == 0)
            continue;

        if (!FD_ISSET(pq_fd, &rfds))
            continue;

        PQconsumeInput(listen_conn);
        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            int id = parse_notify_profile_id(notify->extra);
            if (id <= 0) {
                fprintf(stderr,
                        "[WARN] ignoring NOTIFY with invalid id payload: \"%s\"\n",
                        notify->extra ? notify->extra : "");
            } else {
                fprintf(stderr, "\n[NOTIFY] profile %d\n", id);
                fflush(stderr);
                (void)handle_profile_notify(rt, active_ids, &active_id_count, id);
            }
            PQfreemem(notify);
        }

        if (PQstatus(listen_conn) != CONNECTION_OK) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
        }
    }

    if (rt->has_thread) {
        runtime_stop_forwarder(rt);
    }
    free(rt);
    PQfinish(listen_conn);
    trf_pqc_cleanup();
    return 0;
}