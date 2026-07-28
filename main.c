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
#include "iface_runtime.h"
#include "db_crud_cli.h"
#include "pqc_handshake.h"
#include "pqc_ipc.h"
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

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s               # daemon (passive LISTEN %s; no auto DB load)\n"
            "  %s -gi            # generate new identity key and load into RAM\n"
            "  %s -check-identity # check PQC DB identity integrity and link to RAM cache\n"
            "  %s -id <ID>       # notify daemon to apply config already stored in DB\n"
            "  %s -check [ID]    # check database config consistency\n"
            "  %s -r <policy_id> # trigger manual handshake retry for policy\n"
            "\n"
            "  %s -profile-create  -name <name> [-bridge-enable 0|1]\n"
            "  %s -profile-update  -id <id> [-name <name>] [-bridge-enable 0|1]\n"
            "  %s -profile-delete  -id <id>\n"
            "  %s -profile-list\n"
            "  %s -lan-add  -id <profile_id> -if <ifname>\n"
            "  %s -lan-del  -id <profile_id> -if <ifname>\n"
            "  %s -wan-add     -id <profile_id> -if <ifname> [-dst-ip <ip>] [-weight <0-100>]\n"
            "  %s -wan-update  -id <profile_id> -if <ifname> [-dst-ip <ip>] [-weight <0-100>]\n"
            "  %s -wan-del     -id <profile_id> -if <ifname>\n",
            prog, NOTIFY_CHANNEL, prog, prog, prog, prog, prog,
            prog, prog, prog, prog, prog, prog, prog, prog, prog);
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


static int load_profile_and_run(struct ne_iface_runtime *rt,
                                int *active_ids,
                                int *active_id_count,
                                int profile_id) {
    if (!rt->has_thread)
        *active_id_count = 0;

    int added = active_ids_add(active_ids, active_id_count, profile_id);
    if (added < 0)
        return -1;
    if (ne_iface_runtime_apply(rt, active_ids, *active_id_count, profile_id) != 0) {
        if (added == 1)
            active_ids_remove(active_ids, active_id_count, profile_id);
        return -1;
    }
    return 0;
}

static int handle_profile_notify(struct ne_iface_runtime *rt,
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
        return ne_iface_runtime_stop_forwarder(rt);

    if (ne_iface_runtime_apply(rt, active_ids, *active_id_count, profile_id) != 0) {
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

    if (argc > 1) {
        int crud_rc = ne_db_crud_cli_run(argc, argv);
        if (crud_rc >= 0)
            return crud_rc;
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
    fprintf(stderr, "[NE-BUILD] br-arp-noflood-data-flood-v1 (journal marker — verify deploy)\n");
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

    struct ne_iface_runtime *rt = calloc(1, sizeof(*rt));
    if (!rt) {
        fprintf(stderr, "[FATAL] out of memory for runtime state\n");
        PQfinish(listen_conn);
        return 1;
    }
    ne_iface_runtime_init(rt, &g_stop_requested);

    int active_ids[MAX_ACTIVE_PROFILE_IDS];
    int active_id_count = 0;

    fprintf(stderr,
            "[DAEMON] passive — no auto DB load; use %s -id <id> (LISTEN %s)\n",
            argv[0], NOTIFY_CHANNEL);
    fflush(stderr);

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
        ne_iface_runtime_stop_forwarder(rt);
    }
    free(rt);
    PQfinish(listen_conn);
    trf_pqc_cleanup();
    return 0;
}