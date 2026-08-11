#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/dataplane_util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAC_PURGE_LOG_INTERVAL_MS 10000ull
#define MAC_LAN_LOG_DIR           "/var/log/NE"
#define MAC_LAN_LOG_PATH          MAC_LAN_LOG_DIR "/mac_lan.log"
#define MAC_LAN_LOG_TMP           MAC_LAN_LOG_DIR "/mac_lan.log.tmp"
#define ETH_HEADER_SIZE           14u

enum mac_upsert_result {
    MAC_UPSERT_REFRESH = 0,
    MAC_UPSERT_NEW,
    MAC_UPSERT_MOVE,
};

static uint64_t g_last_purge_log_ms;
static uint64_t g_last_mismatch_log_ms;

static void mac_fdb_persist_save_locked(const struct mac_learn_table *t);
static int mac_fdb_persist_load_locked(struct mac_learn_table *t,
                                       const struct forwarder *fwd);

static void log_mac_fdb_snapshot_locked(const struct mac_learn_table *t)
{
    char line[768];
    size_t pos = 0;
    int n;

    if (!t)
        return;

    n = snprintf(line, sizeof(line), "[MAC-FDB] %d:", t->count);
    if (n < 0)
        return;
    pos = (size_t)n;

    if (t->count == 0) {
        snprintf(line + pos, sizeof(line) - pos, " (empty)");
        pos = strlen(line);
    } else {
        for (int i = 0; i < t->count; i++) {
            const struct mac_learn_entry *e = &t->list[i];
            int w;

            w = snprintf(line + pos, sizeof(line) - pos,
                         "%s%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
                         (i == 0) ? " " : " |",
                         e->ifname[0] ? e->ifname : "-",
                         e->mac[0], e->mac[1], e->mac[2],
                         e->mac[3], e->mac[4], e->mac[5]);
            if (w < 0 || (size_t)w >= sizeof(line) - pos) {
                pos = sizeof(line) - 1;
                break;
            }
            pos += (size_t)w;
        }
    }

    fprintf(stderr, "%s\n", line);
    fflush(stderr);
}

static void log_mac_fmt(const char *event, enum mac_learn_src src,
                        const uint8_t mac[MAC_LEN], const char *ifname)
{
    (void)src;
    fprintf(stderr,
            "[MAC] %-5s %02x:%02x:%02x:%02x:%02x:%02x @%s\n",
            event,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ifname ? ifname : "-");
    fflush(stderr);
}

static void log_mac_move(struct mac_learn_table *t, enum mac_learn_src src,
                         const uint8_t mac[MAC_LEN],
                         const char *old_ifname, const char *new_ifname)
{
    (void)src;
    fprintf(stderr,
            "[MAC] move  %02x:%02x:%02x:%02x:%02x:%02x @%s->%s\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            old_ifname ? old_ifname : "-", new_ifname ? new_ifname : "-");
    fflush(stderr);
    log_mac_fdb_snapshot_locked(t);
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

static uint8_t mac_hash_key(const uint8_t mac[MAC_LEN])
{
    return mac[5];
}

static void hash_rebuild_locked(struct mac_learn_table *t)
{
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    for (int i = 0; i < t->count; i++) {
        uint8_t b = mac_hash_key(t->list[i].mac);

        t->hash_next[i] = t->hash_head[b];
        t->hash_head[b] = i;
    }
}

static int find_idx_by_mac_locked(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN])
{
    uint8_t b = mac_hash_key(mac);

    for (int i = t->hash_head[b]; i >= 0; i = t->hash_next[i]) {
        if (memcmp(t->list[i].mac, mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

/*
 * L2 FDB: key = MAC, value = LAN ifname. Không lưu IP — client đổi subnet không ảnh hưởng.
 */
static enum mac_upsert_result upsert_locked(struct mac_learn_table *t, const char *ifname,
                                            const uint8_t mac[MAC_LEN],
                                            char old_ifname_out[IF_NAMESIZE])
{
    int mac_idx = find_idx_by_mac_locked(t, mac);

    if (old_ifname_out)
        old_ifname_out[0] = '\0';

    if (mac_idx >= 0) {
        char old_ifname[IF_NAMESIZE];

        strncpy(old_ifname, t->list[mac_idx].ifname, sizeof(old_ifname) - 1);
        old_ifname[sizeof(old_ifname) - 1] = '\0';
        if (strcmp(old_ifname, ifname) == 0)
            return MAC_UPSERT_REFRESH;

        if (old_ifname_out) {
            memcpy(old_ifname_out, old_ifname, IF_NAMESIZE);
            old_ifname_out[IF_NAMESIZE - 1] = '\0';
        }
        strncpy(t->list[mac_idx].ifname, ifname, IF_NAMESIZE - 1);
        t->list[mac_idx].ifname[IF_NAMESIZE - 1] = '\0';
        return MAC_UPSERT_MOVE;
    }

    if (t->count >= MAC_LEARN_MAX_ENTRIES) {
        fprintf(stderr, "[MAC] table full on %s\n", ifname ? ifname : "-");
        return MAC_UPSERT_REFRESH;
    }

    {
        int i = t->count++;

        memcpy(t->list[i].mac, mac, MAC_LEN);
        strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
        t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
        hash_rebuild_locked(t);
    }
    return MAC_UPSERT_NEW;
}

static void table_init(struct mac_learn_table *t)
{
    memset(t, 0, sizeof(*t));
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    pthread_spin_init(&t->lock, PTHREAD_PROCESS_PRIVATE);
}

static void table_learn(struct mac_learn_table *t, const char *ifname,
                        const uint8_t mac[MAC_LEN], enum mac_learn_src src)
{
    enum mac_upsert_result r;
    char old_ifname[IF_NAMESIZE];

    if (!t || !ifname || !mac || ifname[0] == '\0')
        return;
    pthread_spin_lock(&t->lock);
    r = upsert_locked(t, ifname, mac, old_ifname);

    if (r == MAC_UPSERT_NEW) {
        log_mac_fmt("learn", src, mac, ifname);
        log_mac_fdb_snapshot_locked(t);
    } else if (r == MAC_UPSERT_MOVE) {
        log_mac_move(t, src, mac, old_ifname, ifname);
    }
    if (r == MAC_UPSERT_NEW || r == MAC_UPSERT_MOVE)
        mac_fdb_persist_save_locked(t);
    pthread_spin_unlock(&t->lock);
}

static int table_lookup(struct mac_learn_table *t, const uint8_t mac[MAC_LEN],
                        char ifname[IF_NAMESIZE])
{
    int i;

    if (!t || !mac || !ifname)
        return -1;
    pthread_spin_lock(&t->lock);
    i = find_idx_by_mac_locked(t, mac);
    if (i < 0) {
        pthread_spin_unlock(&t->lock);
        return -1;
    }
    strncpy(ifname, t->list[i].ifname, IF_NAMESIZE - 1);
    ifname[IF_NAMESIZE - 1] = '\0';
    pthread_spin_unlock(&t->lock);
    return 0;
}

static int ifname_in_configured_locals(const struct forwarder *fwd, const char *ifname)
{
    if (!fwd || !ifname || !ifname[0])
        return 0;

    for (int i = 0; i < fwd->local_count; i++) {
        if (fwd->locals[i].ifname[0] == '\0')
            continue;
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return 1;
    }
    if (fwd->cfg) {
        for (int i = 0; i < fwd->cfg->local_count; i++) {
            if (fwd->cfg->locals[i].ifname[0] == '\0')
                continue;
            if (strcmp(fwd->cfg->locals[i].ifname, ifname) == 0)
                return 1;
        }
    }
    return 0;
}

static int parse_mac_colon(const char *s, uint8_t mac[MAC_LEN])
{
    unsigned m[6];

    if (!s || !mac)
        return -1;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < MAC_LEN; i++)
        mac[i] = (uint8_t)m[i];
    return 0;
}

static int mac_is_zero(const uint8_t mac[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    return memcmp(mac, zero, MAC_LEN) == 0;
}

static int mac_is_multicast(const uint8_t mac[MAC_LEN])
{
    return (mac[0] & 0x01u) != 0;
}

static int mac_fdb_ensure_log_dir(void)
{
    if (mkdir(MAC_LAN_LOG_DIR, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* L2 only: ifname + mac. v1 file (có cột IP) vẫn đọc được — bỏ qua IP. */
static void mac_fdb_persist_save_locked(const struct mac_learn_table *t)
{
    FILE *fp;
    int fd;

    if (!t || mac_fdb_ensure_log_dir() != 0)
        return;
    fp = fopen(MAC_LAN_LOG_TMP, "w");
    if (!fp) {
        fprintf(stderr, "[MAC-FDB] persist FAIL write %s\n", MAC_LAN_LOG_TMP);
        fflush(stderr);
        return;
    }
    fprintf(fp, "# NE MAC LAN FDB v2 — ifname mac (L2 only; rewrite on learn/move/purge)\n");
    for (int i = 0; i < t->count; i++) {
        const struct mac_learn_entry *e = &t->list[i];

        fprintf(fp, "%s %02x:%02x:%02x:%02x:%02x:%02x\n",
                e->ifname[0] ? e->ifname : "-",
                e->mac[0], e->mac[1], e->mac[2],
                e->mac[3], e->mac[4], e->mac[5]);
    }
    fflush(fp);
    fd = fileno(fp);
    if (fd >= 0)
        (void)fsync(fd);
    fclose(fp);
    if (rename(MAC_LAN_LOG_TMP, MAC_LAN_LOG_PATH) != 0) {
        fprintf(stderr, "[MAC-FDB] persist FAIL rename -> %s\n", MAC_LAN_LOG_PATH);
        fflush(stderr);
        return;
    }
    fprintf(stderr, "[MAC-FDB] saved %d -> %s\n", t->count, MAC_LAN_LOG_PATH);
    fflush(stderr);
}

static int mac_fdb_persist_load_locked(struct mac_learn_table *t,
                                       const struct forwarder *fwd)
{
    FILE *fp;
    char line[256];
    int loaded = 0;

    if (!t || !fwd)
        return 0;
    fp = fopen(MAC_LAN_LOG_PATH, "r");
    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp)) {
        char ifname[IF_NAMESIZE];
        char mac_s[24];
        char extra[16];
        uint8_t mac[MAC_LEN];
        int idx;
        int n;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        extra[0] = '\0';
        n = sscanf(line, "%15s %23s %15s", ifname, mac_s, extra);
        if (n < 2)
            continue;
        if (!ifname_in_configured_locals(fwd, ifname))
            continue;
        if (parse_mac_colon(mac_s, mac) != 0)
            continue;
        if (mac_is_zero(mac) || mac_is_multicast(mac))
            continue;
        if (find_idx_by_mac_locked(t, mac) >= 0)
            continue;
        if (t->count >= MAC_LEARN_MAX_ENTRIES)
            break;
        idx = t->count++;
        memcpy(t->list[idx].mac, mac, MAC_LEN);
        strncpy(t->list[idx].ifname, ifname, IF_NAMESIZE - 1);
        t->list[idx].ifname[IF_NAMESIZE - 1] = '\0';
        loaded++;
    }
    fclose(fp);
    if (loaded > 0)
        hash_rebuild_locked(t);
    return loaded;
}

static void table_purge_orphan_locked(struct mac_learn_table *t, struct forwarder *fwd,
                                      uint8_t *purged_mac, char purged_ifname[IF_NAMESIZE],
                                      int *purge_count)
{
    int w = 0;

    if (!t || !fwd)
        return;
    if (purge_count)
        *purge_count = 0;
    if (purged_ifname)
        purged_ifname[0] = '\0';

    for (int i = 0; i < t->count; i++) {
        if (ifname_in_configured_locals(fwd, t->list[i].ifname)) {
            if (w != i)
                t->list[w] = t->list[i];
            w++;
        } else {
            fprintf(stderr,
                    "[MAC] purge %02x:%02x:%02x:%02x:%02x:%02x iface=%s "
                    "(LAN ifname left config)\n",
                    t->list[i].mac[0], t->list[i].mac[1], t->list[i].mac[2],
                    t->list[i].mac[3], t->list[i].mac[4], t->list[i].mac[5],
                    t->list[i].ifname[0] ? t->list[i].ifname : "-");
            if (purge_count && *purge_count == 0) {
                if (purged_mac)
                    memcpy(purged_mac, t->list[i].mac, MAC_LEN);
                if (purged_ifname) {
                    strncpy(purged_ifname, t->list[i].ifname, IF_NAMESIZE - 1);
                    purged_ifname[IF_NAMESIZE - 1] = '\0';
                }
            }
            if (purge_count)
                (*purge_count)++;
        }
    }
    if (w != t->count) {
        t->count = w;
        hash_rebuild_locked(t);
    }
}

static void log_index_space_mismatch(struct forwarder *fwd)
{
    uint64_t now_ms;
    int cfg_n;

    if (!fwd || !fwd->cfg)
        return;
    cfg_n = fwd->cfg->local_count;
    if (fwd->local_count == cfg_n)
        return;

    now_ms = monotonic_ms();
    if (now_ms - g_last_mismatch_log_ms < MAC_PURGE_LOG_INTERVAL_MS)
        return;
    g_last_mismatch_log_ms = now_ms;

    fprintf(stderr,
            "[MAC] index-space fwd_local_count=%d cfg_local_count=%d table=%d\n",
            fwd->local_count, cfg_n, fwd->mac_table.count);
    for (int i = 0; i < fwd->local_count && i < MAX_INTERFACES; i++) {
        fprintf(stderr, "[MAC]   fwd[%d]=%s live=%d\n",
                i,
                fwd->locals[i].ifname[0] ? fwd->locals[i].ifname : "-",
                ne_pair_local_live(&fwd->pair, i));
    }
    for (int i = 0; i < cfg_n && i < MAX_INTERFACES; i++) {
        fprintf(stderr, "[MAC]   cfg[%d]=%s\n",
                i, fwd->cfg->locals[i].ifname[0] ? fwd->cfg->locals[i].ifname : "-");
    }
}

static void table_maintain(struct forwarder *fwd)
{
    uint8_t purged_mac[MAC_LEN];
    char purged_ifname[IF_NAMESIZE];
    int purge_count = 0;

    if (!fwd)
        return;
    log_index_space_mismatch(fwd);
    pthread_spin_lock(&fwd->mac_table.lock);
    table_purge_orphan_locked(&fwd->mac_table, fwd, purged_mac, purged_ifname, &purge_count);
    if (purge_count > 0)
        log_mac_fdb_snapshot_locked(&fwd->mac_table);
    if (purge_count > 0)
        mac_fdb_persist_save_locked(&fwd->mac_table);
    pthread_spin_unlock(&fwd->mac_table.lock);

    if (purge_count > 0) {
        uint64_t now_ms = monotonic_ms();

        if (now_ms - g_last_purge_log_ms >= MAC_PURGE_LOG_INTERVAL_MS) {
            g_last_purge_log_ms = now_ms;
            fprintf(stderr, "[MAC] purge summary count=%d (first iface=%s)\n",
                    purge_count, purged_ifname[0] ? purged_ifname : "-");
        }
    }
}

int mac_fwd_local_for_cfg_idx(const struct forwarder *fwd, int cfg_li)
{
    const char *ifname;

    if (!fwd || !fwd->cfg || cfg_li < 0 || cfg_li >= fwd->cfg->local_count)
        return -1;
    ifname = fwd->cfg->locals[cfg_li].ifname;
    if (!ifname[0])
        return -1;

    for (int i = 0; i < fwd->local_count; i++) {
        if (!ne_pair_local_live(&fwd->pair, i))
            continue;
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int ingress_idx_by_ifname(const struct forwarder *fwd, const char *ifname)
{
    for (int i = 0; i < fwd->local_count; i++) {
        if (!ne_pair_local_live(&fwd->pair, i))
            continue;
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

void mac_learn_bootstrap(struct mac_learn_table *t)
{
    if (!t)
        return;
    table_init(t);
}

void mac_learn_shutdown(struct mac_learn_table *t)
{
    if (!t)
        return;
    pthread_spin_destroy(&t->lock);
}

void mac_learn_persist(struct forwarder *fwd)
{
    if (!fwd)
        return;
    pthread_spin_lock(&fwd->mac_table.lock);
    mac_fdb_persist_save_locked(&fwd->mac_table);
    pthread_spin_unlock(&fwd->mac_table.lock);
}

void mac_learn_restore(struct forwarder *fwd)
{
    int loaded;

    if (!fwd)
        return;
    pthread_spin_lock(&fwd->mac_table.lock);
    loaded = mac_fdb_persist_load_locked(&fwd->mac_table, fwd);
    if (loaded > 0)
        log_mac_fdb_snapshot_locked(&fwd->mac_table);
    if (loaded > 0)
        mac_fdb_persist_save_locked(&fwd->mac_table);
    pthread_spin_unlock(&fwd->mac_table.lock);

    if (loaded > 0)
        fprintf(stderr, "[MAC-FDB] restored %d from %s\n", loaded, MAC_LAN_LOG_PATH);
    else
        fprintf(stderr, "[MAC-FDB] no cache at %s (wait LAN ARP learn)\n", MAC_LAN_LOG_PATH);
    fflush(stderr);
}

void mac_learn_tick(struct forwarder *fwd)
{
    if (!fwd)
        return;
    table_maintain(fwd);
}

void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src)
{
    const uint8_t *eth_src;

    if (!fwd || !pkt || len < ETH_HEADER_SIZE ||
        ingress_idx < 0 || ingress_idx >= fwd->local_count)
        return;
    if (!ne_pair_local_live(&fwd->pair, ingress_idx))
        return;
    if (src != MAC_LEARN_SRC_ARP || !dp_pkt_is_arp(pkt, len))
        return;

    eth_src = pkt + MAC_LEN;
    if (mac_is_zero(eth_src) || mac_is_multicast(eth_src))
        return;

    table_learn(&fwd->mac_table, fwd->locals[ingress_idx].ifname, eth_src, src);
}

int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN])
{
    char ifname[IF_NAMESIZE];
    int li;

    if (!fwd || !mac)
        return -1;
    if (table_lookup(&fwd->mac_table, mac, ifname) != 0)
        return -1;
    li = ingress_idx_by_ifname(fwd, ifname);
    return li;
}
