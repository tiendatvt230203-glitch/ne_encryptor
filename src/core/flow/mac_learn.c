#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef MAC_LEARN_CACHE_TTL_MIN
#define MAC_LEARN_CACHE_TTL_MIN 5ull
#endif

#define MAC_LEARN_ENTRY_TTL_MS  (MAC_LEARN_CACHE_TTL_MIN * 60ull * 1000ull)
#define MAC_FLOOD_LOG_INTERVAL_MS 10000ull
#define MAC_FLOOD_TRACK_MAX 64
#define ETH_HEADER_SIZE         14u

enum mac_upsert_result {
    MAC_UPSERT_REFRESH = 0,
    MAC_UPSERT_NEW,
    MAC_UPSERT_MOVE,
    MAC_UPSERT_REPLACE,
};

struct mac_flood_track {
    uint8_t mac[MAC_LEN];
    uint64_t last_log_ms;
    uint8_t in_use;
};

static struct mac_flood_track g_flood_track[MAC_FLOOD_TRACK_MAX];

static const char *mac_learn_src_name(enum mac_learn_src src)
{
    return src == MAC_LEARN_SRC_ARP ? "arp" : "traffic";
}

static void log_mac_fmt(const char *event, enum mac_learn_src src,
                        const uint8_t mac[MAC_LEN], const char *ifname)
{
    fprintf(stderr,
            "[MAC] %s src=%s %02x:%02x:%02x:%02x:%02x:%02x iface=%s\n",
            event, mac_learn_src_name(src),
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ifname ? ifname : "-");
}

static void log_mac_move(enum mac_learn_src src, const uint8_t mac[MAC_LEN],
                         const char *old_ifname, const char *new_ifname)
{
    fprintf(stderr,
            "[MAC] move src=%s %02x:%02x:%02x:%02x:%02x:%02x iface=%s->%s\n",
            mac_learn_src_name(src),
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            old_ifname ? old_ifname : "-", new_ifname ? new_ifname : "-");
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

static int find_idx_by_ifname_locked(const struct mac_learn_table *t, const char *ifname)
{
    if (!ifname || !ifname[0])
        return -1;

    for (int i = 0; i < t->count; i++) {
        if (strcmp(t->list[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static void remove_idx_locked(struct mac_learn_table *t, int idx)
{
    if (!t || idx < 0 || idx >= t->count)
        return;
    if (idx != t->count - 1)
        t->list[idx] = t->list[t->count - 1];
    t->count--;
    hash_rebuild_locked(t);
}

static enum mac_upsert_result upsert_locked(struct mac_learn_table *t, const char *ifname,
                                            const uint8_t mac[MAC_LEN], uint64_t now_ms,
                                            char old_ifname_out[IF_NAMESIZE])
{
    int if_idx = find_idx_by_ifname_locked(t, ifname);
    int mac_idx;

    if (old_ifname_out)
        old_ifname_out[0] = '\0';

    if (if_idx >= 0) {
        if (memcmp(t->list[if_idx].mac, mac, MAC_LEN) == 0) {
            t->list[if_idx].last_seen_ms = now_ms;
            return MAC_UPSERT_REFRESH;
        }

        mac_idx = find_idx_by_mac_locked(t, mac);
        if (mac_idx >= 0 && mac_idx != if_idx)
            remove_idx_locked(t, mac_idx);

        if_idx = find_idx_by_ifname_locked(t, ifname);
        if (if_idx < 0)
            return MAC_UPSERT_REFRESH;

        memcpy(t->list[if_idx].mac, mac, MAC_LEN);
        t->list[if_idx].last_seen_ms = now_ms;
        hash_rebuild_locked(t);
        return MAC_UPSERT_REPLACE;
    }

    mac_idx = find_idx_by_mac_locked(t, mac);
    if (mac_idx >= 0) {
        char old_ifname[IF_NAMESIZE];

        strncpy(old_ifname, t->list[mac_idx].ifname, sizeof(old_ifname) - 1);
        old_ifname[sizeof(old_ifname) - 1] = '\0';
        if (old_ifname_out)
            strncpy(old_ifname_out, old_ifname, IF_NAMESIZE - 1);
        strncpy(t->list[mac_idx].ifname, ifname, IF_NAMESIZE - 1);
        t->list[mac_idx].ifname[IF_NAMESIZE - 1] = '\0';
        t->list[mac_idx].last_seen_ms = now_ms;
        if (strcmp(old_ifname, ifname) != 0)
            return MAC_UPSERT_MOVE;
        return MAC_UPSERT_REFRESH;
    }

    if (t->count >= MAC_LEARN_MAX_ENTRIES) {
        fprintf(stderr, "[MAC] table full on %s\n", ifname ? ifname : "-");
        return MAC_UPSERT_REFRESH;
    }

    int i = t->count++;

    memcpy(t->list[i].mac, mac, MAC_LEN);
    strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
    t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
    t->list[i].last_seen_ms = now_ms;
    hash_rebuild_locked(t);
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
                        const uint8_t mac[MAC_LEN], enum mac_learn_src src,
                        enum mac_upsert_result *result_out)
{
    uint64_t now_ms;
    enum mac_upsert_result r;
    char old_ifname[IF_NAMESIZE];

    if (!t || !ifname || !mac || ifname[0] == '\0')
        return;
    now_ms = monotonic_ms();
    pthread_spin_lock(&t->lock);
    r = upsert_locked(t, ifname, mac, now_ms, old_ifname);
    pthread_spin_unlock(&t->lock);

    if (result_out)
        *result_out = r;

    if (r == MAC_UPSERT_NEW || r == MAC_UPSERT_REPLACE)
        log_mac_fmt("learn", src, mac, ifname);
    else if (r == MAC_UPSERT_MOVE)
        log_mac_move(src, mac, old_ifname, ifname);
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
    t->list[i].last_seen_ms = monotonic_ms();
    strncpy(ifname, t->list[i].ifname, IF_NAMESIZE - 1);
    ifname[IF_NAMESIZE - 1] = '\0';
    pthread_spin_unlock(&t->lock);
    return 0;
}

static int ifname_in_profile_locals(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname || !ifname[0])
        return 0;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *prof = &cfg->profiles[pi];

        if (!prof->enabled)
            continue;
        for (int i = 0; i < prof->local_count; i++) {
            int li = prof->local_indices[i];
            if (li < 0 || li >= cfg->local_count)
                continue;
            if (strcmp(cfg->locals[li].ifname, ifname) == 0)
                return 1;
        }
    }
    return 0;
}

static void table_purge_orphan_locked(struct mac_learn_table *t, const struct app_config *cfg)
{
    int w = 0;

    if (!t || !cfg)
        return;

    for (int i = 0; i < t->count; i++) {
        if (ifname_in_profile_locals(cfg, t->list[i].ifname)) {
            if (w != i)
                t->list[w] = t->list[i];
            w++;
        }
    }
    if (w != t->count) {
        t->count = w;
        hash_rebuild_locked(t);
    }
}

static void table_expire_stale_locked(struct mac_learn_table *t, uint64_t now_ms, uint64_t ttl_ms)
{
    int w = 0;

    if (!t)
        return;

    for (int i = 0; i < t->count; i++) {
        uint64_t idle_ms = now_ms - t->list[i].last_seen_ms;

        if (idle_ms <= ttl_ms) {
            if (w != i)
                t->list[w] = t->list[i];
            w++;
        }
    }
    if (w != t->count) {
        t->count = w;
        hash_rebuild_locked(t);
    }
}

static void table_maintain(struct mac_learn_table *t, const struct app_config *cfg)
{
    uint64_t now_ms;

    if (!t)
        return;
    now_ms = monotonic_ms();
    pthread_spin_lock(&t->lock);
    table_purge_orphan_locked(t, cfg);
    table_expire_stale_locked(t, now_ms, MAC_LEARN_ENTRY_TTL_MS);
    pthread_spin_unlock(&t->lock);
}

static int table_has_mac_locked(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN])
{
    return find_idx_by_mac_locked(t, mac) >= 0;
}

static int flood_track_slot(const uint8_t mac[MAC_LEN])
{
    int free_slot = -1;

    for (int i = 0; i < MAC_FLOOD_TRACK_MAX; i++) {
        if (!g_flood_track[i].in_use) {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (memcmp(g_flood_track[i].mac, mac, MAC_LEN) == 0)
            return i;
    }
    return free_slot;
}

static void flood_track_clear_mac(const uint8_t mac[MAC_LEN])
{
    for (int i = 0; i < MAC_FLOOD_TRACK_MAX; i++) {
        if (g_flood_track[i].in_use &&
            memcmp(g_flood_track[i].mac, mac, MAC_LEN) == 0) {
            g_flood_track[i].in_use = 0;
            return;
        }
    }
}

void mac_flood_log(struct forwarder *fwd, const uint8_t dmac[MAC_LEN], int profile_pi)
{
    const struct profile_config *prof;
    uint64_t now_ms;
    int slot;
    int known;

    if (!fwd || !fwd->cfg || !dmac)
        return;
    if (profile_pi < 0 || profile_pi >= fwd->cfg->profile_count)
        return;
    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled || prof->local_count <= 0)
        return;

    pthread_spin_lock(&fwd->mac_table.lock);
    known = table_has_mac_locked(&fwd->mac_table, dmac);
    pthread_spin_unlock(&fwd->mac_table.lock);
    if (known)
        return;

    now_ms = monotonic_ms();
    slot = flood_track_slot(dmac);
    if (slot < 0)
        return;
    if (g_flood_track[slot].in_use &&
        now_ms - g_flood_track[slot].last_log_ms < MAC_FLOOD_LOG_INTERVAL_MS)
        return;

    memcpy(g_flood_track[slot].mac, dmac, MAC_LEN);
    g_flood_track[slot].in_use = 1;
    g_flood_track[slot].last_log_ms = now_ms;

    fprintf(stderr,
            "[MAC] flood unknown dmac=%02x:%02x:%02x:%02x:%02x:%02x profile=%s lan=",
            dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5], prof->name);
    for (int i = 0; i < prof->local_count; i++) {
        int li = prof->local_indices[i];

        if (li < 0 || li >= fwd->local_count)
            continue;
        if (i > 0)
            fprintf(stderr, ",");
        fprintf(stderr, "%s", fwd->locals[li].ifname);
    }
    fprintf(stderr, "\n");
}

static int ingress_idx_by_ifname(const struct forwarder *fwd, const char *ifname)
{
    for (int i = 0; i < fwd->local_count; i++) {
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
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

void mac_learn_tick(struct forwarder *fwd)
{
    if (!fwd)
        return;
    table_maintain(&fwd->mac_table, fwd->cfg);
}

void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src)
{
    const uint8_t *eth_src;

    if (!fwd || !pkt || len < ETH_HEADER_SIZE ||
        ingress_idx < 0 || ingress_idx >= fwd->local_count)
        return;

    eth_src = pkt + MAC_LEN;
    if (mac_is_zero(eth_src) || mac_is_multicast(eth_src))
        return;

    {
        enum mac_upsert_result r = MAC_UPSERT_REFRESH;

        table_learn(&fwd->mac_table, fwd->locals[ingress_idx].ifname, eth_src, src, &r);
        if (r == MAC_UPSERT_NEW || r == MAC_UPSERT_REPLACE || r == MAC_UPSERT_MOVE)
            flood_track_clear_mac(eth_src);
    }
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
