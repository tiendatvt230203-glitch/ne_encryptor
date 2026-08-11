#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/dataplane_util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAC_PURGE_LOG_INTERVAL_MS 10000ull
#define ETH_HEADER_SIZE         14u

enum mac_upsert_result {
    MAC_UPSERT_REFRESH = 0,
    MAC_UPSERT_NEW,
    MAC_UPSERT_MOVE,
};

static uint64_t g_last_purge_log_ms;
static uint64_t g_last_mismatch_log_ms;

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

static void log_mac_replace(enum mac_learn_src src,
                            const uint8_t old_mac[MAC_LEN], const uint8_t new_mac[MAC_LEN],
                            const char *ifname, uint32_t spa_be)
{
    uint8_t b[4];

    memcpy(b, &spa_be, 4);
    fprintf(stderr,
            "[MAC] replace src=%s "
            "%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x "
            "iface=%s spa=%u.%u.%u.%u\n",
            mac_learn_src_name(src),
            old_mac[0], old_mac[1], old_mac[2], old_mac[3], old_mac[4], old_mac[5],
            new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5],
            ifname ? ifname : "-",
            b[0], b[1], b[2], b[3]);
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

static void delete_idx_locked(struct mac_learn_table *t, int idx)
{
    int last;

    if (!t || idx < 0 || idx >= t->count)
        return;
    last = t->count - 1;
    if (idx != last)
        t->list[idx] = t->list[last];
    t->count = last;
    hash_rebuild_locked(t);
}

/*
 * Same SPA (client IP) answered with a new MAC after port change:
 * drop the stale MAC entry so FDB switches to the new MAC immediately.
 * Returns 1 if an old MAC was removed.
 */
static int purge_stale_spa_mac_locked(struct mac_learn_table *t, uint32_t spa_be,
                                      const uint8_t new_mac[MAC_LEN],
                                      uint8_t old_mac_out[MAC_LEN],
                                      char old_ifname_out[IF_NAMESIZE])
{
    if (!t || !new_mac || spa_be == 0)
        return 0;

    for (int i = 0; i < t->count; i++) {
        if (t->list[i].spa_be != spa_be)
            continue;
        if (memcmp(t->list[i].mac, new_mac, MAC_LEN) == 0)
            continue;
        if (old_mac_out)
            memcpy(old_mac_out, t->list[i].mac, MAC_LEN);
        if (old_ifname_out) {
            strncpy(old_ifname_out, t->list[i].ifname, IF_NAMESIZE - 1);
            old_ifname_out[IF_NAMESIZE - 1] = '\0';
        }
        delete_idx_locked(t, i);
        return 1;
    }
    return 0;
}

/*
 * Permanent runtime FDB (no TTL): key = MAC, value = LAN ifname from ARP.
 * Re-learn on every LAN ARP: same MAC + new LAN → update ifname (port move).
 * Same SPA + new MAC → caller purges old MAC first, then upserts.
 * Does not drive flooding — only WAN→LAN unicast via mac_lookup.
 */
static enum mac_upsert_result upsert_locked(struct mac_learn_table *t, const char *ifname,
                                            const uint8_t mac[MAC_LEN], uint32_t spa_be,
                                            char old_ifname_out[IF_NAMESIZE])
{
    int mac_idx = find_idx_by_mac_locked(t, mac);

    if (old_ifname_out)
        old_ifname_out[0] = '\0';

    if (mac_idx >= 0) {
        char old_ifname[IF_NAMESIZE];

        strncpy(old_ifname, t->list[mac_idx].ifname, sizeof(old_ifname) - 1);
        old_ifname[sizeof(old_ifname) - 1] = '\0';
        if (spa_be != 0)
            t->list[mac_idx].spa_be = spa_be;
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
        t->list[i].spa_be = spa_be;
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
                        const uint8_t mac[MAC_LEN], uint32_t spa_be,
                        enum mac_learn_src src)
{
    enum mac_upsert_result r;
    char old_ifname[IF_NAMESIZE];
    uint8_t replaced_mac[MAC_LEN];
    char replaced_ifname[IF_NAMESIZE];
    int did_replace = 0;

    if (!t || !ifname || !mac || ifname[0] == '\0')
        return;
    pthread_spin_lock(&t->lock);
    if (spa_be != 0)
        did_replace = purge_stale_spa_mac_locked(t, spa_be, mac, replaced_mac,
                                                 replaced_ifname);
    r = upsert_locked(t, ifname, mac, spa_be, old_ifname);
    pthread_spin_unlock(&t->lock);

    if (did_replace) {
        log_mac_replace(src, replaced_mac, mac,
                        replaced_ifname[0] ? replaced_ifname : ifname, spa_be);
        return;
    }
    if (r == MAC_UPSERT_NEW)
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
    /* No TTL aging — only drop entries whose LAN ifname left config. */
    pthread_spin_lock(&fwd->mac_table.lock);
    table_purge_orphan_locked(&fwd->mac_table, fwd, purged_mac, purged_ifname, &purge_count);
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
    table_maintain(fwd);
}

void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src)
{
    const uint8_t *eth_src;
    uint32_t spa_be = 0, tpa_be = 0;

    if (!fwd || !pkt || len < ETH_HEADER_SIZE ||
        ingress_idx < 0 || ingress_idx >= fwd->local_count)
        return;
    if (!ne_pair_local_live(&fwd->pair, ingress_idx))
        return;
    /* ARP-only: require both call-site tag and ethertype 0x0806. */
    if (src != MAC_LEARN_SRC_ARP || !dp_pkt_is_arp(pkt, len))
        return;

    eth_src = pkt + MAC_LEN;
    if (mac_is_zero(eth_src) || mac_is_multicast(eth_src))
        return;

    (void)dp_parse_arp_ips(pkt, len, &spa_be, &tpa_be);
    /* spa_be binds IP→MAC: cùng IP đổi MAC (đổi port) → purge MAC cũ ngay. */
    table_learn(&fwd->mac_table, fwd->locals[ingress_idx].ifname, eth_src, spa_be, src);
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
