#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/config.h"

#include <stdio.h>
#include <string.h>

#define ETH_HEADER_SIZE 14u

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

static void log_mac(const char *event, const uint8_t mac[MAC_LEN], const char *ifname)
{
    fprintf(stderr, "[MAC] %s %02x:%02x:%02x:%02x:%02x:%02x iface=%s\n",
            event,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            ifname ? ifname : "-");
}

static void log_mac_update(const uint8_t mac[MAC_LEN], const char *old_ifname,
                           const char *new_ifname)
{
    fprintf(stderr, "[MAC] update %02x:%02x:%02x:%02x:%02x:%02x iface=%s->%s\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            old_ifname ? old_ifname : "-", new_ifname ? new_ifname : "-");
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

static void upsert_locked(struct mac_learn_table *t, const char *ifname,
                          const uint8_t mac[MAC_LEN])
{
    int if_idx = find_idx_by_ifname_locked(t, ifname);
    int mac_idx;

    if (if_idx >= 0) {
        if (memcmp(t->list[if_idx].mac, mac, MAC_LEN) == 0)
            return;

        mac_idx = find_idx_by_mac_locked(t, mac);
        if (mac_idx >= 0 && mac_idx != if_idx) {
            remove_idx_locked(t, mac_idx);
            if_idx = find_idx_by_ifname_locked(t, ifname);
            if (if_idx < 0)
                return;
        }

        memcpy(t->list[if_idx].mac, mac, MAC_LEN);
        log_mac("update", mac, t->list[if_idx].ifname);
        hash_rebuild_locked(t);
        return;
    }

    mac_idx = find_idx_by_mac_locked(t, mac);
    if (mac_idx >= 0) {
        log_mac_update(mac, t->list[mac_idx].ifname, ifname);
        strncpy(t->list[mac_idx].ifname, ifname, IF_NAMESIZE - 1);
        t->list[mac_idx].ifname[IF_NAMESIZE - 1] = '\0';
        return;
    }

    if (t->count >= MAC_LEARN_MAX_ENTRIES)
        return;

    int i = t->count++;

    memcpy(t->list[i].mac, mac, MAC_LEN);
    strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
    t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
    log_mac("learn", mac, t->list[i].ifname);
    hash_rebuild_locked(t);
}

static void table_init(struct mac_learn_table *t)
{
    memset(t, 0, sizeof(*t));
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    pthread_spin_init(&t->lock, PTHREAD_PROCESS_PRIVATE);
}

static void table_learn(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    if (!t || !ifname || !mac || ifname[0] == '\0')
        return;
    pthread_spin_lock(&t->lock);
    upsert_locked(t, ifname, mac);
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

static void table_maintain(struct mac_learn_table *t, const struct app_config *cfg)
{
    if (!t)
        return;
    pthread_spin_lock(&t->lock);
    table_purge_orphan_locked(t, cfg);
    pthread_spin_unlock(&t->lock);
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

void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len)
{
    const uint8_t *src;

    if (!fwd || !pkt || len < ETH_HEADER_SIZE ||
        ingress_idx < 0 || ingress_idx >= fwd->local_count)
        return;

    src = pkt + MAC_LEN;
    if (mac_is_zero(src) || mac_is_multicast(src))
        return;

    table_learn(&fwd->mac_table, fwd->locals[ingress_idx].ifname, src);
}

int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN])
{
    char ifname[IF_NAMESIZE];

    if (!fwd || !mac)
        return -1;
    if (table_lookup(&fwd->mac_table, mac, ifname) != 0)
        return -1;
    return ingress_idx_by_ifname(fwd, ifname);
}
