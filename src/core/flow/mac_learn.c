#include "../../../inc/core/mac_learn.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/dataplane_util.h"

#include <stdio.h>
#include <string.h>

#define ETH_HEADER_SIZE 14u

enum {
    MAC_UPSERT_REFRESH = 0,
    MAC_UPSERT_NEW,
    MAC_UPSERT_MOVE,
};

static const char *arp_op_name(uint16_t op)
{
    if (op == 1)
        return "arp-request";
    if (op == 2)
        return "arp-reply";
    return "arp-other";
}

static void format_mac(const uint8_t mac[MAC_LEN], char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_ipv4_be32(uint32_t ip_be, char *buf, size_t bufsz)
{
    uint8_t b[4];

    memcpy(b, &ip_be, 4);
    snprintf(buf, bufsz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void log_mac_event(const char *event, uint16_t arp_op,
                          const uint8_t dmac[MAC_LEN], const uint8_t smac[MAC_LEN],
                          uint32_t spa_be, uint32_t tpa_be,
                          const char *ifname, const char *old_ifname)
{
    char dmac_s[18], smac_s[18], spa_s[16], tpa_s[16];

    format_mac(dmac, dmac_s, sizeof(dmac_s));
    format_mac(smac, smac_s, sizeof(smac_s));
    format_ipv4_be32(spa_be, spa_s, sizeof(spa_s));
    format_ipv4_be32(tpa_be, tpa_s, sizeof(tpa_s));

    if (old_ifname && old_ifname[0]) {
        fprintf(stderr,
                "[MAC] %s from=%s dmac=%s smac=%s spa=%s tpa=%s iface=%s->%s\n",
                event, arp_op_name(arp_op), dmac_s, smac_s, spa_s, tpa_s,
                old_ifname, ifname ? ifname : "-");
    } else {
        fprintf(stderr,
                "[MAC] %s from=%s dmac=%s smac=%s spa=%s tpa=%s iface=%s\n",
                event, arp_op_name(arp_op), dmac_s, smac_s, spa_s, tpa_s,
                ifname ? ifname : "-");
    }
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

/* Cùng MAC cùng LAN → im lặng; đổi LAN → move; MAC mới → learn. Không TTL. */
static int upsert_locked(struct mac_learn_table *t, const char *ifname,
                         const uint8_t mac[MAC_LEN], char old_ifname_out[IF_NAMESIZE])
{
    int mac_idx = find_idx_by_mac_locked(t, mac);

    if (old_ifname_out)
        old_ifname_out[0] = '\0';

    if (mac_idx >= 0) {
        if (strcmp(t->list[mac_idx].ifname, ifname) == 0)
            return MAC_UPSERT_REFRESH;

        if (old_ifname_out) {
            strncpy(old_ifname_out, t->list[mac_idx].ifname, IF_NAMESIZE - 1);
            old_ifname_out[IF_NAMESIZE - 1] = '\0';
        }
        strncpy(t->list[mac_idx].ifname, ifname, IF_NAMESIZE - 1);
        t->list[mac_idx].ifname[IF_NAMESIZE - 1] = '\0';
        return MAC_UPSERT_MOVE;
    }

    if (t->count >= MAC_LEARN_MAX_ENTRIES)
        return MAC_UPSERT_REFRESH;

    {
        int i = t->count++;

        memcpy(t->list[i].mac, mac, MAC_LEN);
        strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
        t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
        hash_rebuild_locked(t);
    }
    return MAC_UPSERT_NEW;
}

static int ifname_in_configured_locals(const struct forwarder *fwd, const char *ifname)
{
    if (!fwd || !ifname || !ifname[0])
        return 0;

    for (int i = 0; i < fwd->local_count; i++) {
        if (fwd->locals[i].ifname[0] && strcmp(fwd->locals[i].ifname, ifname) == 0)
            return 1;
    }
    if (fwd->cfg) {
        for (int i = 0; i < fwd->cfg->local_count; i++) {
            if (fwd->cfg->locals[i].ifname[0] &&
                strcmp(fwd->cfg->locals[i].ifname, ifname) == 0)
                return 1;
        }
    }
    return 0;
}

static void purge_orphan_locked(struct mac_learn_table *t, struct forwarder *fwd)
{
    int w = 0;

    for (int i = 0; i < t->count; i++) {
        if (ifname_in_configured_locals(fwd, t->list[i].ifname)) {
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
    memset(t, 0, sizeof(*t));
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    pthread_spin_init(&t->lock, PTHREAD_PROCESS_PRIVATE);
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
    pthread_spin_lock(&fwd->mac_table.lock);
    purge_orphan_locked(&fwd->mac_table, fwd);
    pthread_spin_unlock(&fwd->mac_table.lock);
}

void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len)
{
    const uint8_t *eth_dst;
    const uint8_t *eth_src;
    const char *ifname;
    uint16_t arp_op = 0;
    uint32_t spa = 0, tpa = 0;
    char old_ifname[IF_NAMESIZE];
    int r;

    if (!fwd || !pkt || len < ETH_HEADER_SIZE ||
        ingress_idx < 0 || ingress_idx >= fwd->local_count)
        return;
    if (!ne_pair_local_live(&fwd->pair, ingress_idx))
        return;

    eth_dst = pkt;
    eth_src = pkt + MAC_LEN;
    if (mac_is_zero(eth_src) || mac_is_multicast(eth_src))
        return;

    ifname = fwd->locals[ingress_idx].ifname;
    if (!ifname[0])
        return;

    /* Chỉ học từ ARP đã parse được (request/reply). */
    if (dp_parse_arp(pkt, len, &arp_op, &spa, &tpa) != 0)
        return;

    pthread_spin_lock(&fwd->mac_table.lock);
    r = upsert_locked(&fwd->mac_table, ifname, eth_src, old_ifname);
    pthread_spin_unlock(&fwd->mac_table.lock);

    if (r == MAC_UPSERT_NEW)
        log_mac_event("learn", arp_op, eth_dst, eth_src, spa, tpa, ifname, NULL);
    else if (r == MAC_UPSERT_MOVE)
        log_mac_event("move", arp_op, eth_dst, eth_src, spa, tpa, ifname, old_ifname);
}

int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN])
{
    char ifname[IF_NAMESIZE];
    int i;

    if (!fwd || !mac)
        return -1;

    pthread_spin_lock(&fwd->mac_table.lock);
    i = find_idx_by_mac_locked(&fwd->mac_table, mac);
    if (i < 0) {
        pthread_spin_unlock(&fwd->mac_table.lock);
        return -1;
    }
    strncpy(ifname, fwd->mac_table.list[i].ifname, IF_NAMESIZE - 1);
    ifname[IF_NAMESIZE - 1] = '\0';
    pthread_spin_unlock(&fwd->mac_table.lock);

    return ingress_idx_by_ifname(fwd, ifname);
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
