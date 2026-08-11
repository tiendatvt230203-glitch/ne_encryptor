#ifndef MAC_LEARN_H
#define MAC_LEARN_H

#include "config.h"
#include <pthread.h>
#include <stdint.h>

struct forwarder;

#define MAC_LEARN_MAX_ENTRIES 256
#define MAC_LEARN_HASH_BUCKETS 256

enum mac_learn_src {
    MAC_LEARN_SRC_TRAFFIC = 0, /* rejected — FDB is ARP-only */
    MAC_LEARN_SRC_ARP = 1,
};

struct mac_learn_entry {
    uint8_t mac[MAC_LEN];
    char ifname[IF_NAMESIZE];
};

struct mac_learn_table {
    struct mac_learn_entry list[MAC_LEARN_MAX_ENTRIES];
    int count;
    int hash_head[MAC_LEARN_HASH_BUCKETS];
    int hash_next[MAC_LEARN_MAX_ENTRIES];
    pthread_spinlock_t lock;
};

void mac_learn_bootstrap(struct mac_learn_table *t);
void mac_learn_shutdown(struct mac_learn_table *t);
void mac_learn_persist(struct forwarder *fwd);
void mac_learn_restore(struct forwarder *fwd);
void mac_learn_tick(struct forwarder *fwd);

/*
 * L2 FDB: MAC → LAN ifname (no IP — thiết bị bridge L2, client đổi subnet không ảnh hưởng).
 * Chỉ ARP trên LAN học SMAC; purge khi ifname rời config. Lookup cho WAN→LAN unicast.
 */
void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src);
int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN]);

/* Map profile cfg local_indices[] entry → live fwd pair slot (by ifname). */
int mac_fwd_local_for_cfg_idx(const struct forwarder *fwd, int cfg_li);

#endif
