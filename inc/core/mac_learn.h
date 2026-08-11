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
    uint32_t spa_be; /* ARP sender IPv4 (0 = unknown); used to replace old MAC */
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
void mac_learn_tick(struct forwarder *fwd);

/*
 * Permanent runtime FDB: MAC → LAN ifname (no TTL aging).
 * Only ARP ethertype on LAN populates entries; purge only when the LAN
 * ifname leaves config. Lookup drives WAN→LAN unicast; never floods.
 *
 * Cập nhật khi đổi port/MAC: ARP who-has/reply trên LAN học lại SMAC.
 * Cùng MAC sang LAN khác → MOVE ifname. Cùng SPA (IP) nhưng MAC mới
 * (vd. eno1 từng x:x:x, sau ARP thấy y:y:y) → xóa MAC cũ, gắn MAC mới ngay.
 */
void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src);
int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN]);

/* Map profile cfg local_indices[] entry → live fwd pair slot (by ifname). */
int mac_fwd_local_for_cfg_idx(const struct forwarder *fwd, int cfg_li);

#endif
