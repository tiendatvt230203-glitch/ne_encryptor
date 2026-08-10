#ifndef MAC_LEARN_H
#define MAC_LEARN_H

#include "config.h"
#include <pthread.h>
#include <stdint.h>

struct forwarder;

#define MAC_LEARN_MAX_ENTRIES 256
#define MAC_LEARN_HASH_BUCKETS 256

/* FDB: SMAC → LAN ifname. Chỉ học từ ARP trên LAN, không TTL. */
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
/* Purge entry có ifname không còn trong config. */
void mac_learn_tick(struct forwarder *fwd);

/* Học SMAC từ ARP LAN. Entry mới → [MAC] learn; đổi LAN → [MAC] move. */
void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len);
/* Tra SMAC → live LAN slot (data WAN→LAN). */
int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN]);

int mac_fwd_local_for_cfg_idx(const struct forwarder *fwd, int cfg_li);

#endif
