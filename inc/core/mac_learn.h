#ifndef MAC_LEARN_H
#define MAC_LEARN_H

#include "config.h"
#include <pthread.h>
#include <stdint.h>

struct forwarder;

#define MAC_LEARN_MAX_ENTRIES 256
#define MAC_LEARN_HASH_BUCKETS 256

enum mac_learn_src {
    MAC_LEARN_SRC_ARP = 1, /* chỉ ARP trên LAN populate FDB */
};

struct mac_learn_entry {
    uint8_t mac[MAC_LEN];
    char ifname[IF_NAMESIZE];
    uint64_t last_seen_ms;
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

/* Học SMAC từ ARP client trên LAN (request/reply). Entry lưu vĩnh viễn (no TTL). */
void mac_learn(struct forwarder *fwd, int ingress_idx, const uint8_t *pkt, uint32_t len,
               enum mac_learn_src src);
/* Tra MAC → LAN ifname (dùng khi TCP/UDP/OSPF về từ WAN gộp kênh; không học từ data). */
int mac_lookup(struct forwarder *fwd, const uint8_t mac[MAC_LEN]);

/* Map profile cfg local_indices[] entry → live fwd pair slot (by ifname). */
int mac_fwd_local_for_cfg_idx(const struct forwarder *fwd, int cfg_li);

#endif
