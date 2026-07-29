#ifndef L4PQC_XSK_PAIR_H
#define L4PQC_XSK_PAIR_H

#include "l4pqc_rss.h"
#include <xdp/xsk.h>

struct l4pqc_batch_pkt {
    uint64_t addr;
    uint32_t len;
    uint8_t  dir;
    uint8_t  iface_idx;
};

struct l4pqc_xsk_sock {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
};

struct l4pqc_queue_ctx {
    int              queue_id;
    uint8_t          cpu_id;
    struct l4pqc_xsk_sock lan;
    struct l4pqc_xsk_sock wan;
};

struct l4pqc_xsk_pair {
    void            *bufs;
    size_t           bufsize;
    struct xsk_umem *umem;
    int              umem_owner_q;
    char             lan_if[IF_NAMESIZE];
    char             wan_if[IF_NAMESIZE];
    int              queue_count;
    uint32_t         xdp_flags;
    struct bpf_object *lan_bpf;
    struct bpf_object *wan_bpf;
    struct l4pqc_queue_ctx queues[L4PQC_MAX_QUEUES];
};

int  l4pqc_xsk_open(struct l4pqc_xsk_pair *xp, const struct l4pqc_config *cfg);
void l4pqc_xsk_close(struct l4pqc_xsk_pair *xp);

void *l4pqc_pkt_data(const struct l4pqc_xsk_pair *xp, uint64_t addr);
int   l4pqc_recv(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp,
                 uint8_t dir, uint8_t iface_idx, struct l4pqc_batch_pkt *out, int max);
void  l4pqc_release_rx(struct l4pqc_xsk_sock *xs);
int   l4pqc_send(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp,
                 uint64_t addr, uint32_t len);
void  l4pqc_refill_fq(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp);
void  l4pqc_drain_cq(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp);

#endif
