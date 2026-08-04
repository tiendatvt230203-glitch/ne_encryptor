#ifndef NE_MTU9K_XSK_PAIR_H
#define NE_MTU9K_XSK_PAIR_H

#include "config.h"

#include <stdint.h>
#include <xdp/xsk.h>
#include <bpf/libbpf.h>

struct mtu9k_queue {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
};

struct mtu9k_iface {
    char ifname[16];
    int ifindex;
    uint8_t mac[6];
    int queue_count;
    int rx_cursor;
    int tx_cursor;
    struct mtu9k_queue queues[NE_MAX_QUEUES];
    struct bpf_object *bpf_obj;
    int xskmap_fd;
    int xdp_on;
};

struct mtu9k_pair {
    void *bufs;
    size_t bufsize;
    uint32_t frame_size;
    uint32_t n_frames;
    struct xsk_umem *umem;
    struct xsk_ring_prod fq; /* umem fill — unused after shared create */
    struct xsk_ring_cons cq;
    uint64_t *free_addrs;
    uint32_t free_head;
    uint32_t free_tail;
    uint32_t free_cap;
    struct mtu9k_iface lan;
    struct mtu9k_iface wan;
};

int mtu9k_pair_open(struct mtu9k_pair *p, const char *lan, const char *wan);
void mtu9k_pair_close(struct mtu9k_pair *p);

void *mtu9k_pkt_data(struct mtu9k_pair *p, uint64_t addr);

/*
 * RX one logical packet (may span several UMEM frames via XDP_PKT_CONTD).
 * Polls all iface queues round-robin.
 * Copies into out[], returns length via *out_len, frees RX frames.
 * Returns 1 on packet, 0 if no complete packet available, -1 on drop/error.
 */
int mtu9k_rx_pkt(struct mtu9k_pair *p, struct mtu9k_iface *iface,
                 uint8_t *out, uint32_t out_cap, uint32_t *out_len);

/*
 * TX one logical packet: scatter into UMEM frames, XDP_PKT_CONTD on all
 * but the last descriptor. Picks a free TX queue round-robin.
 */
int mtu9k_tx_pkt(struct mtu9k_pair *p, struct mtu9k_iface *iface,
                 const uint8_t *data, uint32_t len);

void mtu9k_recycle(struct mtu9k_pair *p, struct mtu9k_iface *iface);

int mtu9k_alloc_frame(struct mtu9k_pair *p, uint64_t *addr_out);
void mtu9k_free_frame(struct mtu9k_pair *p, uint64_t addr);

#endif
