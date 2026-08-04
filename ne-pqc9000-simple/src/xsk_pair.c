#include "xsk_pair.h"

#include <bpf/bpf.h>
#include <dirent.h>
#include <errno.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 0)
#endif

static int pool_push(struct mtu9k_pair *p, uint64_t addr)
{
    uint32_t next = p->free_tail + 1;
    if (next >= p->free_cap)
        next = 0;
    if (next == p->free_head)
        return -1;
    p->free_addrs[p->free_tail] = addr;
    p->free_tail = next;
    return 0;
}

static int pool_pop(struct mtu9k_pair *p, uint64_t *addr)
{
    if (p->free_head == p->free_tail)
        return -1;
    *addr = p->free_addrs[p->free_head];
    p->free_head++;
    if (p->free_head >= p->free_cap)
        p->free_head = 0;
    return 0;
}

void *mtu9k_pkt_data(struct mtu9k_pair *p, uint64_t addr)
{
    return xsk_umem__get_data(p->bufs, addr);
}

static void kick_tx(struct mtu9k_queue *q)
{
    if (!q->xsk || !xsk_ring_prod__needs_wakeup(&q->tx))
        return;
    sendto(xsk_socket__fd(q->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void kick_fq(struct mtu9k_queue *q)
{
    if (!q->xsk || !xsk_ring_prod__needs_wakeup(&q->fq))
        return;
    recvfrom(xsk_socket__fd(q->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

static void refill_fq(struct mtu9k_pair *p, struct mtu9k_queue *q, uint32_t want)
{
    while (want > 0) {
        uint32_t n = want > NE_BATCH ? NE_BATCH : want;
        uint64_t addrs[NE_BATCH];
        uint32_t got = 0;
        uint32_t idx = 0;
        uint32_t reserved;

        for (uint32_t i = 0; i < n; i++) {
            if (pool_pop(p, &addrs[got]) != 0)
                break;
            got++;
        }
        if (got == 0)
            return;

        reserved = xsk_ring_prod__reserve(&q->fq, got, &idx);
        if (reserved != got) {
            for (uint32_t i = 0; i < got; i++)
                pool_push(p, addrs[i]);
            kick_fq(q);
            return;
        }
        for (uint32_t i = 0; i < got; i++)
            *xsk_ring_prod__fill_addr(&q->fq, idx + i) = addrs[i];
        xsk_ring_prod__submit(&q->fq, got);
        kick_fq(q);
        want -= got;
    }
}

static int iface_queue_count(const char *ifname)
{
    char path[256];
    DIR *dir;
    struct dirent *ent;
    int count = 0;

    /* One poll thread drains every RX queue on the NIC. */
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", ifname);
    dir = opendir(path);
    if (!dir)
        return 1;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "rx-", 3) == 0)
            count++;
    }
    closedir(dir);
    if (count <= 0)
        count = 1;
    if (count > (int)NE_MAX_QUEUES)
        count = (int)NE_MAX_QUEUES;
    return count;
}

void mtu9k_recycle(struct mtu9k_pair *p, struct mtu9k_iface *iface)
{
    for (int qi = 0; qi < iface->queue_count; qi++) {
        struct mtu9k_queue *q = &iface->queues[qi];
        uint32_t idx = 0;
        uint32_t n;

        if (!q->xsk)
            continue;
        n = xsk_ring_cons__peek(&q->cq, NE_BATCH, &idx);
        for (uint32_t i = 0; i < n; i++)
            pool_push(p, *xsk_ring_cons__comp_addr(&q->cq, idx + i));
        if (n)
            xsk_ring_cons__release(&q->cq, n);
        refill_fq(p, q, NE_FQ_PREFILL);
    }
}

static int rx_one_queue(struct mtu9k_pair *p, struct mtu9k_queue *q,
                       uint8_t *out, uint32_t out_cap, uint32_t *out_len)
{
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&q->rx, NE_BATCH, &idx);
    uint32_t total = 0;
    uint32_t frags = 0;
    uint64_t addrs[NE_MAX_FRAGS];

    if (n == 0)
        return 0;

    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&q->rx, idx + i);
        int eop = !(d->options & XDP_PKT_CONTD);

        if (frags >= NE_MAX_FRAGS || total + d->len > out_cap) {
            for (uint32_t j = 0; j < frags; j++)
                pool_push(p, addrs[j]);
            pool_push(p, d->addr);
            xsk_ring_cons__release(&q->rx, i + 1);
            return -1;
        }
        addrs[frags++] = d->addr;
        memcpy(out + total, mtu9k_pkt_data(p, d->addr), d->len);
        total += d->len;
        if (eop) {
            xsk_ring_cons__release(&q->rx, i + 1);
            for (uint32_t j = 0; j < frags; j++)
                pool_push(p, addrs[j]);
            *out_len = total;
            return 1;
        }
    }
    for (uint32_t j = 0; j < frags; j++)
        pool_push(p, addrs[j]);
    xsk_ring_cons__release(&q->rx, n);
    return -1;
}

int mtu9k_rx_pkt(struct mtu9k_pair *p, struct mtu9k_iface *iface,
                 uint8_t *out, uint32_t out_cap, uint32_t *out_len)
{
    int nq = iface->queue_count;

    if (nq <= 0)
        return 0;
    for (int i = 0; i < nq; i++) {
        int qi = (iface->rx_cursor + i) % nq;
        int r;

        if (!iface->queues[qi].xsk)
            continue;
        r = rx_one_queue(p, &iface->queues[qi], out, out_cap, out_len);
        if (r != 0) {
            iface->rx_cursor = (qi + 1) % nq;
            return r;
        }
    }
    return 0;
}

static int tx_one_queue(struct mtu9k_pair *p, struct mtu9k_queue *q,
                       const uint8_t *data, uint32_t len)
{
    uint32_t nfrag = (len + p->frame_size - 1) / p->frame_size;
    uint32_t idx = 0;
    uint64_t addrs[NE_MAX_FRAGS];
    uint32_t off = 0;

    if (nfrag == 0 || nfrag > NE_MAX_FRAGS)
        return -1;
    for (uint32_t i = 0; i < nfrag; i++) {
        if (pool_pop(p, &addrs[i]) != 0) {
            for (uint32_t j = 0; j < i; j++)
                pool_push(p, addrs[j]);
            return -1;
        }
    }
    if (xsk_ring_prod__reserve(&q->tx, nfrag, &idx) != nfrag) {
        for (uint32_t i = 0; i < nfrag; i++)
            pool_push(p, addrs[i]);
        kick_tx(q);
        return -1;
    }
    for (uint32_t i = 0; i < nfrag; i++) {
        uint32_t chunk = len - off;
        struct xdp_desc *d;

        if (chunk > p->frame_size)
            chunk = p->frame_size;
        memcpy(mtu9k_pkt_data(p, addrs[i]), data + off, chunk);
        d = xsk_ring_prod__tx_desc(&q->tx, idx + i);
        d->addr = addrs[i];
        d->len = chunk;
        d->options = (i + 1 < nfrag) ? XDP_PKT_CONTD : 0;
        off += chunk;
    }
    xsk_ring_prod__submit(&q->tx, nfrag);
    kick_tx(q);
    return 0;
}

int mtu9k_tx_pkt(struct mtu9k_pair *p, struct mtu9k_iface *iface,
                 const uint8_t *data, uint32_t len)
{
    int nq = iface->queue_count;

    if (!data || len == 0 || len > NE_PKT_MAX || nq <= 0)
        return -1;
    for (int i = 0; i < nq; i++) {
        int qi = (iface->tx_cursor + i) % nq;

        if (!iface->queues[qi].xsk)
            continue;
        if (tx_one_queue(p, &iface->queues[qi], data, len) == 0) {
            iface->tx_cursor = (qi + 1) % nq;
            return 0;
        }
    }
    return -1;
}

static int load_attach_bpf(struct mtu9k_iface *iface, const char *obj_path,
                           const char *prog_name, const char *map_name)
{
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd;
    int err;

    fprintf(stderr, "[BPF] loading %s (simple SKB/XDP_COPY path)\n",
            obj_path);

    iface->bpf_obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(iface->bpf_obj)) {
        fprintf(stderr, "[BPF] open %s failed\n", obj_path);
        iface->bpf_obj = NULL;
        return -1;
    }
    err = bpf_object__load(iface->bpf_obj);
    if (err) {
        fprintf(stderr, "[BPF] load %s failed: %d\n", obj_path, err);
        bpf_object__close(iface->bpf_obj);
        iface->bpf_obj = NULL;
        return -1;
    }
    prog = bpf_object__find_program_by_name(iface->bpf_obj, prog_name);
    map = bpf_object__find_map_by_name(iface->bpf_obj, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[BPF] missing prog/map in %s\n", obj_path);
        bpf_object__close(iface->bpf_obj);
        iface->bpf_obj = NULL;
        return -1;
    }
    prog_fd = bpf_program__fd(prog);
    iface->xskmap_fd = bpf_map__fd(map);
    err = bpf_xdp_attach(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "[BPF] attach %s ifindex=%d failed: %s\n",
                iface->ifname, iface->ifindex, strerror(-err));
        bpf_object__close(iface->bpf_obj);
        iface->bpf_obj = NULL;
        return -1;
    }
    iface->xdp_on = 1;
    return 0;
}

static int update_xskmap_iface(struct mtu9k_iface *iface)
{
    for (int q = 0; q < iface->queue_count; q++) {
        int fd;
        int key = q;
        int err;

        if (!iface->queues[q].xsk)
            return -1;
        fd = xsk_socket__fd(iface->queues[q].xsk);
        if (xsk_socket__update_xskmap(iface->queues[q].xsk, iface->xskmap_fd) == 0)
            continue;
        err = bpf_map_update_elem(iface->xskmap_fd, &key, &fd, 0);
        if (err) {
            fprintf(stderr, "[BPF] xskmap %s q=%d: %s\n",
                    iface->ifname, q, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static void close_iface_queues(struct mtu9k_iface *iface, int opened)
{
    for (int q = 0; q < opened; q++) {
        if (iface->queues[q].xsk) {
            xsk_socket__delete(iface->queues[q].xsk);
            iface->queues[q].xsk = NULL;
        }
    }
    iface->queue_count = 0;
}

static int open_iface_queues(struct mtu9k_pair *p, struct mtu9k_iface *iface,
                             const char *ifname)
{
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP | XDP_USE_SG,
    };
    int nq;

    iface->ifindex = (int)if_nametoindex(ifname);
    if (!iface->ifindex) {
        fprintf(stderr, "[XSK] interface %s not found\n", ifname);
        return -1;
    }
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    nq = iface_queue_count(ifname);
    iface->queue_count = nq;
    iface->rx_cursor = 0;
    iface->tx_cursor = 0;
    fprintf(stderr, "[XSK] %s: binding %d RX queue(s)\n", ifname, nq);

    for (int q = 0; q < nq; q++) {
        int ret = xsk_socket__create_shared(&iface->queues[q].xsk, ifname,
                                           (uint32_t)q, p->umem,
                                           &iface->queues[q].rx,
                                           &iface->queues[q].tx,
                                           &iface->queues[q].fq,
                                           &iface->queues[q].cq, &cfg);
        if (ret) {
            fprintf(stderr, "[XSK] create %s q=%d: %s (%d)\n",
                    ifname, q, strerror(-ret), ret);
            close_iface_queues(iface, q);
            return -1;
        }
    }
    return 0;
}

static void detach_iface(struct mtu9k_iface *iface)
{
    if (iface->xdp_on && iface->ifindex) {
        bpf_xdp_detach(iface->ifindex, XDP_FLAGS_SKB_MODE, NULL);
        iface->xdp_on = 0;
    }
    close_iface_queues(iface, iface->queue_count);
    if (iface->bpf_obj) {
        bpf_object__close(iface->bpf_obj);
        iface->bpf_obj = NULL;
    }
}

int mtu9k_pair_open(struct mtu9k_pair *p, const char *lan, const char *wan)
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = NE_FRAME,
        .frame_headroom = 0,
        .flags = 0,
    };

    memset(p, 0, sizeof(*p));
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);

    p->frame_size = NE_FRAME;
    p->n_frames = NE_N_FRAMES;
    p->free_cap = NE_N_FRAMES + 1;
    p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;
    fprintf(stderr, "[XSK] UMEM %.2f MiB frames=%u x %u\n",
            (double)p->bufsize / (1024.0 * 1024.0), p->n_frames, p->frame_size);

    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p->bufs == MAP_FAILED) {
        perror("[XSK] mmap");
        return -1;
    }
    p->free_addrs = calloc(p->free_cap, sizeof(uint64_t));
    if (!p->free_addrs)
        goto fail;
    if (xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->fq, &p->cq, &ucfg)) {
        fprintf(stderr, "[XSK] umem create failed\n");
        goto fail;
    }
    for (uint32_t i = 0; i < p->n_frames; i++)
        pool_push(p, (uint64_t)i * p->frame_size);

    {
        unsigned int li = if_nametoindex(lan);
        unsigned int wi = if_nametoindex(wan);
        if (li)
            bpf_xdp_detach((int)li, XDP_FLAGS_SKB_MODE, NULL);
        if (wi)
            bpf_xdp_detach((int)wi, XDP_FLAGS_SKB_MODE, NULL);
    }

    if (open_iface_queues(p, &p->lan, lan) != 0)
        goto fail;
    if (open_iface_queues(p, &p->wan, wan) != 0)
        goto fail;

    for (int q = 0; q < p->lan.queue_count; q++)
        refill_fq(p, &p->lan.queues[q], NE_FQ_PREFILL);
    for (int q = 0; q < p->wan.queue_count; q++)
        refill_fq(p, &p->wan.queues[q], NE_FQ_PREFILL);

    if (load_attach_bpf(&p->lan, MTU9K_LAN_BPF, "xdp_redirect_prog", "xsks_map") != 0)
        goto fail;
    if (load_attach_bpf(&p->wan, MTU9K_WAN_BPF, "xdp_wan_redirect_prog",
                        "wan_xsks_map") != 0)
        goto fail;
    if (update_xskmap_iface(&p->lan) != 0)
        goto fail;
    if (update_xskmap_iface(&p->wan) != 0)
        goto fail;

    fprintf(stderr, "[XSK] ready LAN=%s(q=%d) WAN=%s(q=%d) bpf=%s + %s\n",
            lan, p->lan.queue_count, wan, p->wan.queue_count,
            MTU9K_LAN_BPF, MTU9K_WAN_BPF);
    return 0;

fail:
    mtu9k_pair_close(p);
    return -1;
}

void mtu9k_pair_close(struct mtu9k_pair *p)
{
    if (!p)
        return;
    detach_iface(&p->lan);
    detach_iface(&p->wan);
    if (p->umem) {
        xsk_umem__delete(p->umem);
        p->umem = NULL;
    }
    if (p->bufs && p->bufs != MAP_FAILED) {
        munmap(p->bufs, p->bufsize);
        p->bufs = NULL;
    }
    free(p->free_addrs);
    p->free_addrs = NULL;
}
