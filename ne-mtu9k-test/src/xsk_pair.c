#include "xsk_pair.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

int mtu9k_alloc_frame(struct mtu9k_pair *p, uint64_t *addr_out)
{
    return pool_pop(p, addr_out);
}

void mtu9k_free_frame(struct mtu9k_pair *p, uint64_t addr)
{
    (void)pool_push(p, addr);
}

void *mtu9k_pkt_data(struct mtu9k_pair *p, uint64_t addr)
{
    return xsk_umem__get_data(p->bufs, addr);
}

static void kick_tx(struct mtu9k_queue *q)
{
    if (!xsk_ring_prod__needs_wakeup(&q->tx))
        return;
    sendto(xsk_socket__fd(q->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
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
            return;
        }
        for (uint32_t i = 0; i < got; i++)
            *xsk_ring_prod__fill_addr(&q->fq, idx + i) = addrs[i];
        xsk_ring_prod__submit(&q->fq, got);
        want -= got;
    }
}

void mtu9k_recycle(struct mtu9k_pair *p, struct mtu9k_iface *iface)
{
    struct mtu9k_queue *q = &iface->q;
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&q->cq, NE_BATCH, &idx);

    for (uint32_t i = 0; i < n; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&q->cq, idx + i);
        pool_push(p, addr);
    }
    if (n)
        xsk_ring_cons__release(&q->cq, n);
    refill_fq(p, q, NE_FQ_PREFILL);
}

int mtu9k_rx(struct mtu9k_pair *p, struct mtu9k_iface *iface,
             uint64_t *addrs, uint32_t *lens, int max)
{
    struct mtu9k_queue *q = &iface->q;
    uint32_t idx = 0;
    uint32_t n;
    int out = 0;

    (void)p;
    if (max <= 0)
        return 0;
    n = xsk_ring_cons__peek(&q->rx, (uint32_t)max, &idx);
    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&q->rx, idx + i);
        addrs[out] = d->addr;
        lens[out] = d->len;
        out++;
    }
    if (n)
        xsk_ring_cons__release(&q->rx, n);
    return out;
}

int mtu9k_tx(struct mtu9k_pair *p, struct mtu9k_iface *iface,
             uint64_t addr, uint32_t len)
{
    struct mtu9k_queue *q = &iface->q;
    uint32_t idx = 0;

    (void)p;
    if (xsk_ring_prod__reserve(&q->tx, 1, &idx) != 1)
        return -1;
    {
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&q->tx, idx);
        d->addr = addr;
        d->len = len;
        d->options = 0;
    }
    xsk_ring_prod__submit(&q->tx, 1);
    kick_tx(q);
    return 0;
}

static int load_attach_bpf(struct mtu9k_iface *iface, const char *obj_path,
                           const char *prog_name, const char *map_name)
{
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd;
    int err;

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
    err = bpf_xdp_attach(iface->ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
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

static int update_xskmap(struct mtu9k_iface *iface, int queue_id)
{
    int fd = xsk_socket__fd(iface->q.xsk);
    int key = queue_id;
    int err = bpf_map_update_elem(iface->xskmap_fd, &key, &fd, 0);
    if (err) {
        fprintf(stderr, "[BPF] xskmap update %s q=%d failed: %s\n",
                iface->ifname, queue_id, strerror(errno));
        return -1;
    }
    return 0;
}

static int read_iface_mac(const char *ifname, uint8_t mac[6])
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

/* Force combined=1 — no RSS multi-queue / channel fan-in */
static void force_one_rx_queue(const char *ifname)
{
    char cmd[160];

    snprintf(cmd, sizeof(cmd),
             "ethtool -L %s combined 1 >/dev/null 2>&1 || "
             "ethtool -L %s rx 1 tx 1 >/dev/null 2>&1",
             ifname, ifname);
    (void)system(cmd);
}

static int open_queue(struct mtu9k_pair *p, struct mtu9k_iface *iface, const char *ifname)
{
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };
    int ret;

    force_one_rx_queue(ifname);

    iface->ifindex = (int)if_nametoindex(ifname);
    if (!iface->ifindex) {
        fprintf(stderr, "[XSK] interface %s not found\n", ifname);
        return -1;
    }
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    if (read_iface_mac(ifname, iface->mac) != 0) {
        fprintf(stderr, "[XSK] cannot read MAC for %s\n", ifname);
        return -1;
    }
    /* Always queue_id 0 — single LAN / single WAN */
    ret = xsk_socket__create_shared(&iface->q.xsk, ifname, 0, p->umem,
                                    &iface->q.rx, &iface->q.tx,
                                    &iface->q.fq, &iface->q.cq, &cfg);
    if (ret) {
        fprintf(stderr, "[XSK] create %s failed: %s (%d)\n",
                ifname, strerror(-ret), ret);
        return -1;
    }
    return 0;
}

static void detach_iface(struct mtu9k_iface *iface)
{
    if (iface->xdp_on && iface->ifindex) {
        bpf_xdp_detach(iface->ifindex, XDP_FLAGS_DRV_MODE, NULL);
        iface->xdp_on = 0;
    }
    if (iface->q.xsk) {
        xsk_socket__delete(iface->q.xsk);
        iface->q.xsk = NULL;
    }
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
    /* ring buffer needs one empty slot to distinguish full vs empty */
    p->free_cap = NE_N_FRAMES + 1;
    p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;
    fprintf(stderr, "[XSK] UMEM size=%.2f GiB (frames=%u x %u)\n",
            (double)p->bufsize / (1024.0 * 1024.0 * 1024.0),
            p->n_frames, p->frame_size);
    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p->bufs == MAP_FAILED) {
        perror("[XSK] mmap UMEM");
        return -1;
    }
    p->free_addrs = calloc(p->free_cap, sizeof(uint64_t));
    if (!p->free_addrs)
        goto fail;

    if (xsk_umem__create(&p->umem, p->bufs, p->bufsize, &p->fq, &p->cq, &ucfg)) {
        perror("[XSK] umem create");
        goto fail;
    }

    for (uint32_t i = 0; i < p->n_frames; i++)
        pool_push(p, (uint64_t)i * p->frame_size);

    /* Detach leftover XDP */
    {
        unsigned int li = if_nametoindex(lan);
        unsigned int wi = if_nametoindex(wan);
        if (li)
            bpf_xdp_detach((int)li, XDP_FLAGS_DRV_MODE, NULL);
        if (wi)
            bpf_xdp_detach((int)wi, XDP_FLAGS_DRV_MODE, NULL);
    }

    if (open_queue(p, &p->lan, lan) != 0)
        goto fail;
    if (open_queue(p, &p->wan, wan) != 0)
        goto fail;

    refill_fq(p, &p->lan.q, NE_FQ_PREFILL);
    refill_fq(p, &p->wan.q, NE_FQ_PREFILL);

    if (load_attach_bpf(&p->lan, "lib/lan.o", "xdp_redirect_prog", "xsks_map") != 0)
        goto fail;
    if (load_attach_bpf(&p->wan, "lib/wan.o", "xdp_wan_redirect_prog", "wan_xsks_map") != 0)
        goto fail;
    if (update_xskmap(&p->lan, 0) != 0)
        goto fail;
    if (update_xskmap(&p->wan, 0) != 0)
        goto fail;

    fprintf(stderr, "[XSK] ready 1xLAN=%s 1xWAN=%s frame=%u n_frames=%u umem=%.2f MiB (queue0 only)\n",
            lan, wan, p->frame_size, p->n_frames,
            (double)p->bufsize / (1024.0 * 1024.0));
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
