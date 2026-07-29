#include "l4pqc_xsk_pair.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 0)
#endif

extern char _binary_lan_o_start[];
extern char _binary_lan_o_end[];
extern char _binary_wan_o_start[];
extern char _binary_wan_o_end[];

static void xdp_link_off(const char *ifname)
{
    char cmd[160];
    static const char *const modes[] = { "xdp", "xdpgeneric", "xdpoffload" };

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        snprintf(cmd, sizeof(cmd), "ip link set dev %s %s off 2>/dev/null", ifname, modes[i]);
        (void)system(cmd);
    }
}

static int iface_queue_count(const char *ifname)
{
    char path[256];
    int n = 1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/queues/rx-0", ifname);
    if (access(path, F_OK) != 0)
        return 1;
    n = 0;
    for (int i = 0; i < L4PQC_MAX_QUEUES; i++) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/queues/rx-%d", ifname, i);
        if (access(path, F_OK) != 0)
            break;
        n++;
    }
    return n > 0 ? n : 1;
}

static int update_xsk_map_queue(struct xsk_socket *xsk, int map_fd, int queue_id)
{
    __u32 key = (__u32)queue_id;
    int fd;

    if (!xsk || map_fd < 0)
        return -1;
    fd = xsk_socket__fd(xsk);
    if (fd < 0)
        return -1;
    if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
        return 0;
    return bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY);
}

static int attach_xdp_drv(const char *ifname, const void *blob, size_t blob_sz,
                          const char *obj_name, const char *prog_name,
                          struct bpf_object **out_obj)
{
    struct bpf_program *prog;
    int ifindex;
    int rc;

    ifindex = (int)if_nametoindex(ifname);
    if (!ifindex)
        return -1;

    struct bpf_object_open_opts opts = {
        .sz = sizeof(opts),
        .object_name = obj_name,
    };

    *out_obj = bpf_object__open_mem(blob, blob_sz, &opts);
    if (libbpf_get_error(*out_obj)) {
        fprintf(stderr, "[L4PQC] bpf open %s failed\n", obj_name);
        *out_obj = NULL;
        return -1;
    }
    if (bpf_object__load(*out_obj)) {
        fprintf(stderr, "[L4PQC] bpf load %s failed\n", obj_name);
        goto fail;
    }

    prog = bpf_object__find_program_by_name(*out_obj, prog_name);
    if (!prog) {
        fprintf(stderr, "[L4PQC] bpf prog %s missing in %s\n", prog_name, obj_name);
        goto fail;
    }

    xdp_link_off(ifname);
    rc = bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_DRV_MODE, NULL);
    if (rc) {
        fprintf(stderr, "[L4PQC] xdp attach DRV %s on %s failed: %s\n",
                obj_name, ifname, strerror(rc < 0 ? -rc : rc));
        goto fail;
    }

    fprintf(stderr, "[L4PQC] XDP OK %s on %s (DRV + XDP_COPY)\n", obj_name, ifname);
    return 0;

fail:
    if (*out_obj) {
        bpf_object__close(*out_obj);
        *out_obj = NULL;
    }
    return -1;
}

static int bind_xsk_maps(struct bpf_object *obj, const char *map_name,
                         struct l4pqc_xsk_pair *xp, int wan)
{
    struct bpf_map *map;
    int map_fd;

    map = bpf_object__find_map_by_name(obj, map_name);
    if (!map)
        return -1;
    map_fd = bpf_map__fd(map);
    for (int q = 0; q < xp->queue_count; q++) {
        struct xsk_socket *xsk = wan ? xp->queues[q].wan.xsk : xp->queues[q].lan.xsk;
        if (update_xsk_map_queue(xsk, map_fd, q) != 0)
            return -1;
    }
    return 0;
}

static int create_xsk_drv(const char *ifname, int q, struct xsk_umem *umem,
                          struct l4pqc_xsk_sock *xs, int keep_fq_cq)
{
    struct xsk_socket_config cfg = {
        .rx_size = L4PQC_RING,
        .tx_size = L4PQC_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };
    int rc;

    if (!keep_fq_cq) {
        memset(&xs->fq, 0, sizeof(xs->fq));
        memset(&xs->cq, 0, sizeof(xs->cq));
    }
    memset(&xs->rx, 0, sizeof(xs->rx));
    memset(&xs->tx, 0, sizeof(xs->tx));
    xs->xsk = NULL;

    rc = xsk_socket__create_shared(&xs->xsk, ifname, (uint32_t)q, umem,
                                   &xs->rx, &xs->tx, &xs->fq, &xs->cq, &cfg);
    if (rc) {
        fprintf(stderr, "[L4PQC] xsk %s q=%d DRV fail: %s\n",
                ifname, q, strerror(-rc));
        return -1;
    }
    return 0;
}

void *l4pqc_pkt_data(const struct l4pqc_xsk_pair *xp, uint64_t addr)
{
    if (!xp || !xp->bufs)
        return NULL;
    return (uint8_t *)xp->bufs + addr;
}

void l4pqc_refill_fq(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp)
{
    uint32_t idx;
    uint64_t addr;
    uint32_t free_slots = xsk_prod_nb_free(&xs->fq, L4PQC_RING);

    if (!xs || !xp || !xp->bufs)
        return;
    if (!free_slots)
        return;

    if (xsk_ring_prod__reserve(&xs->fq, free_slots, &idx) != free_slots)
        return;

    for (uint32_t i = 0; i < free_slots; i++) {
        addr = (idx + i) * L4PQC_FRAME;
        if (addr >= xp->bufsize)
            addr = (addr % xp->bufsize);
        *xsk_ring_prod__fill_addr(&xs->fq, idx + i) = addr;
    }
    xsk_ring_prod__submit(&xs->fq, free_slots);
}

void l4pqc_drain_cq(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp)
{
    uint32_t idx, completed;
    uint64_t addr;

    (void)xp;
    if (!xs)
        return;
    completed = xsk_ring_cons__peek(&xs->cq, L4PQC_RING, &idx);
    if (!completed)
        return;
    for (uint32_t i = 0; i < completed; i++) {
        addr = *xsk_ring_cons__comp_addr(&xs->cq, idx + i);
        (void)addr;
    }
    xsk_ring_cons__release(&xs->cq, completed);
}

int l4pqc_recv(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp,
               uint8_t dir, uint8_t iface_idx,
               struct l4pqc_batch_pkt *out, int max)
{
    uint32_t idx, rcvd;
    int n = 0;

    if (!xs || !xp || !out || max <= 0)
        return 0;

    if (xsk_ring_prod__needs_wakeup(&xs->fq))
        (void)xsk_socket__fd(xs->xsk);

    rcvd = xsk_ring_cons__peek(&xs->rx, (uint32_t)max, &idx);
    for (uint32_t i = 0; i < rcvd && n < max; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&xs->rx, idx + i);
        out[n].addr = d->addr;
        out[n].len = d->len;
        out[n].dir = dir;
        out[n].iface_idx = iface_idx;
        n++;
    }
    if (rcvd)
        xsk_ring_cons__release(&xs->rx, rcvd);
    return n;
}

void l4pqc_release_rx(struct l4pqc_xsk_sock *xs)
{
    (void)xs;
}

int l4pqc_send(struct l4pqc_xsk_sock *xs, struct l4pqc_xsk_pair *xp,
               uint64_t addr, uint32_t len)
{
    uint32_t idx;
    struct xdp_desc *d;

    (void)xp;
    if (!xs || !xs->xsk)
        return -1;

    if (xsk_ring_prod__needs_wakeup(&xs->tx))
        (void)xsk_socket__fd(xs->xsk);

    if (xsk_ring_prod__reserve(&xs->tx, 1, &idx) != 1)
        return -1;
    d = xsk_ring_prod__tx_desc(&xs->tx, idx);
    d->addr = addr;
    d->len = len;
    xsk_ring_prod__submit(&xs->tx, 1);
    return 0;
}

int l4pqc_xsk_open(struct l4pqc_xsk_pair *xp, const struct l4pqc_config *cfg)
{
    struct xsk_umem_config ucfg = {
        .fill_size = L4PQC_RING,
        .comp_size = L4PQC_RING,
        .frame_size = L4PQC_FRAME,
    };
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    int lan_q, wan_q, nq;
    size_t blob_lan, blob_wan;

    if (!xp || !cfg)
        return -1;

    memset(xp, 0, sizeof(*xp));
    xp->umem_owner_q = -1;
    xp->xdp_flags = XDP_FLAGS_DRV_MODE;
    strncpy(xp->lan_if, cfg->lan_if, sizeof(xp->lan_if) - 1);
    strncpy(xp->wan_if, cfg->wan_if, sizeof(xp->wan_if) - 1);

    lan_q = iface_queue_count(cfg->lan_if);
    wan_q = iface_queue_count(cfg->wan_if);
    nq = cfg->queue_count > 0 ? cfg->queue_count : lan_q;
    if (wan_q < nq)
        nq = wan_q;
    if (nq > L4PQC_MAX_QUEUES)
        nq = L4PQC_MAX_QUEUES;
    if (nq <= 0)
        nq = 1;
    xp->queue_count = nq;

    setrlimit(RLIMIT_MEMLOCK, &rl);
    xp->bufsize = (size_t)L4PQC_N_FRAMES * L4PQC_FRAME;
    xp->bufs = mmap(NULL, xp->bufsize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (xp->bufs == MAP_FAILED) {
        xp->bufs = NULL;
        return -1;
    }

    xdp_link_off(cfg->lan_if);
    xdp_link_off(cfg->wan_if);

    /* 1. UMEM trên LAN q=0 (giống harness / ne_pair) */
    memset(&xp->queues[0].lan.fq, 0, sizeof(xp->queues[0].lan.fq));
    memset(&xp->queues[0].lan.cq, 0, sizeof(xp->queues[0].lan.cq));
    if (xsk_umem__create(&xp->umem, xp->bufs, xp->bufsize,
                         &xp->queues[0].lan.fq, &xp->queues[0].lan.cq, &ucfg) != 0) {
        fprintf(stderr, "[L4PQC] umem create on %s failed\n", cfg->lan_if);
        goto fail;
    }
    xp->umem_owner_q = 0;
    fprintf(stderr, "[L4PQC] umem on %s q=0\n", cfg->lan_if);

    /* 2. Tạo XSK trước (DRV + XDP_COPY), rồi mới attach XDP — giống harness */
    for (int q = 0; q < nq; q++) {
        struct l4pqc_queue_ctx *qc = &xp->queues[q];
        int lan_keep = (q == xp->umem_owner_q);

        qc->queue_id = q;
        qc->cpu_id = (cfg->cpu_map[q] != L4PQC_CPU_NO_PIN) ? cfg->cpu_map[q] : L4PQC_CPU_NO_PIN;

        if (create_xsk_drv(cfg->lan_if, q, xp->umem, &qc->lan, lan_keep) != 0)
            goto fail;
        if (create_xsk_drv(cfg->wan_if, q, xp->umem, &qc->wan, 0) != 0)
            goto fail;
    }

    blob_lan = (size_t)(_binary_lan_o_end - _binary_lan_o_start);
    blob_wan = (size_t)(_binary_wan_o_end - _binary_wan_o_start);

    /* 3. Attach XDP DRV + bind xsks_map */
    if (attach_xdp_drv(cfg->lan_if, _binary_lan_o_start, blob_lan,
                       "lan", "xdp_redirect_prog", &xp->lan_bpf) != 0)
        goto fail;
    if (bind_xsk_maps(xp->lan_bpf, "xsks_map", xp, 0) != 0)
        goto fail;

    if (attach_xdp_drv(cfg->wan_if, _binary_wan_o_start, blob_wan,
                       "wan", "xdp_wan_redirect_prog", &xp->wan_bpf) != 0)
        goto fail;
    if (bind_xsk_maps(xp->wan_bpf, "wan_xsks_map", xp, 1) != 0)
        goto fail;

    for (int q = 0; q < nq; q++) {
        l4pqc_refill_fq(&xp->queues[q].lan, xp);
        l4pqc_refill_fq(&xp->queues[q].wan, xp);
        fprintf(stderr, "[L4PQC] queue %d LAN=%s WAN=%s\n",
                q, cfg->lan_if, cfg->wan_if);
    }

    fprintf(stderr, "[L4PQC] opened %d RSS queues (DRV + XDP_COPY)\n", nq);
    return 0;

fail:
    l4pqc_xsk_close(xp);
    return -1;
}

void l4pqc_xsk_close(struct l4pqc_xsk_pair *xp)
{
    if (!xp)
        return;
    for (int q = 0; q < xp->queue_count; q++) {
        if (xp->queues[q].lan.xsk) {
            xsk_socket__delete(xp->queues[q].lan.xsk);
            xp->queues[q].lan.xsk = NULL;
        }
        if (xp->queues[q].wan.xsk) {
            xsk_socket__delete(xp->queues[q].wan.xsk);
            xp->queues[q].wan.xsk = NULL;
        }
    }
    if (xp->umem) {
        xsk_umem__delete(xp->umem);
        xp->umem = NULL;
    }
    if (xp->lan_bpf) {
        bpf_object__close(xp->lan_bpf);
        xp->lan_bpf = NULL;
    }
    if (xp->wan_bpf) {
        bpf_object__close(xp->wan_bpf);
        xp->wan_bpf = NULL;
    }
    xdp_link_off(xp->lan_if);
    xdp_link_off(xp->wan_if);
    if (xp->bufs && xp->bufs != MAP_FAILED) {
        munmap(xp->bufs, xp->bufsize);
        xp->bufs = NULL;
    }
    memset(xp, 0, sizeof(*xp));
    xp->umem_owner_q = -1;
}
