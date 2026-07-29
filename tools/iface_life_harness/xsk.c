#include "xsk.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 0)
#endif

static void xdp_off(const char *name)
{
    unsigned int idx = if_nametoindex(name);
    char cmd[128];

    if (idx) {
        bpf_xdp_detach((int)idx, 0, NULL);
        bpf_xdp_detach((int)idx, XDP_FLAGS_SKB_MODE, NULL);
        bpf_xdp_detach((int)idx, XDP_FLAGS_DRV_MODE, NULL);
    }
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp off 2>/dev/null", name);
    if (system(cmd) < 0) {}
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdpgeneric off 2>/dev/null", name);
    if (system(cmd) < 0) {}
}

static int find(const struct hx *h, const char *name)
{
    for (int i = 0; i < h->n; i++)
        if (h->ifs[i].live && !strcmp(h->ifs[i].name, name))
            return i;
    return -1;
}

static int slot(struct hx *h)
{
    for (int i = 0; i < h->n; i++)
        if (!h->ifs[i].live)
            return i;
    return h->n < HX_MAX ? h->n : -1;
}

static void kill_if(struct hx_if *x)
{
    if (x->xsk) {
        xsk_socket__delete(x->xsk);
        x->xsk = NULL;
    }
    xdp_off(x->name);
    if (x->bpf) {
        bpf_object__close(x->bpf);
        x->bpf = NULL;
    }
    memset(&x->rx, 0, sizeof(x->rx));
    memset(&x->tx, 0, sizeof(x->tx));
    memset(&x->fq, 0, sizeof(x->fq));
    memset(&x->cq, 0, sizeof(x->cq));
}

static int make_umem(struct hx *h, int i)
{
    struct xsk_umem_config uc = {
        .fill_size = HX_RING,
        .comp_size = HX_RING,
        .frame_size = HX_FRAME,
    };
    int rc;

    if (h->umem) {
        xsk_umem__delete(h->umem);
        h->umem = NULL;
    }
    h->umem_i = -1;
    memset(&h->ifs[i].fq, 0, sizeof(h->ifs[i].fq));
    memset(&h->ifs[i].cq, 0, sizeof(h->ifs[i].cq));
    rc = xsk_umem__create(&h->umem, h->bufs, h->bufsize,
                          &h->ifs[i].fq, &h->ifs[i].cq, &uc);
    if (rc) {
        fprintf(stderr, "[HX] umem_create fail: %s\n", strerror(-rc));
        return -1;
    }
    h->umem_i = i;
    fprintf(stderr, "[HX] umem on %s\n", h->ifs[i].name);
    return 0;
}

static int make_xsk(struct hx *h, int i, uint32_t mode)
{
    struct hx_if *x = &h->ifs[i];
    struct xsk_socket_config c = {
        .rx_size = HX_RING,
        .tx_size = HX_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = mode,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };
    int keep = (h->umem_i == i);
    int rc;

    if (!keep) {
        memset(&x->fq, 0, sizeof(x->fq));
        memset(&x->cq, 0, sizeof(x->cq));
    }
    memset(&x->rx, 0, sizeof(x->rx));
    memset(&x->tx, 0, sizeof(x->tx));
    x->xsk = NULL;
    rc = xsk_socket__create_shared(&x->xsk, x->name, 0, h->umem,
                                   &x->rx, &x->tx, &x->fq, &x->cq, &c);
    if (rc) {
        fprintf(stderr, "[HX] xsk %s mode=0x%x fail: %s\n",
                x->name, mode, strerror(-rc));
        return -1;
    }
    x->flags = mode;
    return 0;
}

static int make_xdp(struct hx_if *x, const char *path,
                    const char *prog_name, const char *map_name)
{
    struct bpf_program *prog;
    struct bpf_map *map;
    int key = 0, fd, rc;
    uint32_t mode;

    x->bpf = bpf_object__open_file(path, NULL);
    if (libbpf_get_error(x->bpf)) {
        fprintf(stderr, "[HX] bpf open %s fail\n", path);
        x->bpf = NULL;
        return -1;
    }
    if (bpf_object__load(x->bpf)) {
        fprintf(stderr, "[HX] bpf load %s fail\n", path);
        bpf_object__close(x->bpf);
        x->bpf = NULL;
        return -1;
    }
    prog = bpf_object__find_program_by_name(x->bpf, prog_name);
    map = bpf_object__find_map_by_name(x->bpf, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[HX] bpf missing prog/map %s\n", path);
        bpf_object__close(x->bpf);
        x->bpf = NULL;
        return -1;
    }

    xdp_off(x->name);
    mode = x->flags ? x->flags : XDP_FLAGS_DRV_MODE;
    rc = bpf_xdp_attach(x->ifindex, bpf_program__fd(prog), mode, NULL);
    if (rc && mode == XDP_FLAGS_DRV_MODE) {
        mode = XDP_FLAGS_SKB_MODE;
        rc = bpf_xdp_attach(x->ifindex, bpf_program__fd(prog), mode, NULL);
    }
    if (rc) {
        fprintf(stderr, "[HX] xdp_attach %s fail: %s\n",
                x->name, strerror(rc < 0 ? -rc : rc));
        bpf_object__close(x->bpf);
        x->bpf = NULL;
        return -1;
    }
    x->flags = mode;
    fd = xsk_socket__fd(x->xsk);
    if (xsk_socket__update_xskmap(x->xsk, bpf_map__fd(map)) != 0 &&
        bpf_map_update_elem(bpf_map__fd(map), &key, &fd, BPF_ANY) != 0) {
        fprintf(stderr, "[HX] xskmap %s fail\n", x->name);
        return -1;
    }
    fprintf(stderr, "[HX] xdp OK %s mode=0x%x\n", x->name, mode);
    return 0;
}

int hx_open(struct hx *h, const char *bpf_lan, const char *bpf_wan)
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

    memset(h, 0, sizeof(*h));
    h->umem_i = -1;
    strncpy(h->bpf_lan, bpf_lan, sizeof(h->bpf_lan) - 1);
    strncpy(h->bpf_wan, bpf_wan, sizeof(h->bpf_wan) - 1);
    setrlimit(RLIMIT_MEMLOCK, &rl);

    h->bufsize = (size_t)HX_FRAMES * HX_FRAME;
    h->bufs = mmap(NULL, h->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (h->bufs == MAP_FAILED) {
        fprintf(stderr, "[HX] mmap fail: %s\n", strerror(errno));
        h->bufs = NULL;
        return -1;
    }
    return 0;
}

void hx_close(struct hx *h)
{
    for (int i = 0; i < h->n; i++) {
        if (h->ifs[i].live)
            kill_if(&h->ifs[i]);
        h->ifs[i].live = 0;
    }
    if (h->umem) {
        xsk_umem__delete(h->umem);
        h->umem = NULL;
    }
    if (h->bufs) {
        munmap(h->bufs, h->bufsize);
        h->bufs = NULL;
    }
    h->umem_i = -1;
    h->n = 0;
}

int hx_add(struct hx *h, const char *ifname, int lan)
{
    int i = slot(h);
    struct hx_if *x;

    if (find(h, ifname) >= 0) {
        fprintf(stderr, "[HX] FAIL add %s: already up\n", ifname);
        return -1;
    }
    if (!if_nametoindex(ifname) || i < 0) {
        fprintf(stderr, "[HX] FAIL add %s: missing/no slot\n", ifname);
        return -1;
    }

    x = &h->ifs[i];
    memset(x, 0, sizeof(*x));
    strncpy(x->name, ifname, IF_NAMESIZE - 1);
    x->ifindex = (int)if_nametoindex(ifname);
    x->lan = lan;

    if (lan) {
        int need = !(h->umem && h->umem_i >= 0 && h->ifs[h->umem_i].live);
        if (need && make_umem(h, i) != 0)
            return -1;
    } else if (!h->umem) {
        fprintf(stderr, "[HX] FAIL add WAN %s: need LAN first\n", ifname);
        return -1;
    }

    xdp_off(ifname);
    if (make_xsk(h, i, XDP_FLAGS_DRV_MODE) != 0 &&
        make_xsk(h, i, XDP_FLAGS_SKB_MODE) != 0)
        return -1;

    if (lan) {
        if (make_xdp(x, h->bpf_lan, "xdp_redirect_prog", "xsks_map") != 0) {
            kill_if(x);
            return -1;
        }
    } else {
        if (make_xdp(x, h->bpf_wan, "xdp_wan_redirect_prog", "wan_xsks_map") != 0) {
            kill_if(x);
            return -1;
        }
    }

    x->live = 1;
    if (i >= h->n)
        h->n = i + 1;
    fprintf(stderr, "[HX] ADD %s %s xsk=%p\n",
            lan ? "LAN" : "WAN", ifname, (void *)x->xsk);
    return 0;
}

int hx_del(struct hx *h, const char *ifname)
{
    int i = find(h, ifname);
    int was_owner;

    if (i < 0) {
        fprintf(stderr, "[HX] FAIL del %s: not up\n", ifname);
        return -1;
    }
    was_owner = (h->umem_i == i);
    fprintf(stderr, "[HX] DEL %s %s%s\n",
            h->ifs[i].lan ? "LAN" : "WAN", ifname,
            was_owner ? " (umem owner)" : "");

    kill_if(&h->ifs[i]);
    h->ifs[i].live = 0;

    if (!was_owner)
        return 0;

    {
        char names[HX_MAX][IF_NAMESIZE];
        int roles[HX_MAX];
        int n = 0;

        if (h->umem) {
            xsk_umem__delete(h->umem);
            h->umem = NULL;
        }
        h->umem_i = -1;

        for (int k = 0; k < h->n; k++) {
            if (!h->ifs[k].live)
                continue;
            strncpy(names[n], h->ifs[k].name, IF_NAMESIZE - 1);
            roles[n] = h->ifs[k].lan;
            kill_if(&h->ifs[k]);
            h->ifs[k].live = 0;
            n++;
        }
        fprintf(stderr, "[HX] rehome umem, reopen %d\n", n);
        for (int k = 0; k < n; k++) {
            if (hx_add(h, names[k], roles[k]) != 0)
                return -1;
        }
    }
    return 0;
}

int hx_ok(const struct hx *h, const char *ifname)
{
    int i = find(h, ifname);
    return i >= 0 && h->ifs[i].xsk != NULL;
}

void hx_dump(const struct hx *h, const char *tag)
{
    fprintf(stderr, "[HX] -- %s -- umem=%p owner=%d\n",
            tag, (void *)h->umem, h->umem_i);
    for (int i = 0; i < h->n; i++) {
        const struct hx_if *x = &h->ifs[i];
        if (!x->name[0])
            continue;
        fprintf(stderr, "[HX]  [%d] live=%d %s %s xsk=%p\n",
                i, x->live, x->lan ? "LAN" : "WAN", x->name, (void *)x->xsk);
    }
}
