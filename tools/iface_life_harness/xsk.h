#ifndef HARNESS_XSK_H
#define HARNESS_XSK_H

#include <net/if.h>
#include <stdint.h>
#include <xdp/xsk.h>

#define HX_MAX 8
#define HX_FRAME 2048u
#define HX_FRAMES 4096u
#define HX_RING 2048u

struct hx_if {
    char name[IF_NAMESIZE];
    int ifindex;
    int lan;
    int live;
    uint32_t flags;
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx, cq;
    struct xsk_ring_prod tx, fq;
    struct bpf_object *bpf;
};

struct hx {
    void *bufs;
    size_t bufsize;
    struct xsk_umem *umem;
    int umem_i;
    struct hx_if ifs[HX_MAX];
    int n;
    char bpf_lan[256];
    char bpf_wan[256];
};

int hx_open(struct hx *h, const char *bpf_lan, const char *bpf_wan);
void hx_close(struct hx *h);
int hx_add(struct hx *h, const char *ifname, int lan);
int hx_del(struct hx *h, const char *ifname);
int hx_ok(const struct hx *h, const char *ifname);
void hx_dump(const struct hx *h, const char *tag);

#endif
