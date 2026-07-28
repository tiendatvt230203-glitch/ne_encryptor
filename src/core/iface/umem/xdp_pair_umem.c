#include "../../../../inc/core/xdp_pair_umem.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static struct xsk_umem_config ne_xdp_umem_config(uint32_t frame_size)
{
    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };
    return ucfg;
}

int ne_xdp_umem_buffer_alloc(struct ne_pair *p)
{
    if (!p)
        return -1;

    p->frame_size = NE_FRAME;
    p->n_frames = NE_N_FRAMES;
    p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;

    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p->bufs == MAP_FAILED) {
        fprintf(stderr, "[UMEM] mmap %zu bytes failed: %s\n",
                p->bufsize, strerror(errno));
        p->bufs = NULL;
        return -1;
    }
    return 0;
}

void ne_xdp_umem_buffer_free(struct ne_pair *p)
{
    if (!p)
        return;
    if (p->bufs && p->bufs != MAP_FAILED) {
        munmap(p->bufs, p->bufsize);
        p->bufs = NULL;
    }
    p->bufsize = 0;
}

int ne_xdp_umem_create(struct ne_pair *p, struct xsk_ring_prod *fq,
                       struct xsk_ring_cons *cq)
{
    struct xsk_umem_config ucfg;

    if (!p || !p->bufs || !fq || !cq)
        return -1;
    if (p->frame_size == 0)
        p->frame_size = NE_FRAME;

    ucfg = ne_xdp_umem_config(p->frame_size);
    if (xsk_umem__create(&p->umem, p->bufs, p->bufsize, fq, cq, &ucfg) != 0) {
        fprintf(stderr, "[UMEM] xsk_umem__create failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

void ne_xdp_umem_destroy(struct ne_pair *p)
{
    if (!p || !p->umem)
        return;
    xsk_umem__delete(p->umem);
    p->umem = NULL;
}

int ne_xdp_umem_recreate(struct ne_pair *p, struct xsk_ring_prod *fq,
                         struct xsk_ring_cons *cq)
{
    ne_xdp_umem_destroy(p);
    return ne_xdp_umem_create(p, fq, cq);
}
