#ifndef XDP_PAIR_UMEM_H
#define XDP_PAIR_UMEM_H

#include "interface.h"
#include <xdp/xsk.h>

int ne_xdp_umem_buffer_alloc(struct ne_pair *p);

void ne_xdp_umem_buffer_free(struct ne_pair *p);

int ne_xdp_umem_create(struct ne_pair *p, struct xsk_ring_prod *fq,
                       struct xsk_ring_cons *cq);

void ne_xdp_umem_destroy(struct ne_pair *p);

int ne_xdp_umem_recreate(struct ne_pair *p, struct xsk_ring_prod *fq,
                         struct xsk_ring_cons *cq);

#endif
