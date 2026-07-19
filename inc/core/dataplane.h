#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "forwarder.h"

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job);
void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job);

/* 1 = bypass policy, 0 = encrypt / no-match (crypto path). */
int dataplane_local_is_bypass(struct forwarder *fwd, int local_idx,
                              const uint8_t *pkt, uint32_t len);

#endif
