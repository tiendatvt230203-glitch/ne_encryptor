#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "forwarder.h"

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job);
void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job);

void ne_local_egress_reset_diag(void);
void ne_local_egress_note_wan_submit(uint64_t addr, int policy_slot, int wan_idx,
                                     uint32_t wire_len);
void ne_local_egress_on_wan_cq(uint64_t addr);
void ne_local_egress_on_xdp_tx_full(int wan_idx);
void ne_local_egress_on_xdp_kick_fail(int wan_idx, int err);
void ne_local_egress_on_wan_not_live(int wan_idx);

void ne_wan_ingress_reset_diag(void);
void ne_wan_ingress_note_lan_submit(uint64_t addr, int policy_slot, int lan_idx,
                                    uint32_t len);
void ne_wan_ingress_on_lan_cq(uint64_t addr);

#endif
