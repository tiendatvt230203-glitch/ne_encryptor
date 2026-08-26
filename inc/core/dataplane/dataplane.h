#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "core/forwarder/forwarder.h"

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job);
void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job);

#endif
