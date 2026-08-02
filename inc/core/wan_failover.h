#ifndef WAN_FAILOVER_H
#define WAN_FAILOVER_H

struct forwarder;

int wan_failover_start(struct forwarder *fwd);
void wan_failover_on_cfg(struct forwarder *fwd);
void wan_failover_stop(void);
int wan_failover_dp_excluded(int wan_dp);

#endif
