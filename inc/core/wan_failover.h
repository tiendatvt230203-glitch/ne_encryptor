#ifndef WAN_FAILOVER_H
#define WAN_FAILOVER_H

struct forwarder;

/* 1 = CFM failover: WAN down → ip link down paired LAN. 0 = off. */
#ifndef FAILOVER_ENABLE
#define FAILOVER_ENABLE 0
#endif

int wan_failover_enabled(void);
int wan_failover_start(struct forwarder *fwd);
void wan_failover_on_cfg(struct forwarder *fwd);
void wan_failover_stop(void);
int wan_failover_dp_excluded(int wan_dp);

#endif
