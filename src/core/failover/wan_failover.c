#include "../../../inc/core/wan_failover.h"

#include <stdio.h>

struct forwarder;

int wan_failover_start(struct forwarder *fwd)
{
    (void)fwd;
    fprintf(stderr, "[WAN-FAILOVER] CFM auto deferred — use -di/-ai\n");
    fflush(stderr);
    return 0;
}

void wan_failover_on_cfg(struct forwarder *fwd)
{
    (void)fwd;
}

void wan_failover_stop(void)
{
}

int wan_failover_dp_excluded(int wan_dp)
{
    (void)wan_dp;
    return 0;
}
