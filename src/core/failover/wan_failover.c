#include "../../../inc/core/wan_failover.h"
#include "../../../inc/core/cfm_diag.h"
#include "../../../inc/core/forwarder.h"

#include <stdio.h>

static struct forwarder *g_fwd;

int wan_failover_start(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    g_fwd = fwd;
    if (cfm_init(fwd->cfg) != 0) {
        fprintf(stderr, "[WAN-FAILOVER] cfm_init failed\n");
        fflush(stderr);
        return -1;
    }
    fprintf(stderr, "[WAN-FAILOVER] CFM started (Packet-Parser-ne logic)\n");
    fflush(stderr);
    return 0;
}

void wan_failover_on_cfg(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return;
    g_fwd = fwd;
    if (cfm_init(fwd->cfg) != 0) {
        fprintf(stderr, "[WAN-FAILOVER] cfm_init on cfg reload failed\n");
        fflush(stderr);
    }
}

void wan_failover_stop(void)
{
    cfm_cleanup();
    g_fwd = NULL;
}

int wan_failover_dp_excluded(int wan_dp)
{
    /* Same meaning as Packet-Parser-ne: exclude WAN when CFM says not up. */
    return cfm_is_link_up(wan_dp) ? 0 : 1;
}
