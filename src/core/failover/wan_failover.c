#include "../../../inc/core/wan_failover.h"
#include "../../../inc/core/cfm_diag.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/wan_admin.h"

#include <stdio.h>

static struct forwarder *g_fwd;

/* Same APIs as CLI -di / -ai; CFM drives them on link edges. */
static void on_cfm_link_state(int wan_dp, const char *ifname,
                              int old_state, int new_state, void *user)
{
    struct forwarder *fwd = user ? (struct forwarder *)user : g_fwd;

    (void)wan_dp;
    (void)old_state;
    if (!fwd || !ifname || !ifname[0])
        return;

    if (new_state == CFM_LINK_STATE_DOWN) {
        fprintf(stderr, "[WAN-FAILOVER] CFM DOWN %s → kick (same as -di)\n", ifname);
        fflush(stderr);
        (void)wan_admin_kick(fwd, ifname);
        return;
    }
    if (new_state == CFM_LINK_STATE_UP) {
        fprintf(stderr, "[WAN-FAILOVER] CFM UP %s → restore (same as -ai)\n", ifname);
        fflush(stderr);
        (void)wan_admin_restore(fwd, ifname);
    }
}

int wan_failover_start(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    g_fwd = fwd;
    cfm_set_state_callback(on_cfm_link_state, fwd);

    if (cfm_init(fwd->cfg) != 0) {
        fprintf(stderr, "[WAN-FAILOVER] cfm_init failed\n");
        fflush(stderr);
        return -1;
    }
    fprintf(stderr,
            "[WAN-FAILOVER] CFM started — DOWN→kick / UP→restore "
            "(manual -di/-ai still OK)\n");
    fflush(stderr);
    return 0;
}

void wan_failover_on_cfg(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return;
    g_fwd = fwd;
    cfm_set_state_callback(on_cfm_link_state, fwd);
    if (cfm_init(fwd->cfg) != 0) {
        fprintf(stderr, "[WAN-FAILOVER] cfm_init on cfg reload failed\n");
        fflush(stderr);
    }
}

void wan_failover_stop(void)
{
    cfm_set_state_callback(NULL, NULL);
    cfm_cleanup();
    g_fwd = NULL;
}

int wan_failover_dp_excluded(int wan_dp)
{
    (void)wan_dp;
    /* Exclusion is via wan_admin_hold after kick; not CFM itself. */
    return 0;
}
