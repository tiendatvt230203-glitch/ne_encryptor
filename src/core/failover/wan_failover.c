#include "../../../inc/core/wan_failover.h"
#include "../../../inc/core/cfm_diag.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/wan_admin.h"

static struct forwarder *g_fwd;

int wan_failover_enabled(void)
{
    return FAILOVER_ENABLE != 0;
}

/*
 * CFM state callback: DOWN → kick (same as -di), UP → restore (same as -ai).
 * UP/DOWN hiện trên bảng [system] — không log [WAN-FAILOVER] tách dòng.
 */
static void on_cfm_link_state(int wan_dp, const char *ifname,
                              int old_state, int new_state, void *user)
{
    struct forwarder *fwd = user ? (struct forwarder *)user : g_fwd;

    (void)old_state;
    (void)wan_dp;
    if (!wan_failover_enabled())
        return;
    if (!fwd || !ifname || !ifname[0])
        return;

    if (new_state == CFM_LINK_STATE_DOWN) {
        // (void)wan_admin_kick(fwd, ifname);
        return;
    }
    if (new_state == CFM_LINK_STATE_UP) {
        // (void)wan_admin_restore(fwd, ifname);
    }
}

int wan_failover_start(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    if (!wan_failover_enabled())
        return 0;

    g_fwd = fwd;
    cfm_set_state_callback(on_cfm_link_state, fwd);

    if (cfm_init(fwd->cfg) != 0)
        return -1;
    return 0;
}

void wan_failover_on_cfg(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return;
    if (!wan_failover_enabled())
        return;

    g_fwd = fwd;
    cfm_set_state_callback(on_cfm_link_state, fwd);
    (void)cfm_init(fwd->cfg);
}

void wan_failover_stop(void)
{
    if (!wan_failover_enabled()) {
        g_fwd = NULL;
        return;
    }
    cfm_set_state_callback(NULL, NULL);
    cfm_cleanup();
    g_fwd = NULL;
}

int wan_failover_dp_excluded(int wan_dp)
{
    if (!wan_failover_enabled())
        return 0;
    /* CFM-managed WANs that are DOWN are kept out of the profile pool. */
    return cfm_link_is_down(wan_dp) ? 1 : 0;
}
