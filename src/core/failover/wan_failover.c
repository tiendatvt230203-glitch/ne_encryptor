#include "../../../inc/core/wan_failover.h"
#include "../../../inc/core/cfm_diag.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/wan_admin.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct forwarder *g_fwd;

int wan_failover_enabled(void)
{
    return FAILOVER_ENABLE != 0;
}

static int ifname_is_safe(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *)ifname; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static void ip_link_set(const char *ifname, int up)
{
    char cmd[256];

    if (!ifname_is_safe(ifname))
        return;
    snprintf(cmd, sizeof(cmd), "/sbin/ip link set dev %s %s",
             ifname, up ? "up" : "down");
    if (system(cmd) != 0)
        fprintf(stderr, "[WAN-FAILOVER] ip link set %s %s failed\n",
                ifname, up ? "up" : "down");
    else
        fprintf(stderr, "[WAN-FAILOVER] ip link set %s %s\n",
                ifname, up ? "up" : "down");
    fflush(stderr);
}

/* WAN down/up → ip link down/up LAN paired in bridge config. */
static void failover_bridge_lans(struct forwarder *fwd, int wan_dp, int up)
{
    const struct app_config *cfg;

    if (!fwd || !fwd->cfg || wan_dp < 0)
        return;
    cfg = fwd->cfg;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *prof = &cfg->profiles[pi];

        if (!prof->enabled)
            continue;
        for (int bi = 0; bi < prof->bridge_count; bi++) {
            const struct bridge_pair *br = &prof->bridges[bi];
            int li;

            if (br->wan_dp != wan_dp)
                continue;
            li = br->local_idx;
            if (li < 0 || li >= cfg->local_count)
                continue;
            if (!cfg->locals[li].ifname[0])
                continue;
            ip_link_set(cfg->locals[li].ifname, up);
        }
    }
}

static void on_cfm_link_state(int wan_dp, const char *ifname,
                              int old_state, int new_state, void *user)
{
    struct forwarder *fwd = user ? (struct forwarder *)user : g_fwd;

    (void)old_state;
    if (!wan_failover_enabled())
        return;
    if (!fwd || !ifname || !ifname[0])
        return;

    if (new_state == CFM_LINK_STATE_DOWN) {
        fprintf(stderr, "[WAN-FAILOVER] CFM DOWN %s dp=%d\n", ifname, wan_dp);
        fflush(stderr);
        (void)wan_admin_kick(fwd, ifname);
        failover_bridge_lans(fwd, wan_dp, 0);
        return;
    }
    if (new_state == CFM_LINK_STATE_UP) {
        fprintf(stderr, "[WAN-FAILOVER] CFM UP %s dp=%d\n", ifname, wan_dp);
        fflush(stderr);
        (void)wan_admin_restore(fwd, ifname);
        failover_bridge_lans(fwd, wan_dp, 1);
    }
}

int wan_failover_start(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    if (!wan_failover_enabled()) {
        fprintf(stderr, "[WAN-FAILOVER] disabled (FAILOVER_ENABLE=0)\n");
        fflush(stderr);
        return 0;
    }

    g_fwd = fwd;
    cfm_set_state_callback(on_cfm_link_state, fwd);

    if (cfm_init(fwd->cfg) != 0) {
        fprintf(stderr, "[WAN-FAILOVER] cfm_init failed\n");
        fflush(stderr);
        return -1;
    }
    fprintf(stderr,
            "[WAN-FAILOVER] enabled — WAN DOWN→kick + ip link down paired LAN; "
            "WAN UP→restore + ip link up paired LAN\n");
    fflush(stderr);
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
    if (cfm_init(fwd->cfg) != 0) {
        fprintf(stderr, "[WAN-FAILOVER] cfm_init on cfg reload failed\n");
        fflush(stderr);
    }
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
    return cfm_link_is_down(wan_dp) ? 1 : 0;
}
