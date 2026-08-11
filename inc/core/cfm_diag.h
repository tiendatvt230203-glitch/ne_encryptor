#ifndef CFM_DIAG_H
#define CFM_DIAG_H

#include <stdbool.h>

struct app_config;

typedef enum {
    CFM_LINK_STATE_INIT = 0,
    CFM_LINK_STATE_UP = 1,
    CFM_LINK_STATE_DOWN = -1
} cfm_link_state_t;

typedef void (*cfm_link_state_cb)(int wan_dp, const char *ifname,
                                  int old_state, int new_state, void *user);

/* Packet-Parser-ne failover API — wan_dp is dataplane index (config_wan_cfg_to_dp). */
int cfm_init(const struct app_config *cfg);
bool cfm_is_link_up(int wan_dp);
/* 1 if CFM monitors wan_dp and link is DOWN; 0 if UP or not CFM-managed. */
int cfm_link_is_down(int wan_dp);
int failover_select_wan(const struct app_config *cfg, int profile_idx, int initial_wan_idx);
void cfm_cleanup(void);

/* Thin wrappers kept for current tree callers (wan_failover.c) */
int cfm_get_link_state(int wan_dp);
void cfm_set_state_callback(cfm_link_state_cb cb, void *user);

#endif