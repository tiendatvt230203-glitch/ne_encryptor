#ifndef KERNEL_BRIDGE_H
#define KERNEL_BRIDGE_H

#include "config.h"

/* Read `bridge link show`, map LAN<->WAN on same master br, fill profile bridges[].
 * If detach_slaves, run `ip link set IF nomaster` after pairs are captured. */
void kernel_bridge_refresh_profile_pairs(struct app_config *cfg, int detach_slaves);

#endif
