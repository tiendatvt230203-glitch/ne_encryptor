#ifndef KERNEL_BRIDGE_H
#define KERNEL_BRIDGE_H

#include "config.h"

/* Read kernel br if up (discover + persist), else load saved LAN<->WAN pairs.
 * First boot: br must be up. Later restarts use /var/lib/network-encryptor/bridge_pairs.conf.
 * Re-discover when br is up again overwrites the saved file (update path TBD). */
void kernel_bridge_refresh_profile_pairs(struct app_config *cfg);

#endif
