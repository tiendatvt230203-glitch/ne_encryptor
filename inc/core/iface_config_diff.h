#ifndef IFACE_CONFIG_DIFF_H
#define IFACE_CONFIG_DIFF_H

#include "config.h"

int ne_iface_cfg_db_unchanged(const struct app_config *old, const struct app_config *new);
int ne_iface_cfg_lan_wan_unchanged(const struct app_config *old, const struct app_config *new);
int ne_iface_cfg_tuning_only_change(const struct app_config *old, const struct app_config *new);
int ne_iface_cfg_policies_unchanged(const struct app_config *old, const struct app_config *new);

#endif
