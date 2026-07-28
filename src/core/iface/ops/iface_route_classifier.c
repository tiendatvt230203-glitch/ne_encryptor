#include "../../../../inc/core/iface_reload.h"
#include "../../../../inc/core/forwarder_reload.h"
#include "../../../../inc/core/interface.h"

#include <string.h>

static int cfg_has_wan_ifname(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

static int cfg_locals_subset(const struct app_config *sub, const struct app_config *sup)
{
    for (int i = 0; i < sub->local_count; i++) {
        if (!config_local_ifname_in_cfg(sup, sub->locals[i].ifname))
            return 0;
    }
    return 1;
}

static int cfg_wans_subset(const struct app_config *sub, const struct app_config *sup)
{
    for (int i = 0; i < sub->wan_count; i++) {
        if (!cfg_has_wan_ifname(sup, sub->wans[i].ifname))
            return 0;
    }
    return 1;
}

static int cfg_has_lan_row_addition(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < new->local_count; i++) {
        if (!config_local_ifname_in_cfg(old, new->locals[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_wan_row_addition(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < new->wan_count; i++) {
        if (!cfg_has_wan_ifname(old, new->wans[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_lan_row_removal(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->local_count; i++) {
        if (!config_local_ifname_in_cfg(new, old->locals[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_wan_row_removal(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->wan_count; i++) {
        if (!cfg_has_wan_ifname(new, old->wans[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_iface_addition(const struct app_config *old, const struct app_config *new)
{
    return cfg_has_lan_row_addition(old, new) || cfg_has_wan_row_addition(old, new);
}

static int cfg_has_iface_removal(const struct app_config *old, const struct app_config *new)
{
    return cfg_has_lan_row_removal(old, new) || cfg_has_wan_row_removal(old, new);
}

static const struct local_config *local_by_ifname(const struct app_config *cfg,
                                                  const char *ifname)
{
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return &cfg->locals[i];
    }
    return NULL;
}

static const struct wan_config *wan_by_ifname(const struct app_config *cfg, const char *ifname)
{
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return &cfg->wans[i];
    }
    return NULL;
}

static int local_db_equal(const struct local_config *a, const struct local_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0;
}

static int wan_db_equal(const struct wan_config *a, const struct wan_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0 &&
           a->dst_ip == b->dst_ip &&
           a->window_size == b->window_size &&
           a->dataplane == b->dataplane;
}

static int cfg_shared_ifaces_unchanged(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->local_count; i++) {
        const char *ifn = old->locals[i].ifname;
        const struct local_config *nl = local_by_ifname(new, ifn);
        if (nl && !local_db_equal(&old->locals[i], nl))
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        const char *ifn = old->wans[i].ifname;
        const struct wan_config *nw = wan_by_ifname(new, ifn);
        if (nw && !wan_db_equal(&old->wans[i], nw))
            return 0;
    }
    return 1;
}

int ne_iface_reload_can_add(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new || !old->profile_count)
        return 0;
    if (!cfg_locals_subset(old, new) || !cfg_wans_subset(old, new))
        return 0;
    return cfg_has_iface_addition(old, new);
}

int ne_iface_reload_can_remove(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new)
        return 0;
    if (!cfg_locals_subset(new, old) || !cfg_wans_subset(new, old))
        return 0;
    return cfg_has_iface_removal(old, new);
}

int ne_iface_reload_can_delta(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new || !old->profile_count)
        return 0;
    if (!cfg_has_iface_addition(old, new) && !cfg_has_iface_removal(old, new))
        return 0;
    if (!cfg_shared_ifaces_unchanged(old, new))
        return 0;
    return 1;
}

int ne_iface_reload_is_add_only(const struct app_config *old, const struct app_config *new)
{
    if (!ne_iface_reload_can_add(old, new))
        return 0;
    return cfg_has_iface_addition(old, new) && !cfg_has_iface_removal(old, new);
}

int ne_iface_reload_is_edit_only(const struct app_config *old, const struct app_config *new)
{
    if (!forwarder_same_topology(old, new))
        return 0;
    if (ne_iface_reload_can_add(old, new) ||
        ne_iface_reload_can_remove(old, new) ||
        ne_iface_reload_can_delta(old, new))
        return 0;
    if (cfg_locals_subset(old, new) && cfg_wans_subset(old, new) &&
        cfg_locals_subset(new, old) && cfg_wans_subset(new, old) &&
        !cfg_has_iface_addition(old, new) && !cfg_has_iface_removal(old, new)) {
        for (int i = 0; i < old->local_count; i++) {
            const struct local_config *nl = local_by_ifname(new, old->locals[i].ifname);
            if (nl && !local_db_equal(&old->locals[i], nl))
                return 1;
        }
        for (int i = 0; i < old->wan_count; i++) {
            const struct wan_config *nw = wan_by_ifname(new, old->wans[i].ifname);
            if (nw && !wan_db_equal(&old->wans[i], nw))
                return 1;
        }
    }
    return 0;
}

int ne_iface_reload_any_predicate(const struct app_config *old, const struct app_config *new)
{
    return ne_iface_reload_can_add(old, new) ||
           ne_iface_reload_can_remove(old, new) ||
           ne_iface_reload_can_delta(old, new);
}

enum ne_iface_reload_path ne_iface_reload_classify(const struct app_config *old,
                                                   const struct app_config *new)
{
    if (ne_iface_reload_is_add_only(old, new))
        return NE_IFACE_RELOAD_PATH_ADD_ONLY;
    if (ne_iface_reload_can_delta(old, new))
        return NE_IFACE_RELOAD_PATH_DELTA;
    if (ne_iface_reload_can_add(old, new))
        return NE_IFACE_RELOAD_PATH_ADD;
    if (ne_iface_reload_can_remove(old, new))
        return NE_IFACE_RELOAD_PATH_REMOVE;
    if (ne_iface_reload_is_edit_only(old, new))
        return NE_IFACE_RELOAD_PATH_EDIT;
    return NE_IFACE_RELOAD_PATH_NONE;
}
