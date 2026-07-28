#include "../../../../inc/core/iface_config_diff.h"
#include "../../../../inc/core/forwarder_reload.h"

#include <string.h>

static const struct crypto_policy *policy_by_db_id(const struct app_config *cfg, int db_id)
{
    for (int i = 0; i < cfg->policy_count; i++) {
        if (cfg->policies[i].db_id == db_id)
            return &cfg->policies[i];
    }
    return NULL;
}

static int policy_fields_equal(const struct crypto_policy *a, const struct crypto_policy *b)
{
    return a->id == b->id &&
           a->db_id == b->db_id &&
           a->priority == b->priority &&
           a->action == b->action &&
           a->protocol == b->protocol &&
           a->src_port_from == b->src_port_from &&
           a->src_port_to == b->src_port_to &&
           a->dst_port_from == b->dst_port_from &&
           a->dst_port_to == b->dst_port_to &&
           a->src_any == b->src_any &&
           a->dst_any == b->dst_any &&
           a->src_negate == b->src_negate &&
           a->dst_negate == b->dst_negate &&
           a->src_net == b->src_net &&
           a->src_mask == b->src_mask &&
           a->dst_net == b->dst_net &&
           a->dst_mask == b->dst_mask &&
           a->crypto_mode == b->crypto_mode &&
           a->aes_bits == b->aes_bits &&
           memcmp(a->key, b->key, AES_KEY_LEN) == 0;
}

int ne_iface_cfg_policies_unchanged(const struct app_config *old, const struct app_config *new)
{
    if (old->policy_count != new->policy_count)
        return 0;
    for (int i = 0; i < old->policy_count; i++) {
        int db_id = old->policies[i].db_id;
        const struct crypto_policy *np = policy_by_db_id(new, db_id);
        if (!np || !policy_fields_equal(&old->policies[i], np))
            return 0;
    }
    for (int i = 0; i < new->policy_count; i++) {
        int db_id = new->policies[i].db_id;
        const struct crypto_policy *op = policy_by_db_id(old, db_id);
        if (!op || !policy_fields_equal(op, &new->policies[i]))
            return 0;
    }
    return 1;
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

static int profile_db_unchanged(const struct profile_config *old,
                                const struct profile_config *new,
                                const struct app_config *ocfg,
                                const struct app_config *ncfg)
{
    if (old->id != new->id ||
        old->enabled != new->enabled ||
        old->bridge_enable != new->bridge_enable ||
        old->bridge_count != new->bridge_count ||
        old->policy_count != new->policy_count ||
        old->local_count != new->local_count ||
        old->wan_count != new->wan_count ||
        strcmp(old->name, new->name) != 0 ||
        strcmp(old->local_identity_fingerprint, new->local_identity_fingerprint) != 0 ||
        strcmp(old->peer_fingerprint, new->peer_fingerprint) != 0 ||
        old->pqc_is_initiator != new->pqc_is_initiator ||
        old->has_pqc_identity != new->has_pqc_identity ||
        strcmp(old->pqc_peer_pub, new->pqc_peer_pub) != 0)
        return 0;

    for (int i = 0; i < old->policy_count; i++) {
        int odb = ocfg->policies[old->policy_indices[i]].db_id;
        int found = 0;
        for (int j = 0; j < new->policy_count; j++) {
            int ndb = ncfg->policies[new->policy_indices[j]].db_id;
            if (odb == ndb) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    for (int j = 0; j < new->policy_count; j++) {
        int ndb = ncfg->policies[new->policy_indices[j]].db_id;
        int found = 0;
        for (int i = 0; i < old->policy_count; i++) {
            int odb = ocfg->policies[old->policy_indices[i]].db_id;
            if (odb == ndb) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }

    for (int i = 0; i < old->local_count; i++) {
        if (old->local_indices[i] != new->local_indices[i])
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        if (old->wan_indices[i] != new->wan_indices[i] ||
            old->wan_bandwidth_weight[i] != new->wan_bandwidth_weight[i])
            return 0;
    }
    for (int i = 0; i < old->bridge_count; i++) {
        if (old->bridges[i].local_idx != new->bridges[i].local_idx ||
            old->bridges[i].wan_dp != new->bridges[i].wan_dp)
            return 0;
    }
    return 1;
}

static int profiles_fully_unchanged(const struct app_config *old, const struct app_config *new)
{
    if (old->profile_count != new->profile_count)
        return 0;
    for (int i = 0; i < old->profile_count; i++) {
        const struct profile_config *op = &old->profiles[i];
        const struct profile_config *np = NULL;
        for (int j = 0; j < new->profile_count; j++) {
            if (new->profiles[j].id == op->id) {
                np = &new->profiles[j];
                break;
            }
        }
        if (!np || !profile_db_unchanged(op, np, old, new))
            return 0;
    }
    return 1;
}

int ne_iface_cfg_lan_wan_unchanged(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new)
        return 0;
    if (old->local_count != new->local_count ||
        old->wan_count != new->wan_count)
        return 0;

    for (int i = 0; i < old->local_count; i++) {
        const struct local_config *nl = local_by_ifname(new, old->locals[i].ifname);
        if (!nl || !local_db_equal(&old->locals[i], nl))
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        const struct wan_config *nw = wan_by_ifname(new, old->wans[i].ifname);
        if (!nw || !wan_db_equal(&old->wans[i], nw))
            return 0;
    }
    return 1;
}

int ne_iface_cfg_db_unchanged(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new)
        return 0;

    if (old->local_count != new->local_count ||
        old->wan_count != new->wan_count ||
        old->policy_count != new->policy_count ||
        old->profile_count != new->profile_count ||
        old->crypto_enabled != new->crypto_enabled ||
        old->encrypt_layer != new->encrypt_layer ||
        old->fake_protocol != new->fake_protocol ||
        old->fake_ethertype_ipv4 != new->fake_ethertype_ipv4 ||
        old->crypto_mode != new->crypto_mode ||
        old->aes_bits != new->aes_bits ||
        memcmp(old->crypto_key, new->crypto_key, AES_KEY_LEN) != 0 ||
        strcmp(old->bpf_file, new->bpf_file) != 0 ||
        strcmp(old->bpf_wan_file, new->bpf_wan_file) != 0)
        return 0;

    if (!ne_iface_cfg_lan_wan_unchanged(old, new))
        return 0;
    if (!ne_iface_cfg_policies_unchanged(old, new))
        return 0;

    for (int i = 0; i < old->profile_count; i++) {
        const struct profile_config *op = &old->profiles[i];
        const struct profile_config *np = NULL;
        for (int j = 0; j < new->profile_count; j++) {
            if (new->profiles[j].id == op->id) {
                np = &new->profiles[j];
                break;
            }
        }
        if (!np || !profile_db_unchanged(op, np, old, new))
            return 0;
    }
    return 1;
}

int ne_iface_cfg_tuning_only_change(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new || ne_iface_cfg_lan_wan_unchanged(old, new))
        return 0;
    if (!forwarder_same_topology(old, new))
        return 0;
    if (!ne_iface_cfg_policies_unchanged(old, new))
        return 0;
    return profiles_fully_unchanged(old, new);
}
