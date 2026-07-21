#include "../../inc/core/config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <netinet/in.h>

static uint32_t ipv4_prefix_to_mask_be(int prefix_len) {
    if (prefix_len <= 0)
        return 0;
    if (prefix_len >= 32)
        return htonl(0xFFFFFFFFu);
    return htonl(0xFFFFFFFFu << (32 - prefix_len));
}

static int ipv4_mask_be_is_contiguous(uint32_t mask_be) {
    uint32_t m = ntohl(mask_be);
    if (m == 0)
        return 1;
    uint32_t inv = ~m;
    return (inv & (inv + 1u)) == 0;
}

static int parse_ipv4_netmask_be(const char *s, uint32_t *mask_out) {
    struct in_addr a;

    if (!s || !mask_out || !s[0])
        return -1;
    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;
    if (!ipv4_mask_be_is_contiguous(a.s_addr))
        return -1;
    *mask_out = a.s_addr;
    return 0;
}

static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    char buf[128];
    const char *ip_part;
    const char *suffix = NULL;

    if (!str || !ip || !netmask)
        return -1;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        suffix = slash + 1;
        while (*suffix == ' ' || *suffix == '\t')
            suffix++;
        if (!suffix[0])
            return -1;
    }

    ip_part = buf;
    while (*ip_part == ' ' || *ip_part == '\t')
        ip_part++;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) != 1)
        return -1;

    *ip = addr.s_addr;

    if (suffix) {
        if (strchr(suffix, '.')) {
            if (parse_ipv4_netmask_be(suffix, netmask) != 0)
                return -1;
        } else {
            char *end = NULL;
            long plen = strtol(suffix, &end, 10);
            if (!end || *end != '\0' || plen < 0 || plen > 32)
                return -1;
            *netmask = ipv4_prefix_to_mask_be((int)plen);
        }
    } else {
        *netmask = ipv4_prefix_to_mask_be(32);
    }

    if (network)
        *network = *ip & *netmask;

    return 0;
}

static int parse_hex_bytes(const char *str, uint8_t *out, int expected_len) {
    int len = strlen(str);
    if (len != expected_len * 2)
        return -1;

    for (int i = 0; i < expected_len; i++) {
        unsigned int val;
        if (sscanf(str + i * 2, "%2x", &val) != 1)
            return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

int config_policy_db_id_taken(const struct app_config *cfg, int db_id)
{
    if (!cfg || db_id <= 0)
        return 0;
    for (int i = 0; i < cfg->policy_count; i++) {
        if (cfg->policies[i].db_id == db_id)
            return 1;
    }
    return 0;
}

int config_policy_pkt_tag_taken(const struct app_config *cfg, int pkt_tag)
{
    if (!cfg)
        return 0;
    for (int i = 0; i < cfg->policy_count; i++) {
        if (cfg->policies[i].id == pkt_tag)
            return 1;
    }
    return 0;
}

int config_local_ifname_in_cfg(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

int config_local_owner_profile(const struct app_config *cfg, int local_idx, int skip_profile_id)
{
    if (!cfg || local_idx < 0 || local_idx >= cfg->local_count)
        return 0;
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];

        if (p->id == skip_profile_id)
            continue;
        for (int li = 0; li < p->local_count; li++) {
            if (p->local_indices[li] == local_idx)
                return p->id;
        }
    }
    return 0;
}

int config_wan_dataplane_owner_profile(const struct app_config *cfg, int wan_idx, int skip_profile_id)
{
    if (!cfg || wan_idx < 0 || wan_idx >= cfg->wan_count)
        return 0;
    if (!cfg->wans[wan_idx].dataplane)
        return 0;
    return config_wan_owner_profile(cfg, wan_idx, skip_profile_id);
}

int config_wan_profile_weight(const struct app_config *cfg, int wan_idx)
{
    int best = 0;

    if (!cfg || wan_idx < 0 || wan_idx >= cfg->wan_count)
        return 0;
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];

        for (int wi = 0; wi < p->wan_count; wi++) {
            if (p->wan_indices[wi] != wan_idx)
                continue;
            if (p->wan_bandwidth_weight[wi] > best)
                best = p->wan_bandwidth_weight[wi];
        }
    }
    return best;
}

int config_wan_live(const struct app_config *cfg, int wan_idx)
{
    if (!cfg || wan_idx < 0 || wan_idx >= cfg->wan_count)
        return 0;
    return cfg->wans[wan_idx].dataplane ? 1 : 0;
}

int config_wan_live_in_cfg(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return config_wan_live(cfg, i);
    }
    return 0;
}

int config_count_dataplane_wans(const struct app_config *cfg)
{
    int n = 0;

    if (!cfg)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (config_wan_live(cfg, i))
            n++;
    }
    return n;
}

int config_wan_cfg_to_dp(const struct app_config *cfg, int cfg_idx)
{
    if (!config_wan_live(cfg, cfg_idx))
        return -1;
    int dp = 0;
    for (int i = 0; i < cfg_idx; i++) {
        if (config_wan_live(cfg, i))
            dp++;
    }
    return dp;
}

int config_wan_dp_to_cfg(const struct app_config *cfg, int dp_idx)
{
    if (!cfg || dp_idx < 0)
        return -1;
    int seen = 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (!config_wan_live(cfg, i))
            continue;
        if (seen == dp_idx)
            return i;
        seen++;
    }
    return -1;
}

int config_wan_owner_profile(const struct app_config *cfg, int wan_idx, int skip_profile_id)
{
    if (!cfg || wan_idx < 0 || wan_idx >= cfg->wan_count)
        return 0;
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];

        if (p->id == skip_profile_id)
            continue;
        for (int wi = 0; wi < p->wan_count; wi++) {
            if (p->wan_indices[wi] == wan_idx)
                return p->id;
        }
    }
    return 0;
}

static int profile_has_dup_index(const int *indices, int count)
{
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (indices[i] == indices[j])
                return 1;
        }
    }
    return 0;
}

static int config_validate_policy_db_ids_across_profiles(const struct app_config *cfg)
{
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *a = &cfg->profiles[pi];

        for (int pj = pi + 1; pj < cfg->profile_count; pj++) {
            const struct profile_config *b = &cfg->profiles[pj];

            for (int ai = 0; ai < a->policy_count; ai++) {
                int a_idx = a->policy_indices[ai];

                if (a_idx < 0 || a_idx >= cfg->policy_count)
                    continue;
                for (int bi = 0; bi < b->policy_count; bi++) {
                    int b_idx = b->policy_indices[bi];

                    if (b_idx < 0 || b_idx >= cfg->policy_count)
                        continue;
                    if (cfg->policies[a_idx].db_id <= 0)
                        continue;
                    if (cfg->policies[a_idx].db_id == cfg->policies[b_idx].db_id) {
                        fprintf(stderr,
                                "[VALIDATE] duplicate policy db_id=%d (profile %d and %d)\n",
                                cfg->policies[a_idx].db_id, a->id, b->id);
                        return -1;
                    }
                }
            }
        }
    }
    return 0;
}

static int config_validate_profiles(const struct app_config *cfg)
{
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];

        if (profile_has_dup_index(p->local_indices, p->local_count)) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: duplicate LAN binding in profile config\n",
                    p->id);
            return -1;
        }
        if (profile_has_dup_index(p->wan_indices, p->wan_count)) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: duplicate WAN binding in profile config\n",
                    p->id);
            return -1;
        }
        if (profile_has_dup_index(p->policy_indices, p->policy_count)) {
            fprintf(stderr,
                    "[VALIDATE] profile %d: duplicate policy binding in profile config\n",
                    p->id);
            return -1;
        }

        for (int li = 0; li < p->local_count; li++) {
            int idx = p->local_indices[li];
            int owner;

            if (idx < 0 || idx >= cfg->local_count)
                continue;
            owner = config_local_owner_profile(cfg, idx, p->id);
            if (owner > 0) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: LAN %s already used by profile %d\n",
                        p->id, cfg->locals[idx].ifname, owner);
                return -1;
            }
        }
        for (int wi = 0; wi < p->wan_count; wi++) {
            int idx = p->wan_indices[wi];
            int owner;

            if (idx < 0 || idx >= cfg->wan_count)
                continue;
            owner = config_wan_owner_profile(cfg, idx, p->id);
            if (owner > 0) {
                fprintf(stderr,
                        "[VALIDATE] profile %d: WAN %s already used by profile %d\n",
                        p->id, cfg->wans[idx].ifname, owner);
                return -1;
            }
        }
    }
    return config_validate_policy_db_ids_across_profiles(cfg);
}

int config_validate(struct app_config *cfg) {
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];

        if (local->ifname[0] == '\0') {
            fprintf(stderr, "LOCAL[%d]: interface not specified\n", i);
            return -1;
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];

        if (wan->ifname[0] == '\0') {
            fprintf(stderr, "WAN[%d]: interface not specified\n", i);
            return -1;
        }

        if (wan->window_size == 0) {
            fprintf(stderr, "WAN %s: window_kb not specified\n", wan->ifname);
            return -1;
        }
    }

    if (config_validate_profiles(cfg) != 0)
        return -1;
    return 0;
}

static int cidr_match_with_negate(int any_flag, int negate,
                                    uint32_t ip, uint32_t net, uint32_t mask) {
    if (any_flag)
        return 1;
    int in_cidr = ((ip & mask) == (net & mask));
    return negate ? !in_cidr : in_cidr;
}

int config_select_profile_for_local(const struct app_config *cfg, int local_idx) {
    if (!cfg || local_idx < 0 || local_idx >= cfg->local_count)
        return -1;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++) {
            if (p->local_indices[i] == local_idx)
                return pi;
        }
    }
    return -1;
}

static int policy_covers_ip(const struct crypto_policy *cp, uint32_t ip)
{
    int src_hit = 0, dst_hit = 0;

    if (!cp)
        return 0;
    /* Catch-all any/any: every IP is in scope. Otherwise only non-any sides. */
    if (cp->src_any && cp->dst_any)
        return 1;
    if (!cp->src_any)
        src_hit = cidr_match_with_negate(0, cp->src_negate, ip, cp->src_net, cp->src_mask);
    if (!cp->dst_any)
        dst_hit = cidr_match_with_negate(0, cp->dst_negate, ip, cp->dst_net, cp->dst_mask);
    return src_hit || dst_hit;
}

int config_local_policies_cover_ip(const struct app_config *cfg, int local_idx, uint32_t ip)
{
    if (!cfg || local_idx < 0 || local_idx >= cfg->local_count)
        return 0;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        int owns = 0;

        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++) {
            if (p->local_indices[i] == local_idx) {
                owns = 1;
                break;
            }
        }
        if (!owns)
            continue;

        for (int i = 0; i < p->policy_count; i++) {
            int poli = p->policy_indices[i];
            if (poli < 0 || poli >= cfg->policy_count)
                continue;
            if (policy_covers_ip(&cfg->policies[poli], ip))
                return 1;
        }
    }
    return 0;
}

static int crypto_policy_match_packet(const struct crypto_policy *cp,
                                      uint32_t src_ip, uint32_t dst_ip,
                                      uint16_t src_port, uint16_t dst_port,
                                      uint8_t protocol) {
    if (!cidr_match_with_negate(cp->src_any, cp->src_negate, src_ip, cp->src_net, cp->src_mask))
        return 0;
    if (!cidr_match_with_negate(cp->dst_any, cp->dst_negate, dst_ip, cp->dst_net, cp->dst_mask))
        return 0;

#if !CRYPTO_POLICY_MATCH_IP_ONLY
    if (cp->src_port_from >= 0 && cp->src_port_to >= 0) {
        if ((int)src_port < cp->src_port_from || (int)src_port > cp->src_port_to)
            return 0;
    }
    if (cp->dst_port_from >= 0 && cp->dst_port_to >= 0) {
        if ((int)dst_port < cp->dst_port_from || (int)dst_port > cp->dst_port_to)
            return 0;
    }
#endif

    if (cp->protocol == POLICY_PROTO_TCP_UDP) {
        if (protocol != 6 && protocol != 17)
            return 0;
    } else if (cp->protocol != POLICY_PROTO_ANY && cp->protocol != protocol) {
        return 0;
    }

    return 1;
}

const struct crypto_policy *config_select_crypto_policy(struct app_config *cfg, int profile_idx,
                                                        uint32_t src_ip, uint32_t dst_ip,
                                                        uint16_t src_port, uint16_t dst_port,
                                                        uint8_t protocol)
{
    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count)
        return NULL;

    const struct profile_config *p = &cfg->profiles[profile_idx];
    const struct crypto_policy *best = NULL;
    int best_priority = 0x7fffffff;
    int best_id = 0x7fffffff;

    for (int i = 0; i < p->policy_count; i++) {
        int pi = p->policy_indices[i];
        if (pi < 0 || pi >= cfg->policy_count)
            continue;

        const struct crypto_policy *cp = &cfg->policies[pi];
        int matched = crypto_policy_match_packet(cp, src_ip, dst_ip, src_port, dst_port, protocol);
        if (!matched)
            matched = crypto_policy_match_packet(cp, dst_ip, src_ip, dst_port, src_port, protocol);
        if (!matched)
            continue;

        if (!best ||
            cp->priority < best_priority ||
            (cp->priority == best_priority && cp->id < best_id)) {
            best = cp;
            best_priority = cp->priority;
            best_id = cp->id;
        }
    }

    return best;
}

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    return parse_ip_cidr(str, ip, netmask, network);
}

int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len) {
    return parse_hex_bytes(str, out, expected_len);
}