#include "../../../inc/core/kernel_bridge.h"
#include "../../../inc/db/db_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/stat.h>

#define KERNEL_BRIDGE_SLAVE_MAX 64
#define KERNEL_BRIDGE_MASTER_MAX 16
#define KERNEL_BRIDGE_PAIRS_FILE NE_STATE_DIR "/bridge_pairs.conf"

struct kernel_bridge_slave {
    char ifname[IF_NAMESIZE];
    char master[IF_NAMESIZE];
};

static int parse_bridge_link_line(const char *line, char *ifname_out, char *master_out)
{
    const char *p;
    const char *name_end;
    const char *master;
    size_t nlen;

    if (!line || !ifname_out || !master_out)
        return -1;

    master = strstr(line, " master ");
    if (!master)
        return -1;

    p = strchr(line, ':');
    if (!p)
        return -1;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;

    name_end = strchr(p, ':');
    if (!name_end || name_end >= master)
        return -1;

    nlen = (size_t)(name_end - p);
    if (nlen == 0 || nlen >= IF_NAMESIZE)
        return -1;

    memcpy(ifname_out, p, nlen);
    ifname_out[nlen] = '\0';

    master += strlen(" master ");
    nlen = 0;
    while (master[nlen] && master[nlen] != ' ' && master[nlen] != '\t' &&
           master[nlen] != '\n' && master[nlen] != '\r')
        nlen++;
    if (nlen == 0 || nlen >= IF_NAMESIZE)
        return -1;

    memcpy(master_out, master, nlen);
    master_out[nlen] = '\0';
    return 0;
}

static int kernel_bridge_slaves_collect(struct kernel_bridge_slave *out, int max_out)
{
    FILE *fp;
    char line[512];
    int n = 0;

    if (!out || max_out <= 0)
        return 0;

    fp = popen("bridge link show 2>/dev/null", "r");
    if (!fp) {
        fprintf(stderr, "[BR] bridge link show failed\n");
        return 0;
    }

    while (fgets(line, sizeof(line), fp) && n < max_out) {
        if (parse_bridge_link_line(line, out[n].ifname, out[n].master) != 0)
            continue;
        n++;
    }
    pclose(fp);
    return n;
}

static int find_local_index_by_ifname(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return -1;
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int find_wan_index_by_ifname(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return -1;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int profile_owns_local_idx(const struct profile_config *p, int local_idx)
{
    for (int i = 0; i < p->local_count; i++) {
        if (p->local_indices[i] == local_idx)
            return 1;
    }
    return 0;
}

static int profile_owns_wan_cfg(const struct profile_config *p, int wan_cfg_idx)
{
    for (int i = 0; i < p->wan_count; i++) {
        if (p->wan_indices[i] == wan_cfg_idx)
            return 1;
    }
    return 0;
}

static void profile_commit_bridge_pair(struct app_config *cfg, struct profile_config *p,
                                       int local_idx, int wan_cfg_idx, const char *bridge_id)
{
    int wan_dp;

    if (local_idx < 0 || wan_cfg_idx < 0)
        return;
    if (p->bridge_count >= MAX_BRIDGES_PER_PROFILE)
        return;

    wan_dp = config_wan_cfg_to_dp(cfg, wan_cfg_idx);
    if (wan_dp < 0)
        return;

    p->bridges[p->bridge_count].local_idx = local_idx;
    p->bridges[p->bridge_count].wan_dp = wan_dp;
    p->bridge_count++;

    fprintf(stderr, "[BR] pair profile=%s master=%s LAN %s <-> WAN %s (dp=%d)\n",
            p->name, bridge_id ? bridge_id : "?",
            cfg->locals[local_idx].ifname,
            cfg->wans[wan_cfg_idx].ifname, wan_dp);
}

static void profile_log_members(const struct app_config *cfg, const struct profile_config *p)
{
    if (p->bridge_count > 0)
        return;
    fprintf(stderr,
            "[BR] profile %s: no bridge pairs (lan=%d wan=%d)\n",
            p->name, p->local_count, p->wan_count);
    (void)cfg;
}

static void kernel_bridge_state_dir_ensure(void)
{
    mkdir(NE_STATE_DIR, 0755);
}

static void kernel_bridge_save_persisted(const struct app_config *cfg)
{
    FILE *fp;
    int n = 0;

    if (!cfg)
        return;

    kernel_bridge_state_dir_ensure();
    fp = fopen(KERNEL_BRIDGE_PAIRS_FILE, "w");
    if (!fp) {
        fprintf(stderr, "[BR] failed to save %s\n", KERNEL_BRIDGE_PAIRS_FILE);
        return;
    }

    fprintf(fp, "# network-encryptor LAN<->WAN pairs (persisted)\n");
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];

        if (!p->enabled)
            continue;
        for (int bi = 0; bi < p->bridge_count; bi++) {
            int li = p->bridges[bi].local_idx;
            int wi = config_wan_dp_to_cfg(cfg, p->bridges[bi].wan_dp);

            if (li < 0 || li >= cfg->local_count || wi < 0 || wi >= cfg->wan_count)
                continue;
            fprintf(fp, "%s %s %s\n", p->name,
                    cfg->locals[li].ifname, cfg->wans[wi].ifname);
            n++;
        }
    }
    fclose(fp);
    if (n > 0)
        fprintf(stderr, "[BR] saved %d pair(s) to %s\n", n, KERNEL_BRIDGE_PAIRS_FILE);
}

static int kernel_bridge_load_persisted(struct app_config *cfg)
{
    FILE *fp;
    char line[256];
    char prof_name[64];
    char lan[IF_NAMESIZE];
    char wan[IF_NAMESIZE];
    int loaded = 0;

    if (!cfg)
        return 0;

    fp = fopen(KERNEL_BRIDGE_PAIRS_FILE, "r");
    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp)) {
        int li;
        int wi;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        if (sscanf(line, "%63s %15s %15s", prof_name, lan, wan) != 3)
            continue;

        li = find_local_index_by_ifname(cfg, lan);
        wi = find_wan_index_by_ifname(cfg, wan);
        if (li < 0 || wi < 0)
            continue;

        for (int pi = 0; pi < cfg->profile_count; pi++) {
            struct profile_config *p = &cfg->profiles[pi];

            if (!p->enabled || strcmp(p->name, prof_name) != 0)
                continue;
            if (!profile_owns_local_idx(p, li) || !profile_owns_wan_cfg(p, wi))
                continue;
            profile_commit_bridge_pair(cfg, p, li, wi, "persisted");
            loaded++;
        }
    }
    fclose(fp);
    if (loaded > 0)
        fprintf(stderr, "[BR] using %d persisted pair(s) from %s\n",
                loaded, KERNEL_BRIDGE_PAIRS_FILE);
    return loaded;
}

static void kernel_bridge_discover_from_slaves(struct app_config *cfg,
                                               const struct kernel_bridge_slave *slaves,
                                               int slave_count)
{
    char masters[KERNEL_BRIDGE_MASTER_MAX][IF_NAMESIZE];
    int master_count = 0;

    for (int si = 0; si < slave_count; si++) {
        int found = 0;

        for (int mi = 0; mi < master_count; mi++) {
            if (strcmp(masters[mi], slaves[si].master) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && master_count < KERNEL_BRIDGE_MASTER_MAX) {
            strncpy(masters[master_count], slaves[si].master, IF_NAMESIZE - 1);
            masters[master_count][IF_NAMESIZE - 1] = '\0';
            master_count++;
        }
    }

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        struct profile_config *p = &cfg->profiles[pi];

        if (!p->enabled)
            continue;

        for (int mi = 0; mi < master_count; mi++) {
            int local_idx = -1;
            int wan_cfg = -1;
            int lan_n = 0;
            int wan_n = 0;

            for (int si = 0; si < slave_count; si++) {
                int li;
                int wi;

                if (strcmp(slaves[si].master, masters[mi]) != 0)
                    continue;

                li = find_local_index_by_ifname(cfg, slaves[si].ifname);
                if (li >= 0 && profile_owns_local_idx(p, li)) {
                    lan_n++;
                    if (local_idx < 0)
                        local_idx = li;
                    continue;
                }

                wi = find_wan_index_by_ifname(cfg, slaves[si].ifname);
                if (wi >= 0 && profile_owns_wan_cfg(p, wi)) {
                    wan_n++;
                    if (wan_cfg < 0)
                        wan_cfg = wi;
                }
            }

            if (local_idx < 0 && wan_cfg < 0)
                continue;
            if (local_idx < 0 || wan_cfg < 0) {
                fprintf(stderr,
                        "[BR] profile=%s master=%s incomplete (lan=%d wan=%d)\n",
                        p->name, masters[mi], lan_n, wan_n);
                continue;
            }
            if (lan_n > 1 || wan_n > 1) {
                fprintf(stderr,
                        "[BR] profile=%s master=%s skipped — multiple LAN/WAN\n",
                        p->name, masters[mi]);
                continue;
            }

            profile_commit_bridge_pair(cfg, p, local_idx, wan_cfg, masters[mi]);
        }

        profile_log_members(cfg, p);
    }
}

void kernel_bridge_refresh_profile_pairs(struct app_config *cfg)
{
    struct kernel_bridge_slave slaves[KERNEL_BRIDGE_SLAVE_MAX];
    int slave_count;

    if (!cfg)
        return;

    for (int pi = 0; pi < cfg->profile_count; pi++)
        cfg->profiles[pi].bridge_count = 0;

    slave_count = kernel_bridge_slaves_collect(slaves, KERNEL_BRIDGE_SLAVE_MAX);
    if (slave_count > 0) {
        fprintf(stderr, "[BR] discovered from kernel bridge (%d slave(s))\n", slave_count);
        kernel_bridge_discover_from_slaves(cfg, slaves, slave_count);
        kernel_bridge_save_persisted(cfg);
        return;
    }

    if (kernel_bridge_load_persisted(cfg) > 0)
        return;

    fprintf(stderr,
            "[BR] no kernel br and no persisted pairs — set up br on first start\n");
    for (int pi = 0; pi < cfg->profile_count; pi++)
        profile_log_members(cfg, &cfg->profiles[pi]);
}
