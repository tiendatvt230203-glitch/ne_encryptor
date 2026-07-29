#include "l4pqc_rss.h"
#include "l4pqc_test_cfg.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>

static const uint8_t k_static_key[32] = { L4PQC_STATIC_KEY };

static int parse_mac(const char *s, uint8_t mac_out[6])
{
    unsigned int b[6];

    if (!s || !mac_out)
        return -1;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac_out[i] = (uint8_t)b[i];
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <lan_if> <wan_if> <lan_mac>\n"
            "example: sudo %s eno2 eno4 3c:ec:ef:c2:21:d0\n",
            prog, prog);
}

int l4pqc_config_from_args(int argc, char **argv, struct l4pqc_config *cfg)
{
    if (!cfg)
        return -1;
    if (argc < 4) {
        usage(argv[0]);
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->lan_if, argv[1], sizeof(cfg->lan_if) - 1);
    strncpy(cfg->wan_if, argv[2], sizeof(cfg->wan_if) - 1);
    if (parse_mac(argv[3], cfg->lan_mac) != 0) {
        fprintf(stderr, "[L4PQC] bad lan_mac (use aa:bb:cc:dd:ee:ff)\n");
        return -1;
    }
    cfg->has_lan_mac = 1;
    cfg->queue_count = 0;
    cfg->policy_wire_id = 1;
    cfg->profile_id = 1;
    cfg->policy_id = 1;
    memcpy(cfg->key, k_static_key, sizeof(k_static_key));
    cfg->key_len = (int)sizeof(k_static_key);
    for (int i = 0; i < L4PQC_MAX_QUEUES; i++)
        cfg->cpu_map[i] = L4PQC_CPU_NO_PIN;

    if (if_nametoindex(cfg->lan_if) == 0) {
        fprintf(stderr, "[L4PQC] LAN not found: %s\n", cfg->lan_if);
        return -1;
    }
    if (if_nametoindex(cfg->wan_if) == 0) {
        fprintf(stderr, "[L4PQC] WAN not found: %s\n", cfg->wan_if);
        return -1;
    }
    return 0;
}
