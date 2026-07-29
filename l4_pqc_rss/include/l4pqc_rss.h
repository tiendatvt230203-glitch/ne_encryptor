#ifndef L4PQC_RSS_H
#define L4PQC_RSS_H

#include <net/if.h>
#include <stdint.h>

#define L4PQC_MAX_QUEUES  16
#define L4PQC_FRAME       2048u
#define L4PQC_N_FRAMES    8192u
#define L4PQC_RING        2048u
#define L4PQC_BATCH       64u
#define L4PQC_CPU_NO_PIN  0xFFu

struct l4pqc_config {
    char lan_if[IF_NAMESIZE];
    char wan_if[IF_NAMESIZE];
    uint8_t lan_mac[6];
    int  has_lan_mac;
    int  queue_count;
    uint8_t cpu_map[L4PQC_MAX_QUEUES];
    uint8_t policy_wire_id;
    int  profile_id;
    int  policy_id;
    uint8_t key[32];
    int  key_len;
};

int  l4pqc_config_from_args(int argc, char **argv, struct l4pqc_config *cfg);
void l4pqc_run(const struct l4pqc_config *cfg);
void l4pqc_stop(void);

#endif
