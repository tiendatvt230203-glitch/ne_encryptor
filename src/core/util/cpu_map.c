#include "../../../inc/core/util/cpu_map.h"

#include <stdio.h>

int ne_cpu_map_validate(void)
{
    return 0;
}

void ne_cpu_map_log(void)
{
    fprintf(stderr, "[DP-CONF] RX_LAN (%u):", (unsigned)NE_RX_LAN_SLOTS);
    for (uint32_t i = 0; i < NE_RX_LAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_RX_LAN[i]);
    fprintf(stderr, "\n[DP-CONF] TX (%u):", (unsigned)NE_TX_SLOTS);
    for (uint32_t i = 0; i < NE_TX_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_TX[i]);
    fprintf(stderr, "\n[DP-CONF] CRYPTO (%u):", (unsigned)NE_CRYPTO_WORKERS);
    for (uint32_t i = 0; i < NE_CRYPTO_WORKERS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_CRYPTO[i]);
    fprintf(stderr, "\n[DP-CONF] RX_WAN (%u):", (unsigned)NE_RX_WAN_SLOTS);
    for (uint32_t i = 0; i < NE_RX_WAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_RX_WAN[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}
