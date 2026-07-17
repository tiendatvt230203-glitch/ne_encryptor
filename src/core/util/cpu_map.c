#include "../../../inc/core/cpu_map.h"

#include <stdio.h>
#include <string.h>

int ne_cpu_map_validate(void)
{
    uint8_t seen[256];
    int n = 0;
    const uint8_t *groups[] = {
        NE_CPU_RX_LAN, NE_CPU_TX_LAN, NE_CPU_CRYPTO, NE_CPU_TX_WAN, NE_CPU_RX_WAN,
    };
    const uint32_t counts[] = {
        NE_RX_LAN_SLOTS, NE_TX_SLOTS, NE_CRYPTO_WORKERS, NE_TX_WAN_SLOTS, NE_RX_WAN_SLOTS,
    };
    const char *names[] = { "RX_LAN", "TX_LAN", "CRYPTO", "TX_WAN", "RX_WAN" };

    memset(seen, 0, sizeof(seen));
    for (int g = 0; g < 5; g++) {
        for (uint32_t i = 0; i < counts[g]; i++) {
            uint8_t c = groups[g][i];
            if (seen[c]) {
                fprintf(stderr, "[DP-CONF] duplicate core %u in %s\n",
                        (unsigned)c, names[g]);
                return -1;
            }
            seen[c] = 1;
            n++;
        }
    }
    (void)n;
    return 0;
}

void ne_cpu_map_log(void)
{
    ne_cpu_map_validate();

    fprintf(stderr, "[DP-CONF] RX_LAN (%u):", (unsigned)NE_RX_LAN_SLOTS);
    for (uint32_t i = 0; i < NE_RX_LAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_RX_LAN[i]);
    fprintf(stderr, "\n[DP-CONF] TX_LAN (%u):", (unsigned)NE_TX_SLOTS);
    for (uint32_t i = 0; i < NE_TX_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_TX_LAN[i]);
    fprintf(stderr, "\n[DP-CONF] CRYPTO (%u):", (unsigned)NE_CRYPTO_WORKERS);
    for (uint32_t i = 0; i < NE_CRYPTO_WORKERS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_CRYPTO[i]);
    fprintf(stderr, "\n[DP-CONF] TX_WAN (%u):", (unsigned)NE_TX_WAN_SLOTS);
    for (uint32_t i = 0; i < NE_TX_WAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_TX_WAN[i]);
    fprintf(stderr, "\n[DP-CONF] RX_WAN (%u):", (unsigned)NE_RX_WAN_SLOTS);
    for (uint32_t i = 0; i < NE_RX_WAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_RX_WAN[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}
