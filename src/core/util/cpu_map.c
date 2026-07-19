#include "../../../inc/core/cpu_map.h"

#include <stdio.h>
#include <string.h>

int ne_cpu_map_validate(void)
{
    uint8_t seen_io[256];
    uint8_t seen_crypto[256];
    const uint8_t *io_groups[] = {
        NE_CPU_RX_LAN, NE_CPU_TX_LAN, NE_CPU_TX_WAN, NE_CPU_RX_WAN,
    };
    const uint32_t io_counts[] = {
        NE_RX_LAN_SLOTS, NE_TX_SLOTS, NE_TX_WAN_SLOTS, NE_RX_WAN_SLOTS,
    };
    const char *io_names[] = { "RX_LAN", "TX_LAN", "TX_WAN", "RX_WAN" };

    memset(seen_io, 0, sizeof(seen_io));
    memset(seen_crypto, 0, sizeof(seen_crypto));

    for (int g = 0; g < 4; g++) {
        for (uint32_t i = 0; i < io_counts[g]; i++) {
            uint8_t c = io_groups[g][i];
            if (seen_io[c]) {
                fprintf(stderr, "[DP-CONF] duplicate core %u in %s\n",
                        (unsigned)c, io_names[g]);
                return -1;
            }
            seen_io[c] = 1;
        }
    }

    for (uint32_t i = 0; i < NE_CRYPTO_WORKERS; i++) {
        uint8_t c = NE_CPU_CRYPTO[i];
        if (seen_crypto[c]) {
            fprintf(stderr, "[DP-CONF] duplicate core %u in CRYPTO\n", (unsigned)c);
            return -1;
        }
        if (seen_io[c]) {
            fprintf(stderr, "[DP-CONF] CRYPTO core %u overlaps RX/TX\n", (unsigned)c);
            return -1;
        }
        seen_crypto[c] = 1;
    }

    for (uint32_t i = 0; i < NE_BYPASS_WORKERS; i++) {
        uint8_t c = NE_CPU_BYPASS[i];
        if (seen_crypto[c]) {
            fprintf(stderr, "[DP-CONF] BYPASS core %u overlaps CRYPTO\n", (unsigned)c);
            return -1;
        }
    }

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
    fprintf(stderr, "\n[DP-CONF] BYPASS (%u):", (unsigned)NE_BYPASS_WORKERS);
    for (uint32_t i = 0; i < NE_BYPASS_WORKERS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_BYPASS[i]);
    fprintf(stderr, "\n[DP-CONF] TX_WAN (%u):", (unsigned)NE_TX_WAN_SLOTS);
    for (uint32_t i = 0; i < NE_TX_WAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_TX_WAN[i]);
    fprintf(stderr, "\n[DP-CONF] RX_WAN (%u):", (unsigned)NE_RX_WAN_SLOTS);
    for (uint32_t i = 0; i < NE_RX_WAN_SLOTS; i++)
        fprintf(stderr, " %u", (unsigned)NE_CPU_RX_WAN[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}
