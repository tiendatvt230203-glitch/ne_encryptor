#ifndef CPU_MAP_H
#define CPU_MAP_H

#include <stdint.h>


static const uint8_t NE_CPU_RX_LAN[]  = { 0u };
static const uint8_t NE_CPU_TX_LAN[]  = { 1u, 2u };
static const uint8_t NE_CPU_CRYPTO[]  = { 3u, 4u, 5u, 6u, 7u, 8u };
static const uint8_t NE_CPU_TX_WAN[]  = { 9u, 10u };
static const uint8_t NE_CPU_RX_WAN[]  = { 11u };
/* Bypass on I/O cores only — never CRYPTO. Append cores here to scale. */
static const uint8_t NE_CPU_BYPASS[]  = { 1u, 2u, 9u, 10u, 0u, 11u };

#define NE_RX_LAN_SLOTS   ((uint32_t)(sizeof(NE_CPU_RX_LAN) / sizeof(NE_CPU_RX_LAN[0])))
#define NE_RX_WAN_SLOTS   ((uint32_t)(sizeof(NE_CPU_RX_WAN) / sizeof(NE_CPU_RX_WAN[0])))
#define NE_TX_SLOTS       ((uint32_t)(sizeof(NE_CPU_TX_LAN) / sizeof(NE_CPU_TX_LAN[0])))
#define NE_TX_WAN_SLOTS   ((uint32_t)(sizeof(NE_CPU_TX_WAN) / sizeof(NE_CPU_TX_WAN[0])))
#define NE_CRYPTO_WORKERS ((uint32_t)(sizeof(NE_CPU_CRYPTO) / sizeof(NE_CPU_CRYPTO[0])))
#define NE_BYPASS_WORKERS ((uint32_t)(sizeof(NE_CPU_BYPASS) / sizeof(NE_CPU_BYPASS[0])))

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(NE_RX_LAN_SLOTS >= 1u, "NE_CPU_RX_LAN needs at least one core");
_Static_assert(NE_RX_WAN_SLOTS >= 1u, "NE_CPU_RX_WAN needs at least one core");
_Static_assert(NE_TX_SLOTS >= 1u, "NE_CPU_TX_LAN needs at least one core");
_Static_assert(NE_TX_WAN_SLOTS >= 1u, "NE_CPU_TX_WAN needs at least one core");
_Static_assert(NE_CRYPTO_WORKERS >= 1u, "NE_CPU_CRYPTO needs at least one core");
_Static_assert(NE_BYPASS_WORKERS >= 1u, "NE_CPU_BYPASS needs at least one core");
_Static_assert(NE_TX_SLOTS == NE_TX_WAN_SLOTS,
               "NE_CPU_TX_LAN[] and NE_CPU_TX_WAN[] must have the same length");
#endif

static inline uint8_t ne_cpu_rx_lan(uint32_t slot)
{
    return NE_CPU_RX_LAN[slot < NE_RX_LAN_SLOTS ? slot : 0u];
}

static inline uint8_t ne_cpu_rx_wan(uint32_t slot)
{
    return NE_CPU_RX_WAN[slot < NE_RX_WAN_SLOTS ? slot : 0u];
}

static inline uint8_t ne_cpu_tx_lan(uint32_t slot)
{
    return NE_CPU_TX_LAN[slot < NE_TX_SLOTS ? slot : 0u];
}

static inline uint8_t ne_cpu_tx_wan(uint32_t slot)
{
    return NE_CPU_TX_WAN[slot < NE_TX_WAN_SLOTS ? slot : 0u];
}

static inline uint8_t ne_cpu_crypto(uint32_t worker)
{
    return NE_CPU_CRYPTO[worker < NE_CRYPTO_WORKERS ? worker : 0u];
}

static inline uint8_t ne_cpu_bypass(uint32_t worker)
{
    return NE_CPU_BYPASS[worker < NE_BYPASS_WORKERS ? worker : 0u];
}

int ne_cpu_map_validate(void);
void ne_cpu_map_log(void);

#endif
