#include "../../../inc/crypto/crypto_option.h"

#include <stdatomic.h>

static __thread uint8_t g_worker_idx;
static atomic_uint_fast16_t g_pkt_id;
static uint32_t g_mtu = CRYPTO_OPT_FRAG_MTU_DEFAULT;

void crypto_option_bind_worker_idx(uint8_t worker_idx)
{
    g_worker_idx = worker_idx;
}

uint8_t crypto_option_worker_idx(void)
{
    return g_worker_idx;
}

uint16_t crypto_option_next_pkt_id(void)
{
    return (uint16_t)(atomic_fetch_add(&g_pkt_id, 1) & 0xFFFFu);
}

void crypto_option_set_mtu(uint32_t mtu)
{
    if (mtu > 0)
        g_mtu = mtu;
}

uint32_t crypto_option_get_mtu(void)
{
    return g_mtu;
}
