#include "../../../../../inc/crypto/crypto_option.h"
#include "../../common/opt_no_frag_ops.h"

/* L4 has no meaningful ports for ICMP/OSPF — pass through. */
static int icmp_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    (void)ctx;
    (void)pkt;
    (void)pkt_len;
    return 0;
}

static int icmp_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    (void)ctx;
    (void)pkt;
    (void)pkt_len;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l4_ctr128_icmp_ops, icmp_encrypt, icmp_decrypt)