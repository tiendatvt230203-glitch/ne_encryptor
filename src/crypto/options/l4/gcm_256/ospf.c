#include "../../../../../inc/crypto/crypto_option.h"
#include "../../common/opt_no_frag_ops.h"

/* L4 has no meaningful ports for ICMP/OSPF — pass through. */
static int ospf_encrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    (void)ctx;
    (void)pkt;
    (void)pkt_len;
    return 0;
}

static int ospf_decrypt(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len)
{
    (void)ctx;
    (void)pkt;
    (void)pkt_len;
    return 0;
}

CRYPTO_OPS_PLAIN(crypto_opt_l4_gcm256_ospf_ops, ospf_encrypt, ospf_decrypt)