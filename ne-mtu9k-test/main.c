#include "config.h"
#include "src/l2_crypto.h"
#include "src/xsk_pair.h"

#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static void on_stop(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void process_lan_to_wan(struct mtu9k_pair *p, uint8_t *pkt, uint32_t len)
{
#if MODE_L2_PQC
    int nlen = l2_encrypt(pkt, len, NE_PKT_MAX);
    if (nlen < 0)
        return;
    len = (uint32_t)nlen;
#endif
    (void)mtu9k_tx_pkt(p, &p->wan, pkt, len);
}

static void process_wan_to_lan(struct mtu9k_pair *p, uint8_t *pkt, uint32_t len)
{
#if MODE_L2_PQC
    if (l2_has_enc_marker(pkt, len)) {
        int nlen = l2_decrypt(pkt, len);
        if (nlen < 0)
            return;
        len = (uint32_t)nlen;
    }
#endif
    (void)mtu9k_tx_pkt(p, &p->lan, pkt, len);
}

int main(int argc, char **argv)
{
    struct mtu9k_pair pair;
    uint8_t pkt[NE_PKT_MAX];

    (void)argc;
    (void)argv;

    signal(SIGINT, on_stop);
    signal(SIGTERM, on_stop);

    if (l2_crypto_init() != 0) {
        fprintf(stderr, "[FATAL] l2_crypto_init failed\n");
        return 1;
    }
    if (mtu9k_pair_open(&pair, IF_LAN, IF_WAN) != 0) {
        fprintf(stderr, "[FATAL] mtu9k_pair_open failed\n");
        l2_crypto_cleanup();
        return 1;
    }

    while (!g_stop) {
        uint32_t len = 0;
        int r;
        int idle = 1;

        mtu9k_recycle(&pair, &pair.lan);
        mtu9k_recycle(&pair, &pair.wan);

        r = mtu9k_rx_pkt(&pair, &pair.lan, pkt, sizeof(pkt), &len);
        if (r > 0) {
            idle = 0;
            process_lan_to_wan(&pair, pkt, len);
        }

        r = mtu9k_rx_pkt(&pair, &pair.wan, pkt, sizeof(pkt), &len);
        if (r > 0) {
            idle = 0;
            process_wan_to_lan(&pair, pkt, len);
        }

        if (idle)
            usleep(50);
    }

    mtu9k_pair_close(&pair);
    l2_crypto_cleanup();
    return 0;
}
