#include "config.h"
#include "src/l2_crypto.h"
#include "src/xsk_pair.h"

#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static void on_stop(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void set_eth_macs(uint8_t *pkt, const uint8_t dst[6], const uint8_t src[6])
{
    memcpy(pkt + 0, dst, 6);
    memcpy(pkt + 6, src, 6);
}

static uint32_t g_rx_lan, g_rx_wan, g_tx_lan, g_tx_wan, g_drop;
static uint32_t g_min_len = UINT32_MAX, g_max_len;

static void note_len(uint32_t len)
{
    if (len < g_min_len)
        g_min_len = len;
    if (len > g_max_len)
        g_max_len = len;
}

static void process_lan_to_wan(struct mtu9k_pair *p, uint8_t *pkt, uint32_t len)
{
    static const uint8_t remote[6] = REMOTE_MAC;
    int nlen;

    note_len(len);
    set_eth_macs(pkt, remote, p->wan.mac);

#if MODE_L2_PQC
    nlen = l2_encrypt(pkt, len, NE_PKT_MAX);
    if (nlen < 0) {
        g_drop++;
        return;
    }
    len = (uint32_t)nlen;
#endif

    if (mtu9k_tx_pkt(p, &p->wan, pkt, len) != 0) {
        g_drop++;
        return;
    }
    g_tx_wan++;
}

static void process_wan_to_lan(struct mtu9k_pair *p, uint8_t *pkt, uint32_t len)
{
    static const uint8_t remote[6] = REMOTE_MAC;
    int nlen;

    note_len(len);

#if MODE_L2_PQC
    if (l2_has_enc_marker(pkt, len)) {
        nlen = l2_decrypt(pkt, len);
        if (nlen < 0) {
            g_drop++;
            return;
        }
        len = (uint32_t)nlen;
    }
#endif

    set_eth_macs(pkt, remote, p->lan.mac);

    if (mtu9k_tx_pkt(p, &p->lan, pkt, len) != 0) {
        g_drop++;
        return;
    }
    g_tx_lan++;
}

int main(int argc, char **argv)
{
    struct mtu9k_pair pair;
    uint8_t pkt[NE_PKT_MAX];
    unsigned stats_ticks = 0;

    (void)argc;
    (void)argv;

    signal(SIGINT, on_stop);
    signal(SIGTERM, on_stop);
    setbuf(stderr, NULL);

    fprintf(stderr,
            "[mtu9k] MODE_L2_PQC=%d frame=%u pkt_max=%u n_frames=%u LAN=%s WAN=%s\n"
            "[mtu9k] note: AF_XDP chunk <= PAGE_SIZE; jumbo via multi-buffer (XDP_USE_SG)\n",
            MODE_L2_PQC, NE_FRAME, NE_PKT_MAX, NE_N_FRAMES, IF_LAN, IF_WAN);

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
            g_rx_lan++;
            process_lan_to_wan(&pair, pkt, len);
        } else if (r < 0) {
            g_drop++;
        }

        r = mtu9k_rx_pkt(&pair, &pair.wan, pkt, sizeof(pkt), &len);
        if (r > 0) {
            idle = 0;
            g_rx_wan++;
            process_wan_to_lan(&pair, pkt, len);
        } else if (r < 0) {
            g_drop++;
        }

        if (idle)
            usleep(50);

        if (++stats_ticks >= 100000) {
            stats_ticks = 0;
            fprintf(stderr,
                    "[stats] rx_lan=%u rx_wan=%u tx_lan=%u tx_wan=%u drop=%u "
                    "len_min=%u len_max=%u\n",
                    g_rx_lan, g_rx_wan, g_tx_lan, g_tx_wan, g_drop,
                    g_min_len == UINT32_MAX ? 0 : g_min_len, g_max_len);
        }
    }

    fprintf(stderr,
            "[mtu9k] stop — rx_lan=%u rx_wan=%u tx_lan=%u tx_wan=%u drop=%u "
            "len_min=%u len_max=%u\n",
            g_rx_lan, g_rx_wan, g_tx_lan, g_tx_wan, g_drop,
            g_min_len == UINT32_MAX ? 0 : g_min_len, g_max_len);

    mtu9k_pair_close(&pair);
    l2_crypto_cleanup();
    return 0;
}
