#include "l4pqc_rss.h"

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void on_sig(int sig)
{
    (void)sig;
    l4pqc_stop();
}

static void print_mac(const char *label, const uint8_t mac[6])
{
    fprintf(stderr, "  %s %02x:%02x:%02x:%02x:%02x:%02x\n",
            label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main(int argc, char **argv)
{
    struct l4pqc_config cfg;

    if (geteuid() != 0) {
        fprintf(stderr, "[L4PQC] need root\n");
        return 1;
    }
    if (l4pqc_config_from_args(argc, argv, &cfg) != 0)
        return 1;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    fprintf(stderr,
            "[L4PQC] RSS L4-PQC test (DRV + XDP_COPY)\n"
            "  LAN=%s  WAN=%s  queues=auto\n",
            cfg.lan_if, cfg.wan_if);
    if (cfg.has_lan_mac)
        print_mac("LAN MAC:", cfg.lan_mac);

    l4pqc_run(&cfg);
    return 0;
}
