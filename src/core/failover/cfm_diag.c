#include "cfm.h"
#include "../../../inc/core/cfm_diag.h"
#include "../../../inc/core/config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CFM_INTERVAL_MS       100
#define CFM_TIMEOUT_MS        350
#define CFM_STARTUP_TIMEOUT_MS 1000

typedef struct cfm_link {
    pthread_mutex_t lock;
    uint64_t last_recv_time;
    int ifindex;
    int sock_fd;
    int wan_dp;
    int cfg_wan_idx;
    int local_mep_id;
    int remote_mep_id;
    uint32_t tx_seq;
    char ifname[IFNAMSIZ];
    uint8_t local_mac[6];
    uint8_t remote_mac[6];
    cfm_link_state_t state;
    bool mac_learned;
} cfm_link_t;

static cfm_link_t g_links[MAX_INTERFACES];
static int g_link_count;
static pthread_t g_cfm_thread;
static volatile bool g_cfm_running;
static pthread_mutex_t g_cfm_init_lock = PTHREAD_MUTEX_INITIALIZER;

static cfm_link_state_cb g_state_cb;
static void *g_state_cb_user;
static pthread_mutex_t g_cb_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static const char *state_str(cfm_link_state_t st)
{
    if (st == CFM_LINK_STATE_UP)
        return "UP";
    if (st == CFM_LINK_STATE_DOWN)
        return "DOWN";
    return "INIT";
}

static void notify_state_change(cfm_link_t *link, cfm_link_state_t old_state)
{
    cfm_link_state_cb cb;
    void *user;

    if (link->state == old_state)
        return;

    fprintf(stderr, "[CFM] Link status on %s (dp=%d) changed: %s -> %s\n",
            link->ifname, link->wan_dp, state_str(old_state), state_str(link->state));
    fflush(stderr);

    pthread_mutex_lock(&g_cb_lock);
    cb = g_state_cb;
    user = g_state_cb_user;
    pthread_mutex_unlock(&g_cb_lock);
    if (cb)
        cb(link->wan_dp, link->ifname, (int)old_state, (int)link->state, user);
}

static void send_ccm_packet(cfm_link_t *link)
{
    cfm_ccm_packet_t pkt;
    struct sockaddr_ll sll;

    memset(&pkt, 0, sizeof(pkt));
    pthread_mutex_lock(&link->lock);
    if (link->mac_learned)
        memcpy(pkt.eth.dst_mac, link->remote_mac, 6);
    else
        memcpy(pkt.eth.dst_mac, CFM_MULTICAST_MAC, 6);
    memcpy(pkt.eth.src_mac, link->local_mac, 6);
    pkt.eth.eth_type = htons(ETH_P_CFM);

    pkt.ccm.md_lvl_version = 0xA0;
    pkt.ccm.opcode = CFM_OPCODE_CCM;
    pkt.ccm.flags = 4;
    pkt.ccm.first_tlv_offset = 70;
    pkt.ccm.seq_number = htonl(link->tx_seq++);
    pkt.ccm.mep_id = htons((uint16_t)link->local_mep_id);
    snprintf((char *)pkt.ccm.maid, sizeof(pkt.ccm.maid), "MA-WAN-PORT-%.16s", link->ifname);
    pkt.end_tlv = 0;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = link->ifindex;
    sll.sll_halen = 6;
    if (link->mac_learned)
        memcpy(sll.sll_addr, link->remote_mac, 6);
    else
        memcpy(sll.sll_addr, CFM_MULTICAST_MAC, 6);
    pthread_mutex_unlock(&link->lock);

    (void)sendto(link->sock_fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sll, sizeof(sll));
}

static void *cfm_monitor_thread(void *arg)
{
    struct pollfd fds[MAX_INTERFACES];
    uint64_t last_tx_time = get_time_ms();

    (void)arg;
    while (g_cfm_running) {
        int active_fds = 0;
        int fd_to_link[MAX_INTERFACES];

        for (int i = 0; i < g_link_count; i++) {
            if (g_links[i].sock_fd < 0)
                continue;
            fds[active_fds].fd = g_links[i].sock_fd;
            fds[active_fds].events = POLLIN;
            fds[active_fds].revents = 0;
            fd_to_link[active_fds] = i;
            active_fds++;
        }

        if (active_fds == 0) {
            usleep(100000);
            continue;
        }

        int ret = poll(fds, (nfds_t)active_fds, 10);
        if (ret > 0) {
            uint64_t now = get_time_ms();
            for (int i = 0; i < active_fds; i++) {
                cfm_ccm_packet_t rx_pkt;
                ssize_t rx_bytes;
                int j;

                if (!(fds[i].revents & POLLIN))
                    continue;
                rx_bytes = recv(fds[i].fd, &rx_pkt, sizeof(rx_pkt), 0);
                if (rx_bytes < (ssize_t)(sizeof(eth_hdr_t) + sizeof(cfm_ccm_hdr_t)))
                    continue;
                if (ntohs(rx_pkt.eth.eth_type) != ETH_P_CFM)
                    continue;

                {
                    uint8_t lvl = (rx_pkt.ccm.md_lvl_version >> 5) & 0x07;
                    uint8_t op = rx_pkt.ccm.opcode;
                    uint16_t rx_mep_id;

                    if (lvl != 5 || op != CFM_OPCODE_CCM)
                        continue;
                    rx_mep_id = ntohs(rx_pkt.ccm.mep_id);
                    j = fd_to_link[i];

                    pthread_mutex_lock(&g_links[j].lock);
                    if (!g_links[j].mac_learned) {
                        cfm_link_state_t old = g_links[j].state;
                        memcpy(g_links[j].remote_mac, rx_pkt.eth.src_mac, 6);
                        g_links[j].remote_mep_id = rx_mep_id;
                        g_links[j].mac_learned = true;
                        g_links[j].state = CFM_LINK_STATE_UP;
                        g_links[j].last_recv_time = now;
                        fprintf(stderr,
                                "[CFM] Learned remote MAC %02x:%02x:%02x:%02x:%02x:%02x "
                                "MEP %d on %s\n",
                                g_links[j].remote_mac[0], g_links[j].remote_mac[1],
                                g_links[j].remote_mac[2], g_links[j].remote_mac[3],
                                g_links[j].remote_mac[4], g_links[j].remote_mac[5],
                                g_links[j].remote_mep_id, g_links[j].ifname);
                        fflush(stderr);
                        pthread_mutex_unlock(&g_links[j].lock);
                        notify_state_change(&g_links[j], old);
                    } else if (rx_mep_id == g_links[j].remote_mep_id &&
                               memcmp(rx_pkt.eth.src_mac, g_links[j].remote_mac, 6) == 0) {
                        cfm_link_state_t old = g_links[j].state;
                        g_links[j].last_recv_time = now;
                        g_links[j].state = CFM_LINK_STATE_UP;
                        pthread_mutex_unlock(&g_links[j].lock);
                        notify_state_change(&g_links[j], old);
                    } else {
                        pthread_mutex_unlock(&g_links[j].lock);
                    }
                }
            }
        }

        {
            uint64_t now = get_time_ms();
            if (now - last_tx_time < CFM_INTERVAL_MS)
                continue;
            for (int i = 0; i < g_link_count; i++) {
                cfm_link_state_t old;

                if (g_links[i].sock_fd < 0)
                    continue;
                send_ccm_packet(&g_links[i]);

                pthread_mutex_lock(&g_links[i].lock);
                old = g_links[i].state;
                if (g_links[i].mac_learned) {
                    if (now - g_links[i].last_recv_time > CFM_TIMEOUT_MS)
                        g_links[i].state = CFM_LINK_STATE_DOWN;
                    else
                        g_links[i].state = CFM_LINK_STATE_UP;
                } else if (now - g_links[i].last_recv_time > CFM_STARTUP_TIMEOUT_MS) {
                    g_links[i].state = CFM_LINK_STATE_DOWN;
                } else {
                    g_links[i].state = CFM_LINK_STATE_INIT;
                }
                pthread_mutex_unlock(&g_links[i].lock);
                notify_state_change(&g_links[i], old);
            }
            last_tx_time = now;
        }
    }
    return NULL;
}

static void cfm_stop_locked(void)
{
    if (g_cfm_running) {
        g_cfm_running = false;
        pthread_mutex_unlock(&g_cfm_init_lock);
        pthread_join(g_cfm_thread, NULL);
        pthread_mutex_lock(&g_cfm_init_lock);
    }
    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].sock_fd >= 0)
            close(g_links[i].sock_fd);
        pthread_mutex_destroy(&g_links[i].lock);
    }
    g_link_count = 0;
    memset(g_links, 0, sizeof(g_links));
}

void cfm_set_state_callback(cfm_link_state_cb cb, void *user)
{
    pthread_mutex_lock(&g_cb_lock);
    g_state_cb = cb;
    g_state_cb_user = user;
    pthread_mutex_unlock(&g_cb_lock);
}

int cfm_init(const struct app_config *cfg)
{
    int initialized_links = 0;

    if (!cfg)
        return -1;

    pthread_mutex_lock(&g_cfm_init_lock);
    cfm_stop_locked();

    for (int i = 0; i < cfg->wan_count && g_link_count < MAX_INTERFACES; i++) {
        const struct wan_config *wan = &cfg->wans[i];
        int ifindex;
        int sock;
        int dp;
        struct sockaddr_ll sll;
        struct packet_mreq mreq;
        struct ifreq ifr;
        cfm_link_t *link;
        int flags;

        if (wan->ifname[0] == '\0')
            continue;
        if (!wan->dataplane || wan->dst_ip != 0)
            continue;

        dp = config_wan_cfg_to_dp(cfg, i);
        if (dp < 0)
            continue;

        ifindex = (int)if_nametoindex(wan->ifname);
        if (ifindex == 0) {
            fprintf(stderr, "[CFM-INIT] Warning: interface %s not found\n", wan->ifname);
            continue;
        }

        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_CFM));
        if (sock < 0) {
            fprintf(stderr, "[CFM-INIT] Error: raw socket for %s: %s\n",
                    wan->ifname, strerror(errno));
            continue;
        }

        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_CFM);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "[CFM-INIT] Error: bind %s: %s\n", wan->ifname, strerror(errno));
            close(sock);
            continue;
        }

        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = ifindex;
        mreq.mr_type = PACKET_MR_MULTICAST;
        mreq.mr_alen = 6;
        memcpy(mreq.mr_address, CFM_MULTICAST_MAC, 6);
        if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            fprintf(stderr, "[CFM-INIT] Warning: multicast join on %s: %s\n",
                    wan->ifname, strerror(errno));
        }

        flags = fcntl(sock, F_GETFL, 0);
        if (flags >= 0)
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        link = &g_links[g_link_count];
        memset(link, 0, sizeof(*link));
        strncpy(link->ifname, wan->ifname, IFNAMSIZ - 1);
        link->ifindex = ifindex;
        link->sock_fd = sock;
        link->cfg_wan_idx = i;
        link->wan_dp = dp;
        link->state = CFM_LINK_STATE_INIT;
        link->mac_learned = false;
        link->last_recv_time = get_time_ms();

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, wan->ifname, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
            memcpy(link->local_mac, ifr.ifr_hwaddr.sa_data, 6);

        link->local_mep_id = ((link->local_mac[4] << 8) | link->local_mac[5]) & 0x1FFF;
        if (link->local_mep_id == 0)
            link->local_mep_id = 1;

        pthread_mutex_init(&link->lock, NULL);
        g_link_count++;
        initialized_links++;
    }

    if (initialized_links > 0) {
        g_cfm_running = true;
        if (pthread_create(&g_cfm_thread, NULL, cfm_monitor_thread, NULL) != 0) {
            fprintf(stderr, "[CFM-INIT] Error: failed to create monitor thread\n");
            g_cfm_running = false;
            for (int i = 0; i < g_link_count; i++) {
                if (g_links[i].sock_fd >= 0)
                    close(g_links[i].sock_fd);
                pthread_mutex_destroy(&g_links[i].lock);
            }
            g_link_count = 0;
            pthread_mutex_unlock(&g_cfm_init_lock);
            return -1;
        }
        fprintf(stderr, "[CFM-INIT] CFM initialized on %d dataplane WAN(s)\n",
                initialized_links);
    } else {
        fprintf(stderr, "[CFM-INIT] No dataplane WAN interfaces for CFM\n");
    }
    fflush(stderr);
    pthread_mutex_unlock(&g_cfm_init_lock);
    return 0;
}

bool cfm_is_link_up(int wan_dp)
{
    return cfm_get_link_state(wan_dp) == CFM_LINK_STATE_UP;
}

int cfm_get_link_state(int wan_dp)
{
    for (int i = 0; i < g_link_count; i++) {
        if (g_links[i].wan_dp != wan_dp)
            continue;
        pthread_mutex_lock(&g_links[i].lock);
        cfm_link_state_t st = g_links[i].state;
        pthread_mutex_unlock(&g_links[i].lock);
        return (int)st;
    }
    return CFM_LINK_STATE_DOWN;
}

void cfm_cleanup(void)
{
    pthread_mutex_lock(&g_cfm_init_lock);
    cfm_stop_locked();
    fprintf(stderr, "[CFM-CLEANUP] CFM diagnostic stopped\n");
    fflush(stderr);
    pthread_mutex_unlock(&g_cfm_init_lock);
}
