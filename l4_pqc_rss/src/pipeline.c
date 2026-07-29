#include "l4pqc_rss.h"
#include "l4pqc_xsk_pair.h"
#include "l4pqc_crypto.h"
#include "l4pqc_test_cfg.h"

#include "../../../inc/crypto/crypto_option.h"
#include "../../../inc/crypto/eth_parse.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern const struct crypto_option_ops *crypto_opt_l4_pqc_tcp_ops(void);
extern const struct crypto_option_ops *crypto_opt_l4_pqc_udp_ops(void);

struct pipeline_args {
    struct l4pqc_xsk_pair *xp;
    struct l4pqc_queue_ctx *qc;
    struct packet_crypto_ctx crypto;
    uint64_t tail_addr;
    volatile int *running;
};

static struct l4pqc_xsk_pair g_xp;
static struct pipeline_args g_pargs[L4PQC_MAX_QUEUES];
static pthread_t g_threads[L4PQC_MAX_QUEUES];
static volatile int g_running;
static int g_thread_count;

static void pin_cpu_optional(uint8_t cpu)
{
    cpu_set_t cpuset;

    if (cpu == L4PQC_CPU_NO_PIN)
        return;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static int is_ipv4_tcp_udp(uint8_t *pkt, uint32_t len, uint8_t *proto_out)
{
    int l3 = crypto_eth_ipv4_offset(pkt, len);
    if (l3 < 0 || len < (uint32_t)(l3 + 20))
        return 0;
    if (proto_out)
        *proto_out = pkt[l3 + 9];
    return 1;
}

static void clamp_tcp_mss(uint8_t *pkt, uint32_t len)
{
    (void)crypto_tcp_clamp_mss(pkt, len, crypto_option_get_mtu(), L4PQC_WIRE_OVERHEAD);
}

static int process_lan_to_wan(struct pipeline_args *pa, struct l4pqc_batch_pkt *bp)
{
    uint8_t *pkt = l4pqc_pkt_data(pa->xp, bp->addr);
    const struct crypto_option_ops *tcp_ops = crypto_opt_l4_pqc_tcp_ops();
    const struct crypto_option_ops *udp_ops = crypto_opt_l4_pqc_udp_ops();
    uint8_t *tail_pkt;
    uint8_t proto = 0;
    uint32_t len = bp->len;
    uint32_t l1 = 0, l2 = 0;

    if (!pkt || len < 14)
        return -1;
    if (crypto_pkt_is_arp(pkt, len) || !is_ipv4_tcp_udp(pkt, len, &proto))
        return l4pqc_send(&pa->qc->wan, pa->xp, bp->addr, len);

    if (proto == IPPROTO_TCP) {
        clamp_tcp_mss(pkt, len);
        if (!tcp_ops || !tcp_ops->encrypt || tcp_ops->encrypt(&pa->crypto, pkt, &len) != 0)
            return -1;
        return l4pqc_send(&pa->qc->wan, pa->xp, bp->addr, len);
    }

    if (proto == IPPROTO_UDP && udp_ops) {
        if (udp_ops->need_split && udp_ops->need_split(len)) {
            tail_pkt = l4pqc_pkt_data(pa->xp, pa->tail_addr);
            if (!tail_pkt || !udp_ops->split)
                return -1;
            if (udp_ops->split(&pa->crypto, pkt, len, L4PQC_FRAME, &l1,
                               tail_pkt, L4PQC_FRAME, &l2) != 0)
                return -1;
            if (l4pqc_send(&pa->qc->wan, pa->xp, bp->addr, l1) != 0)
                return -1;
            return l4pqc_send(&pa->qc->wan, pa->xp, pa->tail_addr, l2);
        }
        if (!udp_ops->encrypt || udp_ops->encrypt(&pa->crypto, pkt, &len) != 0)
            return -1;
        return l4pqc_send(&pa->qc->wan, pa->xp, bp->addr, len);
    }

    return l4pqc_send(&pa->qc->wan, pa->xp, bp->addr, len);
}

static int process_wan_to_lan(struct pipeline_args *pa, struct l4pqc_batch_pkt *bp)
{
    uint8_t *pkt = l4pqc_pkt_data(pa->xp, bp->addr);
    const struct crypto_option_ops *tcp_ops = crypto_opt_l4_pqc_tcp_ops();
    const struct crypto_option_ops *udp_ops = crypto_opt_l4_pqc_udp_ops();
    const struct app_config *stub_cfg = l4pqc_stub_cfg();
    uint8_t out[L4PQC_FRAME];
    uint8_t proto = 0;
    uint16_t pkt_id = 0;
    uint8_t frag_idx = 0;
    uint32_t len = bp->len;
    uint32_t out_len = 0;
    int rr;

    if (!pkt || len < 14)
        return -1;
    if (crypto_pkt_is_arp(pkt, len) || !is_ipv4_tcp_udp(pkt, len, &proto))
        return l4pqc_send(&pa->qc->lan, pa->xp, bp->addr, len);

    if (proto == IPPROTO_UDP && udp_ops && udp_ops->is_fragment &&
        udp_ops->is_fragment(stub_cfg, pkt, len, &pkt_id, &frag_idx)) {
        if (!udp_ops->reasm)
            return -1;
        rr = udp_ops->reasm(0, pa->qc->queue_id, &pa->crypto, pkt, &len, out, &out_len);
        if (rr == 0)
            return 0;
        if (rr != 1 || out_len == 0 || out_len > L4PQC_FRAME)
            return -1;
        memcpy(pkt, out, out_len);
        len = out_len;
        return l4pqc_send(&pa->qc->lan, pa->xp, bp->addr, len);
    }

    if (proto == IPPROTO_TCP) {
        if (!tcp_ops || !tcp_ops->decrypt || tcp_ops->decrypt(&pa->crypto, pkt, &len) != 0)
            return -1;
        clamp_tcp_mss(pkt, len);
        return l4pqc_send(&pa->qc->lan, pa->xp, bp->addr, len);
    }

    if (proto == IPPROTO_UDP) {
        if (!udp_ops || !udp_ops->decrypt || udp_ops->decrypt(&pa->crypto, pkt, &len) != 0)
            return -1;
        return l4pqc_send(&pa->qc->lan, pa->xp, bp->addr, len);
    }

    return l4pqc_send(&pa->qc->lan, pa->xp, bp->addr, len);
}

static void *pipeline_thread(void *arg)
{
    struct pipeline_args *pa = arg;
    struct l4pqc_batch_pkt batch[L4PQC_BATCH];
    const struct crypto_option_ops *udp_ops = crypto_opt_l4_pqc_udp_ops();
    uint64_t gc_tick = 0;

    pin_cpu_optional(pa->qc->cpu_id);
    crypto_option_bind_worker_idx((uint8_t)pa->qc->queue_id);
    fprintf(stderr, "[L4PQC] q=%d pipeline started\n", pa->qc->queue_id);

    while (*(pa->running)) {
        struct timespec ts;

        l4pqc_refill_fq(&pa->qc->lan, pa->xp);
        l4pqc_refill_fq(&pa->qc->wan, pa->xp);
        l4pqc_drain_cq(&pa->qc->lan, pa->xp);
        l4pqc_drain_cq(&pa->qc->wan, pa->xp);

        if (udp_ops && udp_ops->frag_gc && clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            uint64_t now = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
            if (now - gc_tick > 100000000ull) {
                udp_ops->frag_gc(0, pa->qc->queue_id, now);
                gc_tick = now;
            }
        }

        int n = l4pqc_recv(&pa->qc->lan, pa->xp, 0, 0, batch, L4PQC_BATCH);
        for (int i = 0; i < n; i++) {
            if (process_lan_to_wan(pa, &batch[i]) != 0)
                l4pqc_drain_cq(&pa->qc->lan, pa->xp);
        }

        n = l4pqc_recv(&pa->qc->wan, pa->xp, 1, 0, batch, L4PQC_BATCH);
        for (int i = 0; i < n; i++) {
            if (process_wan_to_lan(pa, &batch[i]) != 0)
                l4pqc_drain_cq(&pa->qc->wan, pa->xp);
        }

        if (n == 0)
            sched_yield();
    }

    return NULL;
}

void l4pqc_stop(void)
{
    g_running = 0;
}

void l4pqc_run(const struct l4pqc_config *cfg)
{
    if (!cfg)
        return;

    l4pqc_crypto_set_static_key(cfg->key, cfg->key_len);
    l4pqc_stub_set_key(cfg->key, cfg->key_len);
    l4pqc_stub_cfg_init(cfg->policy_wire_id);

    if (l4pqc_xsk_open(&g_xp, cfg) != 0) {
        fprintf(stderr, "[L4PQC] xsk open failed\n");
        return;
    }

    g_running = 1;
    g_thread_count = 0;

    for (int q = 0; q < g_xp.queue_count; q++) {
        g_pargs[q].xp = &g_xp;
        g_pargs[q].qc = &g_xp.queues[q];
        g_pargs[q].running = &g_running;
        g_pargs[q].tail_addr = (uint64_t)(L4PQC_N_FRAMES - 1 - q) * L4PQC_FRAME;
        if (l4pqc_crypto_init_ctx(&g_pargs[q].crypto, cfg) != 0) {
            fprintf(stderr, "[L4PQC] crypto init q=%d failed\n", q);
            g_running = 0;
            break;
        }
        if (pthread_create(&g_threads[q], NULL, pipeline_thread, &g_pargs[q]) != 0) {
            fprintf(stderr, "[L4PQC] pthread_create q=%d failed\n", q);
            g_running = 0;
            break;
        }
        g_thread_count++;
    }

    while (g_running)
        pause();

    for (int q = 0; q < g_thread_count; q++)
        pthread_join(g_threads[q], NULL);

    l4pqc_xsk_close(&g_xp);
}
