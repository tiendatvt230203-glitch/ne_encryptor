#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/crypto/crypto_option.h"
#include "../../inc/core/dataplane.h"
#include "../../inc/core/crypto_route.h"

#include "../../inc/core/main_diag.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/profile_iface_xdp.h"
#include "../../inc/core/mac_learn.h"
#include "../../inc/core/dataplane_stats.h"
#include "../../inc/crypto/pqc_l2_handshake.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
static atomic_int running = 1;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;
static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

void forwarder_pin_cpu(void)
{
    pin_cpu(ne_cpu_rx_lan(0));
}

#define DP_BURST_ROUNDS   8
#define DP_TX_BURST_MAX   8

static void dp_burst_refill_local(struct forwarder *fwd, int rx_slot)
{
    for (int i = 0; i < DP_BURST_ROUNDS; i++)
        ne_refill_fq_local_slot(&fwd->pair, rx_slot);
}

static void dp_burst_refill_wan(struct forwarder *fwd, int rx_slot)
{
    for (int i = 0; i < DP_BURST_ROUNDS; i++)
        ne_refill_fq_wan_slot(&fwd->pair, rx_slot);
}

static void dp_burst_drain_cq_local(struct forwarder *fwd, int tx_slot)
{
    for (int i = 0; i < DP_BURST_ROUNDS; i++)
        ne_drain_cq_local(&fwd->pair, tx_slot);
}

static void dp_burst_drain_cq_wan(struct forwarder *fwd, int tx_slot)
{
    for (int i = 0; i < DP_BURST_ROUNDS; i++)
        ne_drain_cq_wan(&fwd->pair, tx_slot);
}

static void dp_burst_tx_local(struct forwarder *fwd, int local_idx, int tx_slot)
{
    struct ne_ring *rings[NE_CRYPTO_WORKERS];

    if (!ne_pair_local_live(&fwd->pair, local_idx))
        return;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        rings[w] = &fwd->mid_to_local[local_idx][w];

    for (int burst = 0; burst < DP_TX_BURST_MAX; burst++) {
        int sent = ne_tx_drain_local_all(&fwd->pair, rings, NE_CRYPTO_WORKERS,
                                         local_idx, tx_slot);
        if (sent <= 0)
            break;
    }
}

static void dp_burst_tx_wan(struct forwarder *fwd, int wan_idx, int tx_slot)
{
    struct ne_ring *rings[NE_CRYPTO_WORKERS];

    if (!ne_pair_wan_live(&fwd->pair, wan_idx))
        return;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        rings[w] = &fwd->mid_to_wan[wan_idx][w];

    for (int burst = 0; burst < DP_TX_BURST_MAX; burst++) {
        int sent = ne_tx_drain_wan_all(&fwd->pair, rings, NE_CRYPTO_WORKERS,
                                       wan_idx, tx_slot);
        if (sent <= 0)
            break;
    }
}

struct dp_tx_slot_ctx {
    struct forwarder *fwd;
    int tx_slot;
    uint8_t cpu_id;
};

struct dp_rx_slot_ctx {
    struct forwarder *fwd;
    int rx_slot;
    uint8_t cpu_id;
};

static void init_iface_meta(struct fwd_iface *iface, const char *ifname)
{
    memset(iface, 0, sizeof(*iface));
    iface->ifindex = (int)if_nametoindex(ifname);
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
}

static uint32_t resolve_runtime_frag_mtu(const struct app_config *cfg)
{
    int sockfd;
    uint32_t min_mtu = CRYPTO_OPT_FRAG_MTU_DEFAULT;

    if (!cfg)
        return min_mtu;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return min_mtu;

    for (int wi = 0; wi < cfg->wan_count; wi++) {
        struct ifreq ifr;
        if (!cfg->wans[wi].dataplane)
            continue;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, cfg->wans[wi].ifname, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(sockfd, SIOCGIFMTU, &ifr) != 0)
            continue;
        if (ifr.ifr_mtu > 0 && (uint32_t)ifr.ifr_mtu < min_mtu)
            min_mtu = (uint32_t)ifr.ifr_mtu;
    }

    close(sockfd);
    return min_mtu;
}

static void *local_rx_thread(void *arg)
{
    struct dp_rx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        dp_burst_refill_local(fwd, ctx->rx_slot);

        int rcvd = ne_recv_local_slot(&fwd->pair, ctx->rx_slot, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            ne_dp_warn_rx("LAN", (int)ctx->cpu_id, 0);
            sched_yield();
            continue;
        }

        {
            uint64_t rx_bytes = 0;
            for (int i = 0; i < rcvd; i++)
                rx_bytes += batch[i].len;
            ne_dp_stats_rx_lan(ctx->rx_slot, (uint32_t)rcvd, rx_bytes);
        }

        for (int i = 0; i < rcvd; i++) {
            int wi = dp_crypto_pick_local_worker(ne_packet_data(&fwd->pair, batch[i].addr),
                                                 batch[i].len);
            if (ne_ring_try_push(&fwd->local_to_mid[wi], &batch[i]) != 0) {
                ne_dp_warn_rx_drop("LAN", (int)ctx->cpu_id, wi,
                                   ne_ring_count(&fwd->local_to_mid[wi]));
                ne_dp_stats_rx_ring_drop_lan(ctx->rx_slot, 1);
                ne_frame_free(&fwd->pair, batch[i].addr);
            }
        }
        ne_recv_release_local_slot(&fwd->pair, ctx->rx_slot);
    }
    return NULL;
}

static void *local_tx_thread(void *arg)
{
    struct dp_tx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int tx_slot = ctx->tx_slot;

    pin_cpu(ctx->cpu_id);
    ne_dp_tx_ctx("LAN", tx_slot);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        dp_burst_drain_cq_local(fwd, tx_slot);
        for (int li = 0; li < fwd->local_count; li++)
            dp_burst_tx_local(fwd, li, tx_slot);
        sched_yield();
    }
    return NULL;
}

static void *wan_rx_thread(void *arg)
{
    struct dp_rx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        dp_burst_refill_wan(fwd, ctx->rx_slot);

        int rcvd = ne_recv_wan_slot(&fwd->pair, ctx->rx_slot, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            ne_dp_warn_rx("WAN", (int)ctx->cpu_id, 0);
            sched_yield();
            continue;
        }

        {
            uint64_t rx_bytes = 0;
            for (int i = 0; i < rcvd; i++)
                rx_bytes += batch[i].len;
            ne_dp_stats_rx_wan(ctx->rx_slot, (uint32_t)rcvd, rx_bytes);
        }

        for (int i = 0; i < rcvd; i++) {
            int wi;
            const uint8_t *pkt;

            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            pkt = ne_packet_data(&fwd->pair, batch[i].addr);
            wi = dp_crypto_pick_wan_worker(fwd, pkt, batch[i].len);
            if (wi < 0 || wi >= (int)NE_CRYPTO_WORKERS) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            if (ne_ring_try_push(&fwd->wan_to_mid[wi], &batch[i]) != 0) {
                ne_dp_warn_rx_drop("WAN", (int)ctx->cpu_id, wi,
                                   ne_ring_count(&fwd->wan_to_mid[wi]));
                ne_dp_stats_rx_ring_drop_wan(ctx->rx_slot, 1);
                ne_frame_free(&fwd->pair, batch[i].addr);
            }
        }
        ne_recv_release_wan_slot(&fwd->pair, ctx->rx_slot);
    }
    return NULL;
}

static void *wan_tx_thread(void *arg)
{
    struct dp_tx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int tx_slot = ctx->tx_slot;

    pin_cpu(ctx->cpu_id);
    ne_dp_tx_ctx("WAN", tx_slot);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        dp_burst_drain_cq_wan(fwd, tx_slot);
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            if (fwd_wan_is_stopped(wi))
                continue;
            dp_burst_tx_wan(fwd, wi, tx_slot);
        }
        sched_yield();
    }
    return NULL;
}

struct crypto_worker_ctx {
    struct forwarder *fwd;
    int worker_idx;
    uint8_t cpu_id;
};

static void crypto_worker_tick(struct forwarder *fwd, int is_primary)
{
    if (!is_primary)
        return;
    fwd_crypto_maybe_expire_prev_grace();
    fwd_wan_drain_tick(fwd);
    fwd_wan_weight_blend_tick();
    fwd_crypto_cleanup_stale_profile_slots(fwd->cfg);
    mac_learn_tick(fwd);
    ne_dp_stats_tick(fwd);
}

static void *crypto_worker_thread(void *arg)
{
    struct crypto_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    uint32_t maint_tick = 0;
    int is_primary = (ctx->worker_idx == 0);

    pin_cpu(ctx->cpu_id);
    dp_crypto_worker_bind(ctx->worker_idx);
    crypto_option_bind_worker_idx((uint8_t)ctx->worker_idx);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        if (is_primary) {
            if (pthread_mutex_trylock(&runtime_lock) != 0) {
                if (!atomic_load_explicit(&running, memory_order_acquire))
                    break;
                if (ne_ring_try_pop(&fwd->wan_to_mid[ctx->worker_idx], &job) == 0) {
                    dataplane_process_wan(fwd, job);
                    did_work = 1;
                }
                if (ne_ring_try_pop(&fwd->local_to_mid[ctx->worker_idx], &job) == 0) {
                    dataplane_process_local(fwd, job);
                    did_work = 1;
                }
                if (!did_work)
                    sched_yield();
                continue;
            }
            if (!atomic_load_explicit(&running, memory_order_acquire)) {
                pthread_mutex_unlock(&runtime_lock);
                break;
            }
            if (fwd_reload_apply_if_pending()) {
                pthread_mutex_unlock(&runtime_lock);
                continue;
            }
            if ((++maint_tick & 1023u) == 0)
                crypto_worker_tick(fwd, 1);
        }

        if (ne_ring_try_pop(&fwd->wan_to_mid[ctx->worker_idx], &job) == 0) {
            dataplane_process_wan(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid[ctx->worker_idx], &job) == 0) {
            dataplane_process_local(fwd, job);
            did_work = 1;
        }
        if (++gc_tick >= 2048) {
            fwd_crypto_frag_gc_worker_tick(ctx->worker_idx);
            gc_tick = 0;
        }
        if ((gc_tick & 511u) == 0) {
            ne_dp_warn_crypto((int)ctx->cpu_id, ctx->worker_idx,
                              ne_ring_count(&fwd->local_to_mid[ctx->worker_idx]),
                              ne_ring_count(&fwd->wan_to_mid[ctx->worker_idx]));
        }
        if (is_primary)
            pthread_mutex_unlock(&runtime_lock);

        if (!did_work)
            sched_yield();
    }
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || cfg->local_count <= 0)
        return -1;
    if (forwarder_should_stop())
        return -1;
    if (config_count_dataplane_wans(cfg) <= 0) {
        fprintf(stderr,
                "[FWD] no dataplane WAN — LAN-only until a dataplane WAN is added\n");
        fflush(stderr);
    }

    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = config_count_dataplane_wans(cfg);
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;

    crypto_option_set_mtu(resolve_runtime_frag_mtu(cfg));
    fprintf(stderr, "[FRAG] runtime MTU set to %u\n", crypto_option_get_mtu());
    ne_dp_stats_init();

    for (int i = 0; i < fwd->local_count; i++)
        init_iface_meta(&fwd->locals[i], cfg->locals[i].ifname);
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            return -1;
        fwd->wan_cfg_idx[di] = ci;
        init_iface_meta(&fwd->wans[di], cfg->wans[ci].ifname);
    }

    profile_iface_xdp_prepare_init(cfg);

    if (forwarder_should_stop())
        return -1;

    if (fwd_crypto_rebuild(cfg) != 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    fwd_crypto_reset_on_init();
    if (fwd_crypto_ensure_profile_slots(cfg) != 0)
        return -1;

    pqc_handshake_start_all_profiles(cfg);

    if (ne_pair_open(&fwd->pair, cfg) != 0)
        return -1;
    if (profile_iface_xdp_attach_init(&fwd->pair, cfg) != 0) {
        forwarder_cleanup(fwd);
        return -1;
    }
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (ne_ring_init(&fwd->local_to_mid[w], NE_RING, 0) != 0 ||
            ne_ring_init(&fwd->wan_to_mid[w], NE_RING, 0) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->local_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->mid_to_local[i][w], NE_RING, 1) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->mid_to_wan[i][w], NE_RING, 1) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
        }
    }

    fwd_wan_reset_on_init(fwd);
    // MAC_LEARN
    mac_learn_bootstrap(&fwd->mac_table);
    // MAC_LEARN
    atomic_store_explicit(&running, 1, memory_order_release);
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    if (!fwd)
        return;
    // MAC_LEARN
    mac_learn_shutdown(&fwd->mac_table);
    // MAC_LEARN
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        ne_ring_destroy(&fwd->local_to_mid[w]);
        ne_ring_destroy(&fwd->wan_to_mid[w]);
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            ne_ring_destroy(&fwd->mid_to_wan[i][w]);
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            ne_ring_destroy(&fwd->mid_to_local[i][w]);
    }
    fwd_crypto_cleanup_all_profile_slots();
    ne_pair_close(&fwd->pair);
}

static void forwarder_join_started(struct forwarder *fwd, int local_rx_started, int local_tx_started,
                                   int crypto_started, int wan_tx_started, int wan_rx_started)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    for (int w = 0; w < local_rx_started; w++)
        pthread_join(fwd->local_rx_threads[w], NULL);
    for (int w = 0; w < local_tx_started; w++)
        pthread_join(fwd->local_tx_threads[w], NULL);
    for (int w = 0; w < crypto_started; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    for (int w = 0; w < wan_tx_started; w++)
        pthread_join(fwd->wan_tx_threads[w], NULL);
    for (int w = 0; w < wan_rx_started; w++)
        pthread_join(fwd->wan_rx_threads[w], NULL);
}

void forwarder_run(struct forwarder *fwd)
{
    struct crypto_worker_ctx crypto_ctx[NE_CRYPTO_WORKERS];
    struct dp_tx_slot_ctx local_tx_ctx[NE_TX_SLOTS];
    struct dp_tx_slot_ctx wan_tx_ctx[NE_TX_SLOTS];
    struct dp_rx_slot_ctx local_rx_ctx[NE_RX_LAN_SLOTS];
    struct dp_rx_slot_ctx wan_rx_ctx[NE_RX_WAN_SLOTS];
    int crypto_started = 0;
    int local_rx_started = 0, local_tx_started = 0, wan_tx_started = 0, wan_rx_started = 0;

    if (!fwd || forwarder_should_stop())
        return;

    if (ne_cpu_map_validate() != 0)
        return;

    {
        int lan_rx_active = ne_rx_lan_slots_for(fwd->pair.local_queue_total);

        for (int w = 0; w < lan_rx_active; w++) {
            local_rx_ctx[w].fwd = fwd;
            local_rx_ctx[w].rx_slot = w;
            local_rx_ctx[w].cpu_id = ne_cpu_rx_lan((uint32_t)w);
            if (pthread_create(&fwd->local_rx_threads[w], NULL, local_rx_thread, &local_rx_ctx[w]) != 0) {
                forwarder_join_started(fwd, local_rx_started, 0, 0, 0, 0);
                return;
            }
            local_rx_started++;
        }
    }

    for (int w = 0; w < (int)NE_TX_SLOTS; w++) {
        local_tx_ctx[w].fwd = fwd;
        local_tx_ctx[w].tx_slot = w;
        local_tx_ctx[w].cpu_id = ne_cpu_tx_lan((uint32_t)w);
        if (pthread_create(&fwd->local_tx_threads[w], NULL, local_tx_thread, &local_tx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, local_tx_started, 0, 0, 0);
            return;
        }
        local_tx_started++;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        crypto_ctx[w].fwd = fwd;
        crypto_ctx[w].worker_idx = w;
        crypto_ctx[w].cpu_id = ne_cpu_crypto((uint32_t)w);
        if (pthread_create(&fwd->crypto_threads[w], NULL, crypto_worker_thread, &crypto_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, local_tx_started, crypto_started, 0, 0);
            return;
        }
        crypto_started++;
    }

    for (int w = 0; w < (int)NE_TX_SLOTS; w++) {
        wan_tx_ctx[w].fwd = fwd;
        wan_tx_ctx[w].tx_slot = w;
        wan_tx_ctx[w].cpu_id = ne_cpu_tx_wan((uint32_t)w);
        if (pthread_create(&fwd->wan_tx_threads[w], NULL, wan_tx_thread, &wan_tx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, local_tx_started, crypto_started,
                                   wan_tx_started, 0);
            return;
        }
        wan_tx_started++;
    }

    {
        int wan_rx_active = ne_rx_wan_slots_for(fwd->pair.wan_queue_total);

        for (int w = 0; w < wan_rx_active; w++) {
            wan_rx_ctx[w].fwd = fwd;
            wan_rx_ctx[w].rx_slot = w;
            wan_rx_ctx[w].cpu_id = ne_cpu_rx_wan((uint32_t)w);
            if (pthread_create(&fwd->wan_rx_threads[w], NULL, wan_rx_thread, &wan_rx_ctx[w]) != 0) {
                forwarder_join_started(fwd, local_rx_started, local_tx_started, crypto_started,
                                       wan_tx_started, wan_rx_started);
                return;
            }
            wan_rx_started++;
        }
    }

    fwd->threads_started = 1;
    if (fwd->cfg) {
        ne_cpu_map_log();
        main_diag_log_dataplane_ready(fwd->cfg);
    }
    for (int w = 0; w < local_rx_started; w++)
        pthread_join(fwd->local_rx_threads[w], NULL);
    for (int w = 0; w < (int)NE_TX_SLOTS; w++)
        pthread_join(fwd->local_tx_threads[w], NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    for (int w = 0; w < (int)NE_TX_SLOTS; w++)
        pthread_join(fwd->wan_tx_threads[w], NULL);
    for (int w = 0; w < wan_rx_started; w++)
        pthread_join(fwd->wan_rx_threads[w], NULL);
    fwd->threads_started = 0;
}

void forwarder_stop(void)
{
    atomic_store_explicit(&running, 0, memory_order_release);
}

void forwarder_shutdown_resources(void)
{
    fwd_reload_shutdown();
}

int forwarder_should_stop(void)
{
    return atomic_load_explicit(&running, memory_order_acquire) == 0;
}