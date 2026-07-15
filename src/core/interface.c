#include "../../inc/core/interface.h"
#include "../../inc/core/profile_iface_xdp.h"
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>

#ifndef NE_DP_WARN_LOG_ENABLE
#define NE_DP_WARN_LOG_ENABLE 0
#endif

#define NE_DP_WARN_RX_LAN   0
#define NE_DP_WARN_RX_WAN   1
#define NE_DP_WARN_TX_LAN0  2
#define NE_DP_WARN_TX_LAN1  3
#define NE_DP_WARN_TX_WAN0  4
#define NE_DP_WARN_TX_WAN1  5
#define NE_DP_WARN_CRYPTO0  6
#define NE_DP_WARN_SLOTS    (NE_DP_WARN_CRYPTO0 + NE_CRYPTO_WORKERS)
#define NE_DP_WARN_CLEAR    8192u

#if NE_DP_WARN_LOG_ENABLE
static int dp_warn_on[NE_DP_WARN_SLOTS];
static uint32_t dp_warn_clear_streak[NE_DP_WARN_SLOTS];
static pthread_mutex_t dp_warn_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread const char *tls_dp_tx_dir;
static __thread int tls_dp_tx_slot = -1;
#endif

static void dp_warn_once(int id, int active, const char *fmt, ...)
{
#if NE_DP_WARN_LOG_ENABLE
    va_list ap;

    if (id < 0 || id >= NE_DP_WARN_SLOTS)
        return;
    pthread_mutex_lock(&dp_warn_lock);
    if (active) {
        dp_warn_clear_streak[id] = 0;
        if (!dp_warn_on[id]) {
            fprintf(stderr, "[DP-WARN] ");
            va_start(ap, fmt);
            vfprintf(stderr, fmt, ap);
            va_end(ap);
            fprintf(stderr, "\n");
            fflush(stderr);
            dp_warn_on[id] = 1;
        }
    } else if (dp_warn_on[id]) {
        dp_warn_clear_streak[id]++;
        if (dp_warn_clear_streak[id] >= NE_DP_WARN_CLEAR) {
            dp_warn_on[id] = 0;
            dp_warn_clear_streak[id] = 0;
        }
    }
    pthread_mutex_unlock(&dp_warn_lock);
#else
    (void)id;
    (void)active;
    (void)fmt;
#endif
}

void ne_dp_tx_ctx(const char *dir, int tx_slot)
{
#if NE_DP_WARN_LOG_ENABLE
    tls_dp_tx_dir = dir;
    tls_dp_tx_slot = tx_slot;
#else
    (void)dir;
    (void)tx_slot;
#endif
}

void ne_dp_warn_rx(const char *dir, int cpu, int batch_rcvd)
{
    int id = (dir && (dir[0] == 'W' || dir[0] == 'w')) ? NE_DP_WARN_RX_WAN : NE_DP_WARN_RX_LAN;

    if (batch_rcvd <= 0)
        dp_warn_once(id, 0, "");
}

void ne_dp_warn_rx_drop(const char *dir, int cpu, int worker, uint32_t q_depth)
{
    int id = (dir && (dir[0] == 'W' || dir[0] == 'w')) ? NE_DP_WARN_RX_WAN : NE_DP_WARN_RX_LAN;

    dp_warn_once(id, 1,
                 "core=%d RX %s saturated worker=%d q_depth=%u (crypto queue full)",
                 cpu, dir ? dir : "?", worker, q_depth);
}

void ne_dp_warn_tx(int cpu, int tx_full, uint32_t pending)
{
#if NE_DP_WARN_LOG_ENABLE
    int id;
    int active;

    if (!tls_dp_tx_dir || tls_dp_tx_slot < 0 || tls_dp_tx_slot >= (int)NE_TX_SLOTS)
        return;
    if (tls_dp_tx_dir[0] == 'L' || tls_dp_tx_dir[0] == 'l')
        id = NE_DP_WARN_TX_LAN0 + tls_dp_tx_slot;
    else
        id = NE_DP_WARN_TX_WAN0 + tls_dp_tx_slot;
    active = tx_full && pending > 0;
    dp_warn_once(id, active,
                 "core=%d TX %s slot=%d saturated pending=%u (TX ring full)",
                 cpu, tls_dp_tx_dir, tls_dp_tx_slot, pending);
#else
    (void)cpu;
    (void)tx_full;
    (void)pending;
#endif
}

void ne_dp_warn_crypto(int cpu, int worker, uint32_t lan_q, uint32_t wan_q)
{
    uint32_t hi = (NE_RING * 7u) / 8u;

    if (worker < 0 || worker >= (int)NE_CRYPTO_WORKERS)
        return;
    dp_warn_once(NE_DP_WARN_CRYPTO0 + worker, lan_q >= hi || wan_q >= hi,
                 "core=%d crypto saturated worker=%d lan_q=%u wan_q=%u",
                 cpu, worker, lan_q, wan_q);
}

static int ne_rx_slots_for_queues(int queue_total, uint32_t slots_max)
{
    if (queue_total <= 0)
        return 1;
    if ((uint32_t)queue_total < slots_max)
        return queue_total;
    return (int)slots_max;
}

int ne_rx_lan_slots_for(int local_queue_total)
{
    return ne_rx_slots_for_queues(local_queue_total, NE_RX_LAN_SLOTS);
}

int ne_rx_wan_slots_for(int wan_queue_total)
{
    return ne_rx_slots_for_queues(wan_queue_total, NE_RX_WAN_SLOTS);
}

void ne_dp_log_hw_scale(int local_queue_total, int wan_queue_total)
{
    fprintf(stderr,
            "[DP-CONF] HW scale: queues(lan=%d wan=%d total=%d) "
            "RX threads(lan=%d/%u wan=%d/%u)\n",
            local_queue_total, wan_queue_total,
            local_queue_total + wan_queue_total,
            ne_rx_lan_slots_for(local_queue_total), (unsigned)NE_RX_LAN_SLOTS,
            ne_rx_wan_slots_for(wan_queue_total), (unsigned)NE_RX_WAN_SLOTS);
    fflush(stderr);
}

static uint32_t pool_free_count(struct ne_pool *p)
{
    if (!p || !p->buf)
        return 0;
    return p->cap - (p->head - p->tail);
}

static void ne_dp_warn_pool_empty(void)
{
    static int warned;

    if (warned)
        return;
    warned = 1;
    fprintf(stderr, "[DP-WARN] UMEM pool empty (frame alloc/refill failed)\n");
    fflush(stderr);
}

static int ifname_is_safe(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *)ifname; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static int interface_set_promisc_off(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc off >/dev/null 2>&1", ifname);
    return system(cmd) == 0 ? 0 : -1;
}

void interface_promisc_off_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        interface_set_promisc_off(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        interface_set_promisc_off(cfg->wans[i].ifname);
}

void interface_reset_redirect_maps(void) {}

int interface_set_queue_count(const char *ifname, int desired_count)
{
    if (!ifname_is_safe(ifname) || desired_count <= 0)
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ethtool -L %s combined %d >/dev/null 2>&1",
             ifname, desired_count);
    if (system(cmd) == 0) {
        return 0;
    }

    snprintf(cmd, sizeof(cmd), "ethtool -L %s rx %d tx %d >/dev/null 2>&1",
             ifname, desired_count, desired_count);
    if (system(cmd) == 0)
        return 0;

    return -1;
}

static int interface_set_promisc(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc on >/dev/null 2>&1", ifname);
    if (system(cmd) == 0)
        return 0;

    return -1;
}

int interface_get_queue_count(const char *ifname)
{
    char path[256];
    int count = 0;

    if (!ifname_is_safe(ifname))
        return 1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", ifname);
    DIR *dir = opendir(path);
    if (!dir)
        return 1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "rx-", 3) == 0)
            count++;
    }
    closedir(dir);
    return count > 0 ? count : 1;
}

static int resolve_iface_queue_count(const char *ifname)
{
    int hw = interface_get_queue_count(ifname);
    if (hw < 1)
        hw = 1;

#if NE_QUEUE_OVERRIDE > 0
    int want = NE_QUEUE_OVERRIDE;
#else
    int want = hw;
#endif

    if (want > MAX_QUEUES)
        want = MAX_QUEUES;
    if (want < 1)
        want = 1;
    return want;
}

static int apply_iface_queue_count(const char *ifname, int want)
{
#if NE_QUEUE_OVERRIDE > 0
    int hw = interface_get_queue_count(ifname);

    if (hw != want)
        return interface_set_queue_count(ifname, want);
#endif
    (void)ifname;
    (void)want;
    return 0;
}

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop)
{
    if (!r || cap == 0 || (cap & (cap - 1)) != 0)
        return -1;
    memset(r, 0, sizeof(*r));
    r->buf = calloc(cap, sizeof(*r->buf));
    if (!r->buf)
        return -1;
    r->cap = cap;
    r->mask = cap - 1;
    r->mpsc_pop = mpsc_pop ? 1 : 0;
    if (pthread_spin_init(&r->push_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    if (r->mpsc_pop && pthread_spin_init(&r->pop_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        pthread_spin_destroy(&r->push_lock);
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
    if (!r)
        return;
    if (r->mpsc_pop)
        pthread_spin_destroy(&r->pop_lock);
    pthread_spin_destroy(&r->push_lock);
    free(r->buf);
    memset(r, 0, sizeof(*r));
}

// Push gói tin đi vào ring (muilti core push)
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt)
{
    uint32_t head, tail;

    if (!r || !pkt)
        return -1;

    pthread_spin_lock(&r->push_lock);
    head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if ((uint32_t)(head - tail) >= r->cap) {
        pthread_spin_unlock(&r->push_lock);
        return -1;
    }
    r->buf[head & r->mask] = *pkt;
    __atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
    pthread_spin_unlock(&r->push_lock);
    return 0;
}

// Pop gói tin đi ra khỏi ring
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt)
{
    uint32_t tail, head;

    if (!r || !pkt)
        return -1;

    if (r->mpsc_pop)
        pthread_spin_lock(&r->pop_lock);
    tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    if (tail == head) { // ring trống
        if (r->mpsc_pop)
            pthread_spin_unlock(&r->pop_lock);
        return -1;
    }
    *pkt = r->buf[tail & r->mask];
    __atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
    if (r->mpsc_pop)
        pthread_spin_unlock(&r->pop_lock);
    return 0;
}

uint32_t ne_ring_count(const struct ne_ring *r)
{
    uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    return head - tail;
}

static int pool_init(struct ne_pool *p, uint32_t cap)
{
    if (!p || cap == 0 || (cap & (cap - 1)) != 0)
        return -1;
    memset(p, 0, sizeof(*p));
    p->buf = calloc(cap, sizeof(*p->buf));
    if (!p->buf)
        return -1;
    p->cap = cap;
    p->mask = cap - 1;
    if (pthread_spin_init(&p->lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        free(p->buf);
        memset(p, 0, sizeof(*p));
        return -1;
    }
    return 0;
}

static void pool_destroy(struct ne_pool *p)
{
    if (!p || !p->buf)
        return;
    pthread_spin_destroy(&p->lock);
    free(p->buf);
    memset(p, 0, sizeof(*p));
}

static uint32_t pool_push(struct ne_pool *p, const uint64_t *addrs, uint32_t n)
{
    pthread_spin_lock(&p->lock);
    uint32_t free_slots = p->cap - (p->head - p->tail);
    uint32_t put = n < free_slots ? n : free_slots;
    uint32_t head = p->head;
    for (uint32_t i = 0; i < put; i++)
        p->buf[(head + i) & p->mask] = addrs[i];
    p->head += put;
    pthread_spin_unlock(&p->lock);
    return put;
}

static uint32_t pool_pop(struct ne_pool *p, uint64_t *addrs, uint32_t n)
{
    pthread_spin_lock(&p->lock);
    uint32_t avail = p->head - p->tail;
    uint32_t got = n < avail ? n : avail;
    uint32_t tail = p->tail;
    for (uint32_t i = 0; i < got; i++)
        addrs[i] = p->buf[(tail + i) & p->mask];
    p->tail += got;
    pthread_spin_unlock(&p->lock);
    return got;
}

int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out)
{
    if (p && addr_out && pool_pop(&p->pool, addr_out, 1) == 1)
        return 0;
    ne_dp_warn_pool_empty();
    return -1;
}

uint32_t ne_frame_alloc_batch(struct ne_pair *p, uint64_t *addrs_out, uint32_t max_n)
{
    if (!p || !addrs_out || max_n == 0)
        return 0;
    return pool_pop(&p->pool, addrs_out, max_n);
}

void ne_frame_free(struct ne_pair *p, uint64_t addr)
{
    if (p)
        (void)pool_push(&p->pool, &addr, 1);
}

void *ne_packet_data(struct ne_pair *p, uint64_t addr)
{
    return xsk_umem__get_data(p->bufs, addr);
}

static int open_iface_queues(struct ne_pair *p, struct ne_iface *iface,
                             const char *ifname, int queue_count)
{
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = p->xdp_flags,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    iface->ifindex = (int)if_nametoindex(ifname);
    if (!iface->ifindex)
        return -1;
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    iface->queue_count = queue_count;

    for (int q = 0; q < queue_count; q++) {
        struct ne_xsk_queue *slot = &iface->queues[q];
        int ret = xsk_socket__create_shared(&slot->xsk, ifname, (uint32_t)q, p->umem,
                                            &slot->rx, &slot->tx,
                                            &slot->fq, &slot->cq, &cfg);
        if (ret)
            return -1;
    }
    return 0;
}

static void prefill_queue(struct ne_pair *p, struct ne_xsk_queue *slot, uint32_t want)
{
    uint64_t addrs[NE_BATCH_SIZE];

    while (want > 0) {
        uint32_t n = want > NE_BATCH_SIZE ? NE_BATCH_SIZE : want;
        uint32_t got = pool_pop(&p->pool, addrs, n);
        if (got == 0)
            return;

        uint32_t idx = 0;
        uint32_t reserved = xsk_ring_prod__reserve(&slot->fq, got, &idx);
        if (reserved != got) {
            (void)pool_push(&p->pool, addrs, got);
            return;
        }
        for (uint32_t i = 0; i < got; i++)
            *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
        xsk_ring_prod__submit(&slot->fq, got);
        want -= got;
    }
}

static void prefill_iface(struct ne_pair *p, struct ne_iface *iface, uint32_t want_per_queue)
{
    for (int q = 0; q < iface->queue_count; q++)
        prefill_queue(p, &iface->queues[q], want_per_queue);
}

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg)
{
#define NE_TRY(expr) do { if (expr) goto fail; } while (0)
    if (!p || !cfg || cfg->local_count <= 0)
        return -1;

    memset(p, 0, sizeof(*p));
    p->local_count = cfg->local_count;
    if (p->local_count > MAX_INTERFACES)
        p->local_count = MAX_INTERFACES;
    p->wan_count = config_count_dataplane_wans(cfg);
    if (p->wan_count > MAX_INTERFACES)
        p->wan_count = MAX_INTERFACES;
    if (p->wan_count == 0) {
        fprintf(stderr, "[DP-CONF] no dataplane WAN rows — LAN-only dataplane\n");
        fflush(stderr);
    }
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);

    p->frame_size = NE_FRAME;
    p->xdp_flags = XDP_FLAGS_DRV_MODE;

    p->local_queue_total = 0;
    p->wan_queue_total = 0;

    for (int i = 0; i < p->local_count; i++) {
        int nq = resolve_iface_queue_count(cfg->locals[i].ifname);
        NE_TRY(apply_iface_queue_count(cfg->locals[i].ifname, nq));
        p->locals[i].queue_count = nq;
        p->local_queue_total += nq;
        fprintf(stderr, "[DP-CONF] %s LAN queues=%d%s\n", cfg->locals[i].ifname, nq,
                NE_QUEUE_OVERRIDE > 0 ? " (override)" : " (nic)");
    }
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        int nq = resolve_iface_queue_count(cfg->wans[ci].ifname);
        NE_TRY(apply_iface_queue_count(cfg->wans[ci].ifname, nq));
        p->wans[di].queue_count = nq;
        p->wan_queue_total += nq;
        fprintf(stderr, "[DP-CONF] %s WAN queues=%d%s\n", cfg->wans[ci].ifname, nq,
                NE_QUEUE_OVERRIDE > 0 ? " (override)" : " (nic)");
    }

    p->n_frames = NE_N_FRAMES;
    p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;

    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p->bufs == MAP_FAILED)
        return -1;

    NE_TRY(pool_init(&p->pool, p->n_frames));
    for (uint32_t i = 0; i < p->n_frames; i++) {
        uint64_t addr = (uint64_t)i * p->frame_size;
        (void)pool_push(&p->pool, &addr, 1);
    }

    for (int i = 0; i < p->local_count; i++)
        NE_TRY(interface_set_promisc(cfg->locals[i].ifname));
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        NE_TRY(interface_set_promisc(cfg->wans[ci].ifname));
    }

    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = p->frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize,
                            &p->locals[0].queues[0].fq,
                            &p->locals[0].queues[0].cq, &ucfg));

    for (int i = 0; i < p->local_count; i++)
        NE_TRY(open_iface_queues(p, &p->locals[i], cfg->locals[i].ifname,
                                 p->locals[i].queue_count));
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        NE_TRY(open_iface_queues(p, &p->wans[di], cfg->wans[ci].ifname,
                                 p->wans[di].queue_count));
    }

    uint32_t prefill = NE_FQ_PREFILL;
    uint32_t fq_total = prefill * (uint32_t)(p->local_queue_total + p->wan_queue_total);

    fprintf(stderr,
            "[DP-CONF] UMEM frames=%u (~%zu MB) queues=%d fq_prefill/queue=%u (~%u in FQ, ~%u free)\n",
            p->n_frames, p->bufsize / (1024u * 1024u),
            p->local_queue_total + p->wan_queue_total, prefill, fq_total,
            pool_free_count(&p->pool));
    fflush(stderr);

    for (int i = 0; i < p->local_count; i++)
        prefill_iface(p, &p->locals[i], prefill);
    for (int i = 0; i < p->wan_count; i++)
        prefill_iface(p, &p->wans[i], prefill);

    fprintf(stderr, "[DP-CONF] UMEM pool after FQ prefill: ~%u frames free\n",
            pool_free_count(&p->pool));
    ne_dp_log_hw_scale(p->local_queue_total, p->wan_queue_total);
    fflush(stderr);

    for (int i = 0; i < p->local_count; i++)
        p->local_live[i] = 1;
    for (int i = 0; i < p->wan_count; i++)
        p->wan_live[i] = 1;

    return 0;

fail:
    profile_iface_xdp_detach_config(cfg);
    ne_pair_close(p);
    return -1;
#undef NE_TRY
}

void ne_pair_close(struct ne_pair *p)
{
    if (!p)
        return;
    for (int i = 0; i < p->local_count; i++)
        profile_iface_xdp_detach_local(p, i);
    for (int i = 0; i < p->wan_count; i++)
        profile_iface_xdp_detach_wan(p, i);
    for (int i = 0; i < p->wan_count; i++) {
        for (int q = 0; q < p->wans[i].queue_count; q++) {
            if (p->wans[i].queues[q].xsk)
                xsk_socket__delete(p->wans[i].queues[q].xsk);
        }
    }
    for (int i = 0; i < p->local_count; i++) {
        for (int q = 0; q < p->locals[i].queue_count; q++) {
            if (p->locals[i].queues[q].xsk)
                xsk_socket__delete(p->locals[i].queues[q].xsk);
        }
    }
    if (p->umem)
        xsk_umem__delete(p->umem);
    pool_destroy(&p->pool);
    if (p->bufs && p->bufs != MAP_FAILED)
        munmap(p->bufs, p->bufsize);
    memset(p, 0, sizeof(*p));
}

int ne_pair_local_live(const struct ne_pair *p, int pair_local_idx)
{
    if (!p || pair_local_idx < 0 || pair_local_idx >= p->local_count)
        return 0;
    return p->local_live[pair_local_idx] != 0;
}

int ne_pair_wan_live(const struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= p->wan_count)
        return 0;
    return p->wan_live[dp_slot] != 0;
}

int ne_pair_plumb_local(struct ne_pair *p, const struct app_config *cfg, int cfg_local_idx,
                        int pair_li)
{
    if (!p || !cfg || !p->umem || cfg_local_idx < 0 || cfg_local_idx >= cfg->local_count)
        return -1;
    if (pair_li < 0 || pair_li >= MAX_INTERFACES)
        return -1;

    const char *ifname = cfg->locals[cfg_local_idx].ifname;
    int nq = resolve_iface_queue_count(ifname);
    if (apply_iface_queue_count(ifname, nq) != 0)
        return -1;
    p->locals[pair_li].queue_count = nq;
    if (interface_set_promisc(ifname) != 0)
        return -1;
    if (open_iface_queues(p, &p->locals[pair_li], ifname, nq) != 0)
        return -1;

    if (pair_li >= p->local_count)
        p->local_count = pair_li + 1;
    p->local_queue_total += nq;
    prefill_iface(p, &p->locals[pair_li], NE_FQ_PREFILL);
    p->local_live[pair_li] = 1;
    return 0;
}

int ne_pair_plumb_wan_dp(struct ne_pair *p, const struct app_config *cfg, int cfg_wan_idx,
                         int dp_slot)
{
    if (!p || !cfg || !p->umem || cfg_wan_idx < 0 || cfg_wan_idx >= cfg->wan_count)
        return -1;
    if (!cfg->wans[cfg_wan_idx].dataplane || dp_slot < 0 || dp_slot >= MAX_INTERFACES)
        return -1;

    const char *ifname = cfg->wans[cfg_wan_idx].ifname;
    int nq = resolve_iface_queue_count(ifname);
    if (apply_iface_queue_count(ifname, nq) != 0)
        return -1;
    p->wans[dp_slot].queue_count = nq;
    if (interface_set_promisc(ifname) != 0)
        return -1;
    if (open_iface_queues(p, &p->wans[dp_slot], ifname, nq) != 0)
        return -1;

    if (dp_slot >= p->wan_count)
        p->wan_count = dp_slot + 1;
    p->wan_queue_total += nq;
    prefill_iface(p, &p->wans[dp_slot], NE_FQ_PREFILL);
    p->wan_live[dp_slot] = 1;
    return 0;
}

void ne_pair_unplumb_local(struct ne_pair *p, int pair_li)
{
    if (!p || pair_li < 0 || pair_li >= p->local_count || !p->local_live[pair_li])
        return;

    profile_iface_xdp_detach_local(p, pair_li);
    p->local_live[pair_li] = 0;
    int nq = p->locals[pair_li].queue_count;
    p->locals[pair_li].queue_count = 0;
    for (int q = 0; q < nq; q++) {
        if (p->locals[pair_li].queues[q].xsk) {
            xsk_socket__delete(p->locals[pair_li].queues[q].xsk);
            p->locals[pair_li].queues[q].xsk = NULL;
        }
    }
}

void ne_pair_unplumb_wan_dp(struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= p->wan_count || !p->wan_live[dp_slot])
        return;

    profile_iface_xdp_detach_wan(p, dp_slot);
    p->wan_live[dp_slot] = 0;
    int nq = p->wans[dp_slot].queue_count;
    p->wans[dp_slot].queue_count = 0;
    for (int q = 0; q < nq; q++) {
        if (p->wans[dp_slot].queues[q].xsk) {
            xsk_socket__delete(p->wans[dp_slot].queues[q].xsk);
            p->wans[dp_slot].queues[q].xsk = NULL;
        }
    }
}
// RX
static int recv_queue(struct ne_xsk_queue *slot, struct ne_packet *out, uint32_t max,
                      uint8_t dir, uint8_t wan_idx, uint8_t local_idx)
{
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&slot->rx, max, &idx);
    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&slot->rx, idx + i);
        out[i].addr = d->addr;
        out[i].len = d->len;
        out[i].dir = dir;
        out[i].wan_idx = wan_idx;
        out[i].local_idx = local_idx;
    }
    slot->rx_pending = n;
    return (int)n;
}

static int xsk_queue_for_rx_slot(int q, int rx_slot, int nq, int rx_slots)
{
    int slots = nq < rx_slots ? (nq > 0 ? nq : 1) : rx_slots;

    if (rx_slot >= slots)
        return 0;
    return (q % slots) == rx_slot;
}

int ne_recv_local_slot(struct ne_pair *p, int rx_slot, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return 0;

    for (int i = 0; i < p->local_count && total < max; i++) {
        if (!p->local_live[i])
            continue;
        struct ne_iface *iface = &p->locals[i];
        int q_count = iface->queue_count;

        for (int q = 0; q < q_count && total < max; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, q_count, (int)NE_RX_LAN_SLOTS))
                continue;
            iface->queues[q].rx_pending = 0;

            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_LOCAL, 0, (uint8_t)i);

            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}

int ne_recv_local(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    return ne_recv_local_slot(p, 0, out, max);
}

int ne_recv_wan_slot(struct ne_pair *p, int rx_slot, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return 0;

    for (int i = 0; i < p->wan_count && total < max; i++) {
        if (!p->wan_live[i])
            continue;
        struct ne_iface *iface = &p->wans[i];
        int q_count = iface->queue_count;

        for (int q = 0; q < q_count && total < max; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, q_count, (int)NE_RX_WAN_SLOTS))
                continue;
            iface->queues[q].rx_pending = 0;

            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_WAN, (uint8_t)i, 0);

            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}

int ne_recv_wan(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    return ne_recv_wan_slot(p, 0, out, max);
}


void ne_recv_release_local_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return;

    for (int i = 0; i < p->local_count; i++) {
        struct ne_iface *iface = &p->locals[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, iface->queue_count, (int)NE_RX_LAN_SLOTS))
                continue;
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

void ne_recv_release_local(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_LAN_SLOTS; s++)
        ne_recv_release_local_slot(p, s);
}

void ne_recv_release_wan_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return;

    for (int i = 0; i < p->wan_count; i++) {
        struct ne_iface *iface = &p->wans[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (!xsk_queue_for_rx_slot(q, rx_slot, iface->queue_count, (int)NE_RX_WAN_SLOTS))
                continue;
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

void ne_recv_release_wan(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_WAN_SLOTS; s++)
        ne_recv_release_wan_slot(p, s);
}


// CQ
static void drain_cq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t n;

    while ((n = xsk_ring_cons__peek(&slot->cq, NE_BATCH_SIZE, &idx)) > 0) {
        for (uint32_t i = 0; i < n; i++)
            addrs[i] = *xsk_ring_cons__comp_addr(&slot->cq, idx + i);
        uint32_t pushed = pool_push(pool, addrs, n);
        if (pushed > 0)
            xsk_ring_cons__release(&slot->cq, pushed);
        if (pushed < n || n < NE_BATCH_SIZE)
            break;
    }
}

static int xsk_queue_for_tx_slot(int q, int tx_slot, int nq)
{
    int slots = nq < (int)NE_TX_SLOTS ? (nq > 0 ? nq : 1) : (int)NE_TX_SLOTS;

    if (tx_slot >= slots)
        return 0;
    return (q % slots) == tx_slot;
}

static void drain_cq_iface_slot(struct ne_iface *iface, struct ne_pool *pool, int tx_slot)
{
    int nq = iface->queue_count;

    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_tx_slot(q, tx_slot, nq))
            continue;
        drain_cq_queue(&iface->queues[q], pool);
    }
}

void ne_drain_cq_local(struct ne_pair *p, int tx_slot)
{
    if (!p || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        drain_cq_iface_slot(&p->locals[i], &p->pool, tx_slot);
    }
}

void ne_drain_cq_wan(struct ne_pair *p, int tx_slot)
{
    if (!p || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        drain_cq_iface_slot(&p->wans[i], &p->pool, tx_slot);
    }
}

static void refill_fq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t free_slots = xsk_prod_nb_free(&slot->fq, NE_BATCH_SIZE);
    uint32_t want;
    uint32_t got;

    if (!free_slots)
        return;
    want = free_slots > NE_BATCH_SIZE ? NE_BATCH_SIZE : free_slots;
    got = pool_pop(pool, addrs, want);
    if (!got)
        return;
    if (xsk_ring_prod__reserve(&slot->fq, got, &idx) != got) {
        (void)pool_push(pool, addrs, got);
        return;
    }
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&slot->fq, got);
}

static void refill_fq_iface_slot(struct ne_iface *iface, struct ne_pool *pool, int rx_slot,
                                  int rx_slots)
{
    int nq = iface->queue_count;

    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_rx_slot(q, rx_slot, nq, rx_slots))
            continue;
        refill_fq_queue(&iface->queues[q], pool);
    }
}

void ne_refill_fq_local_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_LAN_SLOTS)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        refill_fq_iface_slot(&p->locals[i], &p->pool, rx_slot, (int)NE_RX_LAN_SLOTS);
    }
}

void ne_refill_fq_wan_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_WAN_SLOTS)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        refill_fq_iface_slot(&p->wans[i], &p->pool, rx_slot, (int)NE_RX_WAN_SLOTS);
    }
}

void ne_refill_fq_local(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_LAN_SLOTS; s++)
        ne_refill_fq_local_slot(p, s);
}

void ne_refill_fq_wan(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_WAN_SLOTS; s++)
        ne_refill_fq_wan_slot(p, s);
}

// TX
static int tx_drain_queue(struct ne_xsk_queue *slot, struct ne_ring *src, uint32_t max_frame,
                          uint64_t *tx_no_free)
{   
    struct ne_packet jobs[NE_BATCH_SIZE];
    uint32_t free_slots = xsk_prod_nb_free(&slot->tx, NE_BATCH_SIZE);
    uint32_t pending = ne_ring_count(src);
    int cpu = sched_getcpu();

    if (!free_slots) {
        if (tx_no_free)
            (*tx_no_free)++;
        ne_dp_warn_tx(cpu, 1, pending);
        if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
            (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
        return 0;
    }
    ne_dp_warn_tx(cpu, 0, pending);

    uint32_t popped = 0;
    uint32_t want = free_slots > NE_BATCH_SIZE ? NE_BATCH_SIZE : free_slots;
    while (popped < want && ne_ring_try_pop(src, &jobs[popped]) == 0)
        popped++;
    if (!popped)
        return 0;

    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&slot->tx, popped, &idx) != popped) {
        for (uint32_t i = 0; i < popped; i++)
            (void)ne_ring_try_push(src, &jobs[i]);
        return 0;
    }

    for (uint32_t i = 0; i < popped; i++) {
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&slot->tx, idx + i);
        d->addr = jobs[i].addr;
        d->len = jobs[i].len > max_frame ? max_frame : jobs[i].len;
    }

    xsk_ring_prod__submit(&slot->tx, popped);
    if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
    return (int)popped;
}


static int tx_drain_iface_ring(struct ne_iface *iface, struct ne_ring *src, uint32_t max_frame,
                               int tx_slot)
{
    int nq = iface->queue_count;

    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_tx_slot(q, tx_slot, nq))
            continue;
        int sent = tx_drain_queue(&iface->queues[q], src, max_frame, &iface->tx_no_free);
        if (sent > 0)
            return sent;
    }
    return 0;
}

static __thread uint32_t tls_tx_drain_rr;

static int tx_drain_iface_all_rings(struct ne_iface *iface, struct ne_ring *srcs[],
                                    int src_count, uint32_t max_frame, int tx_slot)
{
    int sent = 0;
    int start;

    if (!srcs || src_count <= 0)
        return 0;

    start = (int)(tls_tx_drain_rr % (uint32_t)src_count);
    for (int i = 0; i < src_count; i++) {
        int s = (start + i) % src_count;

        if (!srcs[s])
            continue;
        sent += tx_drain_iface_ring(iface, srcs[s], max_frame, tx_slot);
    }
    if (sent > 0)
        tls_tx_drain_rr++;
    return sent;
}

int ne_tx_drain_local_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                          int local_idx, int tx_slot)
{
    if (!p || local_idx < 0 || local_idx >= p->local_count)
        return 0;
    if (!p->local_live[local_idx])
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    return tx_drain_iface_all_rings(&p->locals[local_idx], srcs, src_count, p->frame_size,
                                    tx_slot);
}

int ne_tx_drain_wan_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                        int wan_idx, int tx_slot)
{
    if (!p || wan_idx < 0 || wan_idx >= p->wan_count)
        return 0;
    if (!p->wan_live[wan_idx])
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    return tx_drain_iface_all_rings(&p->wans[wan_idx], srcs, src_count, p->frame_size, tx_slot);
}