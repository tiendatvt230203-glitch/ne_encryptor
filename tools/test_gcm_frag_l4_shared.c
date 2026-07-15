/*
 * Diagnose L4 shared frag_table under concurrent reassemble + GC.
 *
 * Models production: one frag_table, many writers, GC on side (worker-0 style).
 * Also runs intentional pkt_id slot collisions (same pkt_id % FRAG_TABLE_SIZE).
 *
 * Build:
 *   gcc -O2 -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include \
 *     tools/test_gcm_frag_l4_shared.c \
 *     src/core/fragment.o src/crypto/packet_crypto.o \
 *     src/crypto/crypto_layer2.o src/crypto/crypto_layer3.o src/crypto/crypto_layer4.o \
 *     src/crypto/eth_parse.o \
 *     -L./lib -Wl,-rpath,'$ORIGIN/../lib' -lssl -lcrypto -lpthread -lscrypt \
 *     -o tools/test_gcm_frag_l4_shared
 *   LD_LIBRARY_PATH=./lib ./tools/test_gcm_frag_l4_shared
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include "inc/core/config.h"
#include "inc/core/fragment.h"
#include "inc/crypto/packet_crypto.h"
#include "inc/crypto/crypto_layer2.h"
#include "inc/crypto/crypto_layer4.h"

#define N_WORKERS     6
#define N_KEYS        4
#define ITERS         3000
#define PAYLOAD       1200
#define TEST_FRAG_MTU 700
#define COLLIDE_ITERS 500

int sig_pqc_diversify_key(int profile_id, int policy_id, uint8_t *out_policy_key)
{
    (void)profile_id;
    (void)policy_id;
    if (out_policy_key)
        memset(out_policy_key, 0xA5, 32);
    return 0;
}
int trf_pqc_generate_nonce(uint8_t *n)
{
    (void)n;
    return -1;
}
int trf_encrypt_payload_gcm(void *a, const uint8_t *b, const uint8_t *c, int d,
                            uint8_t *e, int f, int *g)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    (void)g;
    return -1;
}
int trf_decrypt_payload_gcm(void *a, const uint8_t *b, const uint8_t *c, int d,
                            uint8_t *e, int f, int *g)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    (void)g;
    return -1;
}

static struct packet_crypto_ctx g_ctx[N_KEYS];
static struct frag_table *g_ft; /* ONE shared table */

static atomic_int g_stop;
static atomic_ullong g_ok;
static atomic_ullong g_pending;
static atomic_ullong g_corrupt;
static atomic_ullong g_split_fail;
static atomic_ullong g_dec_fail;
static atomic_ullong g_gc_ticks;
static atomic_int g_dump_left = 8;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static size_t fill_udp(uint8_t *pkt, size_t pad, unsigned seed)
{
    size_t ip_tot = 20 + 8 + pad;
    size_t eth_len = 14 + ip_tot;
    memset(pkt, 0, eth_len);
    memset(pkt, 0x02, 6);
    memset(pkt + 6, 0x04, 6);
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    uint8_t *ip = pkt + 14;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(ip_tot >> 8);
    ip[3] = (uint8_t)(ip_tot & 0xff);
    ip[8] = 64;
    ip[9] = 17;
    ip[12] = 10;
    ip[13] = (uint8_t)((seed >> 8) & 0xff);
    ip[14] = (uint8_t)(seed & 0xff);
    ip[15] = 1;
    ip[16] = 10;
    ip[19] = 2;
    uint16_t c = crypto_calc_ip_checksum(ip, 20);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)(c & 0xff);
    uint8_t *u = ip + 20;
    u[0] = 0x12;
    u[1] = 0x34;
    u[2] = 0x56;
    u[3] = 0x78;
    uint16_t ul = (uint16_t)(8 + pad);
    u[4] = (uint8_t)(ul >> 8);
    u[5] = (uint8_t)(ul & 0xff);
    for (size_t i = 0; i < pad; i++)
        u[8 + i] = (uint8_t)((seed + i) & 0xff);
    return eth_len;
}

static void dump_corrupt(int tid, uint16_t pid, uint32_t olen, size_t plen)
{
    int left = atomic_fetch_sub(&g_dump_left, 1);
    if (left <= 0)
        return;
    fprintf(stderr,
            "CORRUPT join tid=%d pkt_id=%u slot=%u olen=%u expect_plen=%zu\n",
            tid, pid, (unsigned)(pid % FRAG_TABLE_SIZE), olen, plen);
}

struct thr_arg {
    int tid;
    int collide_mode;
    struct frag_table *ft; /* NULL → use global g_ft */
};

static int one_assembly(int tid, uint8_t kid, unsigned seed, const uint8_t *orig, size_t plen,
                        struct frag_table *ft)
{
    uint8_t work[2048], f1[2048], h0[2048], h1[2048], out[2048];
    uint32_t f0len = 0, f1len = 0, olen = 0;
    uint16_t pid0 = 0, pid1 = 0;
    uint8_t fx0 = 0, fx1 = 0;
    int nd0, nd1, rr;

    packet_crypto_set_policy_id((uint8_t)(kid + 1));
    packet_crypto_set_encrypt_layer(4);

    memcpy(work, orig, plen);
    if (frag_split_and_encrypt_l4(&g_ctx[kid], work, (uint32_t)plen, sizeof(work), &f0len,
                                  f1, sizeof(f1), &f1len) != 0) {
        atomic_fetch_add(&g_split_fail, 1);
        return -1;
    }

    memcpy(h0, work, f0len);
    memcpy(h1, f1, f1len);
    nd0 = crypto_layer4_decrypt_fragment(&g_ctx[kid], h0, f0len, &pid0, &fx0);
    nd1 = crypto_layer4_decrypt_fragment(&g_ctx[kid], h1, f1len, &pid1, &fx1);
    if (nd0 < 0 || nd1 < 0 || pid0 != pid1) {
        atomic_fetch_add(&g_dec_fail, 1);
        return -1;
    }

    if ((seed ^ (unsigned)tid) & 1) {
        rr = frag_try_reassemble_l4(ft, h1, (uint32_t)nd1, pid1, fx1, out, &olen);
        if (rr == 1) {
            atomic_fetch_add(&g_corrupt, 1);
            dump_corrupt(tid, pid1, olen, plen);
            return -1;
        }
        if (rr < 0) {
            atomic_fetch_add(&g_pending, 1);
            return -1;
        }
        atomic_fetch_add(&g_pending, 1);
        rr = frag_try_reassemble_l4(ft, h0, (uint32_t)nd0, pid0, fx0, out, &olen);
    } else {
        rr = frag_try_reassemble_l4(ft, h0, (uint32_t)nd0, pid0, fx0, out, &olen);
        if (rr == 1) {
            atomic_fetch_add(&g_corrupt, 1);
            dump_corrupt(tid, pid0, olen, plen);
            return -1;
        }
        if (rr < 0) {
            atomic_fetch_add(&g_pending, 1);
            return -1;
        }
        atomic_fetch_add(&g_pending, 1);
        rr = frag_try_reassemble_l4(ft, h1, (uint32_t)nd1, pid1, fx1, out, &olen);
    }

    if (rr == 1 && olen == (uint32_t)plen && memcmp(out, orig, plen) == 0) {
        atomic_fetch_add(&g_ok, 1);
        return 0;
    }
    if (rr == 0) {
        atomic_fetch_add(&g_pending, 1);
        return -1;
    }
    atomic_fetch_add(&g_corrupt, 1);
    dump_corrupt(tid, pid0, olen, plen);
    return -1;
}

static void *worker(void *arg)
{
    struct thr_arg *ta = arg;
    int tid = ta->tid;
    struct frag_table *ft = ta->ft ? ta->ft : g_ft;
    uint8_t orig[2048];
    size_t plen;
    int iters = ta->collide_mode ? COLLIDE_ITERS : ITERS;

    crypto_layer2_bind_worker_idx((uint8_t)tid);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int it = 0; it < iters && !atomic_load(&g_stop); it++) {
        uint8_t kid = (uint8_t)((tid + it) % N_KEYS);
        unsigned seed = (unsigned)(tid * 1000003u + (unsigned)it);
        plen = fill_udp(orig, PAYLOAD, seed);
        (void)one_assembly(tid, kid, seed, orig, plen, ft);
    }
    return NULL;
}

static void *gc_thread(void *arg)
{
    (void)arg;
    while (!atomic_load(&g_stop)) {
        frag_table_gc_at(g_ft, now_ns());
        atomic_fetch_add(&g_gc_ticks, 1);
        usleep(200); /* ~5 kHz GC pressure */
    }
    return NULL;
}

int main(void)
{
    pthread_t th[N_WORKERS];
    pthread_t gcth;
    struct thr_arg args[N_WORKERS];
    int rc = 0;

    g_ft = calloc(1, sizeof(*g_ft));
    if (!g_ft) {
        fprintf(stderr, "oom frag_table\n");
        return 1;
    }
    frag_table_init(g_ft);
    frag_set_mtu(TEST_FRAG_MTU);

    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int k = 0; k < N_KEYS; k++) {
        uint8_t master[32];
        memset(master, (uint8_t)(0x30 + k), sizeof(master));
        master[0] = (uint8_t)k;
        if (packet_crypto_init(&g_ctx[k], master) != 0)
            return 1;
        g_ctx[k].policy_id = k + 1;
    }
    packet_crypto_reset_counter();

    printf("L4 shared frag_table: workers=%d keys=%d iters=%d + GC thread\n",
           N_WORKERS, N_KEYS, ITERS);
    printf("note: production L4 WAN sticky worker0 may dodge this; harness forces multi-writer\n");

    atomic_store(&g_stop, 0);
    pthread_create(&gcth, NULL, gc_thread, NULL);

    for (int t = 0; t < N_WORKERS; t++) {
        args[t].tid = t;
        args[t].collide_mode = 0;
        args[t].ft = NULL;
        pthread_create(&th[t], NULL, worker, &args[t]);
    }
    for (int t = 0; t < N_WORKERS; t++)
        pthread_join(th[t], NULL);

    atomic_store(&g_stop, 1);
    pthread_join(gcth, NULL);

    printf("--- phase1 shared-table (hazard) ---\n");
    printf("assemblies_ok:   %llu\n", (unsigned long long)atomic_load(&g_ok));
    printf("pending/lost:    %llu\n", (unsigned long long)atomic_load(&g_pending));
    printf("corrupt_joins:   %llu\n", (unsigned long long)atomic_load(&g_corrupt));
    printf("split_fail:      %llu\n", (unsigned long long)atomic_load(&g_split_fail));
    printf("dec_fail:        %llu\n", (unsigned long long)atomic_load(&g_dec_fail));
    printf("gc_ticks:        %llu\n", (unsigned long long)atomic_load(&g_gc_ticks));
    int phase1_corrupt = (int)atomic_load(&g_corrupt);
    if (phase1_corrupt)
        printf("DIAG: shared multi-writer corrupt=%d (expected hazard)\n", phase1_corrupt);

    /* Phase 2: deliberate slot collision — feed two assemblies that share idx
     * by manually constructing with known pkt_ids that collide. We cannot set
     * frag_next_pkt_id, so instead: leave half of assembly A in table, then
     * force many new packs until one reuses same slot before A completes.
     * Here: open-frag half then flood. */
    {
        uint8_t orig[2048], work[2048], f1[2048], h0[2048], h1[2048], out[2048];
        uint32_t f0len, f1len, olen;
        uint16_t pid0, pid1;
        uint8_t fx0, fx1;
        int nd0, nd1, slot_hits = 0, coll_corrupt = 0;
        size_t plen = fill_udp(orig, PAYLOAD, 42);
        struct frag_table *ft2 = calloc(1, sizeof(*ft2));
        if (!ft2)
            return 1;
        frag_table_init(ft2);

        packet_crypto_set_policy_id(1);
        packet_crypto_set_encrypt_layer(4);
        memcpy(work, orig, plen);
        if (frag_split_and_encrypt_l4(&g_ctx[0], work, (uint32_t)plen, sizeof(work), &f0len,
                                      f1, sizeof(f1), &f1len) != 0) {
            fprintf(stderr, "phase2 split fail\n");
            free(ft2);
            free(g_ft);
            return 1;
        }
        memcpy(h0, work, f0len);
        memcpy(h1, f1, f1len);
        nd0 = crypto_layer4_decrypt_fragment(&g_ctx[0], h0, f0len, &pid0, &fx0);
        nd1 = crypto_layer4_decrypt_fragment(&g_ctx[0], h1, f1len, &pid1, &fx1);
        /* Store only first half of A */
        (void)frag_try_reassemble_l4(ft2, h0, (uint32_t)nd0, pid0, fx0, out, &olen);

        for (int i = 0; i < 2000; i++) {
            uint8_t o2[2048], w2[2048], f2[2048], d0[2048], d1b[2048], jo[2048];
            uint32_t a0, a1, jo_len = 0;
            uint16_t p0, p1;
            uint8_t x0, x1;
            size_t pl = fill_udp(o2, PAYLOAD, (unsigned)(1000 + i));
            memcpy(w2, o2, pl);
            if (frag_split_and_encrypt_l4(&g_ctx[0], w2, (uint32_t)pl, sizeof(w2), &a0, f2,
                                          sizeof(f2), &a1) != 0)
                continue;
            memcpy(d0, w2, a0);
            memcpy(d1b, f2, a1);
            if (crypto_layer4_decrypt_fragment(&g_ctx[0], d0, a0, &p0, &x0) < 0)
                continue;
            if (crypto_layer4_decrypt_fragment(&g_ctx[0], d1b, a1, &p1, &x1) < 0)
                continue;
            if ((p0 % FRAG_TABLE_SIZE) == (pid0 % FRAG_TABLE_SIZE) && p0 != pid0)
                slot_hits++;
            /* Complete B fully on same table — may overwrite A's half */
            (void)frag_try_reassemble_l4(ft2, d0, a0, p0, x0, jo, &jo_len);
            (void)frag_try_reassemble_l4(ft2, d1b, a1, p1, x1, jo, &jo_len);
        }

        /* Try complete A with leftover half — expect pending/fail or corrupt, not silent wrong match */
        {
            uint8_t ja[2048];
            uint32_t jal = 0;
            int rr = frag_try_reassemble_l4(ft2, h1, (uint32_t)nd1, pid1, fx1, ja, &jal);
            if (rr == 1 && (jal != (uint32_t)plen || memcmp(ja, orig, plen) != 0)) {
                coll_corrupt++;
                fprintf(stderr,
                        "SLOT COLLISION CORRUPT: pkt_id=%u joined wrong olen=%u\n",
                        pid0, jal);
            }
            printf("--- phase2 slot collision ---\n");
            printf("same-slot foreign pkts seen: %d\n", slot_hits);
            printf("corrupt after overwrite:     %d\n", coll_corrupt);
            if (coll_corrupt)
                rc = 1;
        }
        free(ft2);
    }

    printf("--- summary ---\n");
    free(g_ft);
    g_ft = NULL;

    /* Phase 3: per-worker tables — production fix model must be clean */
    {
        struct frag_table *fts[N_WORKERS];
        unsigned long long ok3, cor3;

        atomic_store(&g_ok, 0);
        atomic_store(&g_pending, 0);
        atomic_store(&g_corrupt, 0);
        atomic_store(&g_split_fail, 0);
        atomic_store(&g_dec_fail, 0);
        atomic_store(&g_stop, 0);
        packet_crypto_reset_counter();

        for (int t = 0; t < N_WORKERS; t++) {
            fts[t] = calloc(1, sizeof(*fts[t]));
            if (!fts[t])
                return 1;
            frag_table_init(fts[t]);
        }

        printf("--- phase3 per-worker tables (production fix) ---\n");
        for (int t = 0; t < N_WORKERS; t++) {
            args[t].tid = t;
            args[t].collide_mode = 0;
            args[t].ft = fts[t];
            pthread_create(&th[t], NULL, worker, &args[t]);
        }
        for (int t = 0; t < N_WORKERS; t++)
            pthread_join(th[t], NULL);

        ok3 = atomic_load(&g_ok);
        cor3 = atomic_load(&g_corrupt);
        printf("assemblies_ok:   %llu\n", ok3);
        printf("pending/lost:    %llu\n", (unsigned long long)atomic_load(&g_pending));
        printf("corrupt_joins:   %llu (must 0)\n", cor3);

        for (int t = 0; t < N_WORKERS; t++)
            free(fts[t]);

        if (cor3 != 0 || ok3 == 0) {
            printf("FAIL: per-worker model still corrupt/empty\n");
            rc = 1;
        } else if (rc) {
            /* phase2 slot collision corrupt */
            printf("FAIL: phase2 slot collision corrupt\n");
        } else {
            printf("PASS: phase1 documented shared-table hazard (corrupt=%d); "
                   "phase3 per-worker clean (ok=%llu)\n",
                   phase1_corrupt, ok3);
            printf("production: profile_frag_l4 is per-worker like L2/L3\n");
            rc = 0;
        }
    }

    return rc;
}
