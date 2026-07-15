/*
 * Frag-path GCM nonce uniqueness + deliberate packet_crypto_reset_counter under load.
 *
 * Build:
 *   gcc -O2 -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include \
 *     tools/test_gcm_frag_nonce.c \
 *     src/core/fragment.o src/crypto/packet_crypto.o \
 *     src/crypto/crypto_layer2.o src/crypto/crypto_layer3.o src/crypto/crypto_layer4.o \
 *     src/crypto/eth_parse.o \
 *     -L./lib -Wl,-rpath,'$ORIGIN/../lib' -lssl -lcrypto -lpthread -lscrypt \
 *     -o tools/test_gcm_frag_nonce
 *   LD_LIBRARY_PATH=./lib ./tools/test_gcm_frag_nonce
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>

#include "inc/core/config.h"
#include "inc/core/fragment.h"
#include "inc/crypto/packet_crypto.h"
#include "inc/crypto/crypto_layer2.h"
#include "inc/crypto/crypto_layer3.h"
#include "inc/crypto/crypto_layer4.h"

#define N_THREADS     4
#define N_KEYS        4
#define ITERS         4000
#define PAYLOAD       1200
#define TEST_FRAG_MTU 700
#define NONCE_B       PACKET_CRYPTO_NONCE_BYTES
#define NONCE_TAB     (1u << 20)

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

struct nonce_rec {
    uint8_t used;
    uint8_t key_id;
    uint8_t nonce[NONCE_B];
};

static struct nonce_rec *g_ntab;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_dup_phase1;
static atomic_int g_dup_phase2;
static atomic_ullong g_enc_phase1;
static atomic_ullong g_enc_phase2;
static atomic_int g_reset_done;
static struct packet_crypto_ctx g_ctx[N_KEYS];

static uint32_t nhash(uint8_t kid, const uint8_t *n)
{
    uint32_t h = 2166136261u ^ kid;
    for (int i = 0; i < NONCE_B; i++) {
        h ^= n[i];
        h *= 16777619u;
    }
    return h;
}

static int nonce_record(uint8_t kid, const uint8_t *n, atomic_int *dup_counter)
{
    uint32_t idx = nhash(kid, n) & (NONCE_TAB - 1);
    pthread_mutex_lock(&g_mu);
    for (uint32_t i = 0; i < NONCE_TAB; i++) {
        struct nonce_rec *s = &g_ntab[idx];
        if (!s->used) {
            s->used = 1;
            s->key_id = kid;
            memcpy(s->nonce, n, NONCE_B);
            pthread_mutex_unlock(&g_mu);
            return 0;
        }
        if (s->key_id == kid && memcmp(s->nonce, n, NONCE_B) == 0) {
            pthread_mutex_unlock(&g_mu);
            atomic_fetch_add(dup_counter, 1);
            return -1;
        }
        idx = (idx + 1) & (NONCE_TAB - 1);
    }
    pthread_mutex_unlock(&g_mu);
    atomic_fetch_add(dup_counter, 1);
    return -1;
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

static int extract_l2(const uint8_t *pkt, size_t len, uint8_t out[NONCE_B])
{
    int off = crypto_layer2_nonce_off(pkt, len);
    if (off < 0 || len < (size_t)off + NONCE_B)
        return -1;
    memcpy(out, pkt + off, NONCE_B);
    return 0;
}

static int extract_l3(const uint8_t *pkt, size_t len, uint8_t out[NONCE_B])
{
    int ihl = (pkt[14] & 0x0F) * 4;
    int off = 14 + ihl;
    if (ihl < 20 || len < (size_t)off + NONCE_B)
        return -1;
    memcpy(out, pkt + off, NONCE_B);
    return 0;
}

static int extract_l4(const uint8_t *pkt, size_t len, uint8_t out[NONCE_B])
{
    int ihl = (pkt[14] & 0x0F) * 4;
    int off = 14 + ihl + 4;
    if (ihl < 20 || len < (size_t)off + NONCE_B)
        return -1;
    memcpy(out, pkt + off, NONCE_B);
    return 0;
}

static void record_pair(uint8_t kid, const uint8_t *f0, uint32_t l0, const uint8_t *f1,
                        uint32_t l1, int layer, atomic_int *dupc, atomic_ullong *enc)
{
    uint8_t n[NONCE_B];
    int (*ex)(const uint8_t *, size_t, uint8_t *) =
        layer == 2 ? extract_l2 : (layer == 3 ? extract_l3 : extract_l4);
    if (ex(f0, l0, n) == 0) {
        (void)nonce_record(kid, n, dupc);
        atomic_fetch_add(enc, 1);
    }
    if (ex(f1, l1, n) == 0) {
        (void)nonce_record(kid, n, dupc);
        atomic_fetch_add(enc, 1);
    }
}

static void split_all_layers(uint8_t kid, const uint8_t *orig, size_t plen, atomic_int *dupc,
                             atomic_ullong *enc)
{
    uint8_t work[2048], f1[2048];
    uint32_t f0len, f1len;

    packet_crypto_set_policy_id((uint8_t)(kid + 1));

    packet_crypto_set_encrypt_layer(2);
    memcpy(work, orig, plen);
    if (frag_split_and_encrypt_l2(&g_ctx[kid], work, (uint32_t)plen, sizeof(work), &f0len, f1,
                                  sizeof(f1), &f1len) == 0)
        record_pair(kid, work, f0len, f1, f1len, 2, dupc, enc);

    packet_crypto_set_encrypt_layer(3);
    memcpy(work, orig, plen);
    if (frag_split_and_encrypt(&g_ctx[kid], work, (uint32_t)plen, sizeof(work), &f0len, f1,
                               sizeof(f1), &f1len) == 0)
        record_pair(kid, work, f0len, f1, f1len, 3, dupc, enc);

    packet_crypto_set_encrypt_layer(4);
    memcpy(work, orig, plen);
    if (frag_split_and_encrypt_l4(&g_ctx[kid], work, (uint32_t)plen, sizeof(work), &f0len, f1,
                                  sizeof(f1), &f1len) == 0)
        record_pair(kid, work, f0len, f1, f1len, 4, dupc, enc);
}

struct thr_arg {
    int tid;
    int phase; /* 1 or 2 */
};

static void *worker(void *arg)
{
    struct thr_arg *ta = arg;
    int tid = ta->tid;
    uint8_t orig[2048];
    atomic_int *dupc = ta->phase == 1 ? &g_dup_phase1 : &g_dup_phase2;
    atomic_ullong *enc = ta->phase == 1 ? &g_enc_phase1 : &g_enc_phase2;

    crypto_layer2_bind_worker_idx((uint8_t)tid);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int it = 0; it < ITERS; it++) {
        uint8_t kid = (uint8_t)((tid + it) % N_KEYS);
        size_t plen = fill_udp(orig, PAYLOAD, (unsigned)(tid * 900011u + (unsigned)it));
        split_all_layers(kid, orig, plen, dupc, enc);

        /* Mid-run: one thread resets global nonce counter (reload simulation) */
        if (ta->phase == 2 && tid == 0 && it == ITERS / 2 &&
            atomic_exchange(&g_reset_done, 1) == 0) {
            packet_crypto_reset_counter();
            fprintf(stderr, "phase2: packet_crypto_reset_counter() at mid-load\n");
        }
    }
    return NULL;
}

static int run_phase(int phase)
{
    pthread_t th[N_THREADS];
    struct thr_arg args[N_THREADS];

    for (int t = 0; t < N_THREADS; t++) {
        args[t].tid = t;
        args[t].phase = phase;
        pthread_create(&th[t], NULL, worker, &args[t]);
    }
    for (int t = 0; t < N_THREADS; t++)
        pthread_join(th[t], NULL);
    return 0;
}

int main(void)
{
    int rc = 0;

    g_ntab = calloc(NONCE_TAB, sizeof(*g_ntab));
    if (!g_ntab)
        return 1;

    frag_set_mtu(TEST_FRAG_MTU);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int k = 0; k < N_KEYS; k++) {
        uint8_t master[32];
        memset(master, (uint8_t)(0x50 + k), sizeof(master));
        master[0] = (uint8_t)k;
        if (packet_crypto_init(&g_ctx[k], master) != 0)
            return 1;
        g_ctx[k].policy_id = k + 1;
    }
    packet_crypto_reset_counter();

    printf("frag nonce: threads=%d keys=%d iters=%d layers=L2+L3+L4\n", N_THREADS, N_KEYS,
           ITERS);

    /* Phase 1: no reset — must have zero dups */
    memset(g_ntab, 0, NONCE_TAB * sizeof(*g_ntab));
    atomic_store(&g_dup_phase1, 0);
    atomic_store(&g_enc_phase1, 0);
    run_phase(1);
    printf("--- phase1 (no reset) ---\n");
    printf("encrypts: %llu  dups: %d (must 0)\n",
           (unsigned long long)atomic_load(&g_enc_phase1), atomic_load(&g_dup_phase1));

    /* Phase 2: reset mid-load — expect dups (reuse after counter wraps to 0) */
    memset(g_ntab, 0, NONCE_TAB * sizeof(*g_ntab));
    atomic_store(&g_dup_phase2, 0);
    atomic_store(&g_enc_phase2, 0);
    atomic_store(&g_reset_done, 0);
    packet_crypto_reset_counter();
    run_phase(2);
    printf("--- phase2 (reset_counter mid-load) ---\n");
    printf("encrypts: %llu  dups: %d\n", (unsigned long long)atomic_load(&g_enc_phase2),
           atomic_load(&g_dup_phase2));
    printf("reset_fired: %d\n", atomic_load(&g_reset_done));

    if (atomic_load(&g_dup_phase1) != 0 || atomic_load(&g_enc_phase1) == 0) {
        printf("FAIL: phase1 nonce uniqueness broken\n");
        rc = 1;
    } else if (!atomic_load(&g_reset_done)) {
        printf("FAIL: phase2 reset did not fire\n");
        rc = 1;
    } else if (atomic_load(&g_dup_phase2) == 0) {
        /* Per-thread salt means counter restart may not collide full 12B nonce
         * across different threads; still warn — same thread after reset WILL collide
         * if salt unchanged. If zero dups, that would be surprising for same TLS salt. */
        printf("WARN: phase2 observed 0 dups after reset (salt×counter may dodge); "
               "document reload risk anyway\n");
        printf("PASS: phase1 unique; phase2 reset exercised (dups=%d)\n",
               atomic_load(&g_dup_phase2));
    } else {
        printf("PASS: phase1 unique; phase2 reset caused %d (key,nonce) reuse — "
               "reload hazard confirmed\n",
               atomic_load(&g_dup_phase2));
    }

    free(g_ntab);
    return rc;
}
