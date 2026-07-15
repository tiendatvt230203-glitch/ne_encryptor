/*
 * Concurrent AES-GCM stress: multi-thread × multi-key × L2/L3/L4.
 *
 * Build (from repo root, after make):
 *   gcc -O2 -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include \
 *     tools/test_gcm_concurrency.c \
 *     src/crypto/packet_crypto.o src/crypto/crypto_layer2.o src/crypto/crypto_layer3.o \
 *     src/crypto/crypto_layer4.o src/crypto/eth_parse.o \
 *     -L./lib -Wl,-rpath,'$ORIGIN/../lib' -lssl -lcrypto -lpthread -lscrypt \
 *     -o tools/test_gcm_concurrency
 *   ./tools/test_gcm_concurrency
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>

#include "inc/core/config.h"
#include "inc/crypto/packet_crypto.h"
#include "inc/crypto/crypto_layer2.h"
#include "inc/crypto/crypto_layer3.h"
#include "inc/crypto/crypto_layer4.h"

#define N_THREADS   8
#define N_KEYS      8
#define ITERS       80000
#define PAYLOAD_PAD 900
#define NONCE_BYTES PACKET_CRYPTO_NONCE_BYTES
/* Open-address table: ~2× expected (key,nonce) inserts (L2/L3/L4 + neg). */
#define NONCE_TAB_SIZE (1u << 23) /* 8M slots */

int sig_pqc_diversify_key(int profile_id, int policy_id, uint8_t *out_policy_key)
{
    (void)profile_id;
    (void)policy_id;
    if (out_policy_key)
        memset(out_policy_key, 0xA5, 32);
    return 0;
}
int trf_pqc_generate_nonce(uint8_t *nonce)
{
    (void)nonce;
    return -1;
}
int trf_encrypt_payload_gcm(void *ctx, const uint8_t *key, const uint8_t *nonce, int nonce_len,
                            uint8_t *data, int len, int *out_len)
{
    (void)ctx; (void)key; (void)nonce; (void)nonce_len; (void)data; (void)len; (void)out_len;
    return -1;
}
int trf_decrypt_payload_gcm(void *ctx, const uint8_t *key, const uint8_t *nonce, int nonce_len,
                            uint8_t *data, int len, int *out_len)
{
    (void)ctx; (void)key; (void)nonce; (void)nonce_len; (void)data; (void)len; (void)out_len;
    return -1;
}

/* --- nonce set: key_id + 12-byte nonce (open addressing) --- */
struct nonce_rec {
    uint8_t used;
    uint8_t key_id;
    uint8_t nonce[NONCE_BYTES];
};

static struct nonce_rec *g_nonce_tab;
static size_t g_nonce_count;
static size_t g_same_nonce_diff_key; /* informational */
static pthread_mutex_t g_nonce_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_dup_fail;
static atomic_int g_rt_fail;
static atomic_int g_wrong_key_ok;   /* expected fails that succeeded as fail */
static atomic_int g_wrong_key_bad;  /* expected fail but decrypt succeeded */
static atomic_int g_flip_ok;
static atomic_int g_flip_bad;
static atomic_ullong g_encrypts;

static struct packet_crypto_ctx g_ctx[N_KEYS];

static uint32_t nonce_hash(uint8_t key_id, const uint8_t nonce[NONCE_BYTES])
{
    uint32_t h = 2166136261u ^ key_id;
    for (int i = 0; i < NONCE_BYTES; i++) {
        h ^= nonce[i];
        h *= 16777619u;
    }
    return h;
}

static uint16_t ip_cksum(const uint8_t *ip, int len)
{
    return crypto_calc_ip_checksum(ip, len);
}

static size_t fill_udp(uint8_t *pkt, size_t pad, unsigned seed)
{
    size_t ip_tot = 20 + 8 + pad;
    size_t eth_len = 14 + ip_tot;
    memset(pkt, 0, eth_len);
    memset(pkt + 0, 0x02, 6);
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
    ip[17] = 0;
    ip[18] = 0;
    ip[19] = 2;
    uint16_t c = ip_cksum(ip, 20);
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

static int extract_nonce_l2(const uint8_t *pkt, size_t len, uint8_t out[NONCE_BYTES])
{
    int off = crypto_layer2_nonce_off(pkt, len);
    if (off < 0 || len < (size_t)off + NONCE_BYTES)
        return -1;
    memcpy(out, pkt + off, NONCE_BYTES);
    return 0;
}

static int extract_nonce_l3(const uint8_t *pkt, size_t len, uint8_t out[NONCE_BYTES])
{
    if (len < 14 + 20)
        return -1;
    int ihl = (pkt[14] & 0x0F) * 4;
    int off = 14 + ihl;
    if (ihl < 20 || len < (size_t)off + NONCE_BYTES)
        return -1;
    memcpy(out, pkt + off, NONCE_BYTES);
    return 0;
}

static int extract_nonce_l4(const uint8_t *pkt, size_t len, uint8_t out[NONCE_BYTES])
{
    if (len < 14 + 20 + 4 + NONCE_BYTES)
        return -1;
    int ihl = (pkt[14] & 0x0F) * 4;
    int off = 14 + ihl + 4; /* after clear ports */
    if (ihl < 20 || len < (size_t)off + NONCE_BYTES)
        return -1;
    memcpy(out, pkt + off, NONCE_BYTES);
    return 0;
}

static int nonce_record(uint8_t key_id, const uint8_t nonce[NONCE_BYTES])
{
    uint32_t h = nonce_hash(key_id, nonce);
    uint32_t mask = NONCE_TAB_SIZE - 1;
    uint32_t idx = h & mask;

    pthread_mutex_lock(&g_nonce_mu);
    for (uint32_t n = 0; n < NONCE_TAB_SIZE; n++) {
        struct nonce_rec *slot = &g_nonce_tab[idx];
        if (!slot->used) {
            slot->used = 1;
            slot->key_id = key_id;
            memcpy(slot->nonce, nonce, NONCE_BYTES);
            g_nonce_count++;
            pthread_mutex_unlock(&g_nonce_mu);
            return 0;
        }
        if (slot->key_id == key_id &&
            memcmp(slot->nonce, nonce, NONCE_BYTES) == 0) {
            pthread_mutex_unlock(&g_nonce_mu);
            atomic_fetch_add(&g_dup_fail, 1);
            return -1;
        }
        if (memcmp(slot->nonce, nonce, NONCE_BYTES) == 0)
            g_same_nonce_diff_key++;
        idx = (idx + 1) & mask;
    }
    pthread_mutex_unlock(&g_nonce_mu);
    fprintf(stderr, "nonce table full\n");
    atomic_fetch_add(&g_dup_fail, 1);
    return -1;
}

typedef int (*enc_fn)(struct packet_crypto_ctx *, uint8_t *, size_t);
typedef int (*dec_fn)(struct packet_crypto_ctx *, uint8_t *, size_t);
typedef int (*nonce_fn)(const uint8_t *, size_t, uint8_t *);

static int roundtrip_layer(struct packet_crypto_ctx *ctx, uint8_t key_id,
                           const uint8_t *orig, size_t pkt_len,
                           enc_fn enc, dec_fn dec, nonce_fn get_nonce,
                           int do_neg)
{
    uint8_t work[2048];
    uint8_t nonce[NONCE_BYTES];
    int elen, dlen;

    memcpy(work, orig, pkt_len);
    elen = enc(ctx, work, pkt_len);
    /* GCM layers always grow (tunnel/tag); elen==pkt_len means passthrough skip. */
    if (elen < 0 || elen <= (int)pkt_len || (size_t)elen > sizeof(work)) {
        atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }
    atomic_fetch_add(&g_encrypts, 1);

    if (get_nonce(work, (size_t)elen, nonce) != 0) {
        atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }
    if (nonce_record(key_id, nonce) != 0)
        return -1;

    dlen = dec(ctx, work, (size_t)elen);
    if (dlen != (int)pkt_len || memcmp(work, orig, pkt_len) != 0) {
        atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }

    if (!do_neg)
        return 0;

    /* Wrong key: encrypt with ctx, decrypt with another key */
    {
        uint8_t encbuf[2048];
        int e2, d2;
        uint8_t kid2 = (uint8_t)((key_id + 1) % N_KEYS);

        memcpy(encbuf, orig, pkt_len);
        e2 = enc(ctx, encbuf, pkt_len);
        if (e2 <= (int)pkt_len) {
            atomic_fetch_add(&g_rt_fail, 1);
            return -1;
        }
        atomic_fetch_add(&g_encrypts, 1);
        if (get_nonce(encbuf, (size_t)e2, nonce) == 0)
            (void)nonce_record(key_id, nonce);

        d2 = dec(&g_ctx[kid2], encbuf, (size_t)e2);
        if (d2 >= 0 && d2 == (int)pkt_len && memcmp(encbuf, orig, pkt_len) == 0)
            atomic_fetch_add(&g_wrong_key_bad, 1);
        else
            atomic_fetch_add(&g_wrong_key_ok, 1);
    }

    /* Bit-flip ciphertext then decrypt with correct key */
    {
        uint8_t encbuf[2048];
        int e2, d2;

        memcpy(encbuf, orig, pkt_len);
        e2 = enc(ctx, encbuf, pkt_len);
        if (e2 <= (int)pkt_len || e2 < 40) {
            atomic_fetch_add(&g_rt_fail, 1);
            return -1;
        }
        atomic_fetch_add(&g_encrypts, 1);
        if (get_nonce(encbuf, (size_t)e2, nonce) == 0)
            (void)nonce_record(key_id, nonce);

        encbuf[e2 / 2] ^= 0x01;
        d2 = dec(ctx, encbuf, (size_t)e2);
        if (d2 >= 0 && d2 == (int)pkt_len && memcmp(encbuf, orig, pkt_len) == 0)
            atomic_fetch_add(&g_flip_bad, 1);
        else
            atomic_fetch_add(&g_flip_ok, 1);
    }
    return 0;
}

struct thr_arg {
    int tid;
};

static void *worker_main(void *arg)
{
    struct thr_arg *ta = arg;
    int tid = ta->tid;
    uint8_t orig[2048];
    size_t pkt_len;

    crypto_layer2_bind_worker_idx((uint8_t)tid);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int it = 0; it < ITERS; it++) {
        uint8_t key_id = (uint8_t)((tid + it) % N_KEYS);
        struct packet_crypto_ctx *ctx = &g_ctx[key_id];
        int do_neg = ((it % 64) == 0);

        packet_crypto_set_policy_id((uint8_t)(key_id + 1));
        pkt_len = fill_udp(orig, PAYLOAD_PAD, (unsigned)(tid * 1000003u + (unsigned)it));

        packet_crypto_set_encrypt_layer(2);
        if (roundtrip_layer(ctx, key_id, orig, pkt_len,
                            crypto_layer2_encrypt, crypto_layer2_decrypt,
                            extract_nonce_l2, do_neg) != 0)
            continue;

        packet_crypto_set_encrypt_layer(3);
        if (roundtrip_layer(ctx, key_id, orig, pkt_len,
                            crypto_layer3_encrypt, crypto_layer3_decrypt,
                            extract_nonce_l3, do_neg) != 0)
            continue;

        packet_crypto_set_encrypt_layer(4);
        (void)roundtrip_layer(ctx, key_id, orig, pkt_len,
                              crypto_layer4_encrypt, crypto_layer4_decrypt,
                              extract_nonce_l4, do_neg);
    }
    return NULL;
}

int main(void)
{
    pthread_t th[N_THREADS];
    struct thr_arg args[N_THREADS];
    int rc = 0;

    g_nonce_tab = calloc(NONCE_TAB_SIZE, sizeof(*g_nonce_tab));
    if (!g_nonce_tab) {
        fprintf(stderr, "oom nonce table\n");
        return 1;
    }

    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int k = 0; k < N_KEYS; k++) {
        uint8_t master[32];
        memset(master, (uint8_t)(0x10 + k), sizeof(master));
        master[0] = (uint8_t)k;
        master[31] = (uint8_t)(0xA0 + k);
        if (packet_crypto_init(&g_ctx[k], master) != 0) {
            fprintf(stderr, "init key %d failed\n", k);
            return 1;
        }
        g_ctx[k].policy_id = k + 1;
    }
    /* Counter was reset by each init; start clean after all keys ready. */
    packet_crypto_reset_counter();

    printf("GCM concurrency: threads=%d keys=%d iters/thread=%d layers=L2+L3+L4\n",
           N_THREADS, N_KEYS, ITERS);

    for (int t = 0; t < N_THREADS; t++) {
        args[t].tid = t;
        if (pthread_create(&th[t], NULL, worker_main, &args[t]) != 0) {
            fprintf(stderr, "pthread_create %d failed\n", t);
            return 1;
        }
    }
    for (int t = 0; t < N_THREADS; t++)
        pthread_join(th[t], NULL);

    printf("--- results ---\n");
    printf("encrypts:          %llu\n", (unsigned long long)atomic_load(&g_encrypts));
    printf("unique (key,nonce):%zu\n", g_nonce_count);
    printf("same nonce≠key:    %zu (OK)\n", g_same_nonce_diff_key);
    printf("dup (key,nonce):   %d  (must be 0)\n", atomic_load(&g_dup_fail));
    printf("roundtrip fails:   %d  (must be 0)\n", atomic_load(&g_rt_fail));
    printf("wrong-key rejects: %d\n", atomic_load(&g_wrong_key_ok));
    printf("wrong-key leaks:   %d  (must be 0)\n", atomic_load(&g_wrong_key_bad));
    printf("bitflip rejects:   %d\n", atomic_load(&g_flip_ok));
    printf("bitflip leaks:     %d  (must be 0)\n", atomic_load(&g_flip_bad));
    printf("note: L4 frag shared-table race not covered (non-GCM issue)\n");

    if (atomic_load(&g_dup_fail) || atomic_load(&g_rt_fail) ||
        atomic_load(&g_wrong_key_bad) || atomic_load(&g_flip_bad) ||
        atomic_load(&g_wrong_key_ok) == 0 || atomic_load(&g_flip_ok) == 0) {
        printf("FAIL\n");
        rc = 1;
    } else {
        printf("PASS: concurrent multi-key GCM L2/L3/L4 OK\n");
        rc = 0;
    }

    free(g_nonce_tab);
    return rc;
}
