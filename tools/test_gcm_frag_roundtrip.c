/*
 * Full-path GCM: split-encrypt → decrypt_fragment → reassemble (L2/L3/L4).
 *
 * Build (repo root, after make objs):
 *   gcc -O2 -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include \
 *     tools/test_gcm_frag_roundtrip.c \
 *     src/core/fragment.o src/crypto/packet_crypto.o \
 *     src/crypto/crypto_layer2.o src/crypto/crypto_layer3.o src/crypto/crypto_layer4.o \
 *     src/crypto/eth_parse.o \
 *     -L./lib -Wl,-rpath,'$ORIGIN/../lib' -lssl -lcrypto -lpthread -lscrypt \
 *     -o tools/test_gcm_frag_roundtrip
 *   LD_LIBRARY_PATH=./lib ./tools/test_gcm_frag_roundtrip
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

#define N_THREADS  4
#define N_KEYS     4
#define ITERS      2000
#define PAYLOAD    1200
#define TEST_FRAG_MTU 700
#define NONCE_B    PACKET_CRYPTO_NONCE_BYTES
#define NONCE_TAB  (1u << 20)

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
static pthread_mutex_t g_nmu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_dup;
static atomic_int g_rt_fail;
static atomic_int g_neg_ok;
static atomic_int g_neg_bad;
static atomic_ullong g_joins;
static atomic_ullong g_splits;

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

static int nonce_record(uint8_t kid, const uint8_t *n)
{
    uint32_t idx = nhash(kid, n) & (NONCE_TAB - 1);
    pthread_mutex_lock(&g_nmu);
    for (uint32_t i = 0; i < NONCE_TAB; i++) {
        struct nonce_rec *s = &g_ntab[idx];
        if (!s->used) {
            s->used = 1;
            s->key_id = kid;
            memcpy(s->nonce, n, NONCE_B);
            pthread_mutex_unlock(&g_nmu);
            return 0;
        }
        if (s->key_id == kid && memcmp(s->nonce, n, NONCE_B) == 0) {
            pthread_mutex_unlock(&g_nmu);
            atomic_fetch_add(&g_dup, 1);
            return -1;
        }
        idx = (idx + 1) & (NONCE_TAB - 1);
    }
    pthread_mutex_unlock(&g_nmu);
    atomic_fetch_add(&g_dup, 1);
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

static int extract_nonce_l2(const uint8_t *pkt, size_t len, uint8_t out[NONCE_B])
{
    int off = crypto_layer2_nonce_off(pkt, len);
    if (off < 0 || len < (size_t)off + NONCE_B)
        return -1;
    memcpy(out, pkt + off, NONCE_B);
    return 0;
}

static int extract_nonce_l3(const uint8_t *pkt, size_t len, uint8_t out[NONCE_B])
{
    if (len < 14 + 20 + NONCE_B)
        return -1;
    int ihl = (pkt[14] & 0x0F) * 4;
    int off = 14 + ihl;
    if (ihl < 20 || len < (size_t)off + NONCE_B)
        return -1;
    memcpy(out, pkt + off, NONCE_B);
    return 0;
}

static int extract_nonce_l4(const uint8_t *pkt, size_t len, uint8_t out[NONCE_B])
{
    if (len < 14 + 20 + 4 + NONCE_B)
        return -1;
    int ihl = (pkt[14] & 0x0F) * 4;
    int off = 14 + ihl + 4;
    if (ihl < 20 || len < (size_t)off + NONCE_B)
        return -1;
    memcpy(out, pkt + off, NONCE_B);
    return 0;
}

typedef int (*split_fn)(struct packet_crypto_ctx *, uint8_t *, uint32_t, size_t, uint32_t *,
                        uint8_t *, size_t, uint32_t *);
typedef int (*dec_frag_fn)(struct packet_crypto_ctx *, uint8_t *, size_t, uint16_t *, uint8_t *);
typedef int (*reasm_fn)(struct frag_table *, const uint8_t *, uint32_t, uint16_t, uint8_t,
                        uint8_t *, uint32_t *);
typedef int (*nonce_fn)(const uint8_t *, size_t, uint8_t *);

static int feed_half(struct frag_table *ft, reasm_fn reasm, uint8_t *half, int nd,
                     uint16_t pid, uint8_t fidx, uint8_t *out, uint32_t *olen)
{
    int rr = reasm(ft, half, (uint32_t)nd, pid, fidx, out, olen);
    return rr;
}

static int roundtrip_one(struct packet_crypto_ctx *ctx, uint8_t kid,
                         struct frag_table *ft, const uint8_t *orig, size_t plen,
                         split_fn split, dec_frag_fn decf, reasm_fn reasm, nonce_fn getn,
                         int order_rev, int do_neg)
{
    uint8_t work[2048], f1[2048], h0[2048], h1[2048], out[2048];
    uint8_t nonce[NONCE_B];
    uint32_t f0len = 0, f1len = 0, olen = 0;
    uint16_t pid0 = 0, pid1 = 0;
    uint8_t fx0 = 0, fx1 = 0;
    int nd0, nd1, rr;

    memcpy(work, orig, plen);
    if (split(ctx, work, (uint32_t)plen, sizeof(work), &f0len, f1, sizeof(f1), &f1len) != 0) {
        atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }
    if (f0len == 0 || f1len == 0 || f0len > sizeof(work) || f1len > sizeof(f1)) {
        atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }
    atomic_fetch_add(&g_splits, 1);

    if (getn(work, f0len, nonce) == 0)
        (void)nonce_record(kid, nonce);
    if (getn(f1, f1len, nonce) == 0)
        (void)nonce_record(kid, nonce);

    memcpy(h0, work, f0len);
    memcpy(h1, f1, f1len);

    nd0 = decf(ctx, h0, f0len, &pid0, &fx0);
    nd1 = decf(ctx, h1, f1len, &pid1, &fx1);
    if (nd0 < 0 || nd1 < 0 || pid0 != pid1) {
        atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }

    frag_table_init(ft);
    if (!order_rev) {
        rr = feed_half(ft, reasm, h0, nd0, pid0, fx0, out, &olen);
        if (rr != 0) {
            atomic_fetch_add(&g_rt_fail, 1);
            return -1;
        }
        rr = feed_half(ft, reasm, h1, nd1, pid1, fx1, out, &olen);
    } else {
        rr = feed_half(ft, reasm, h1, nd1, pid1, fx1, out, &olen);
        if (rr != 0) {
            atomic_fetch_add(&g_rt_fail, 1);
            return -1;
        }
        rr = feed_half(ft, reasm, h0, nd0, pid0, fx0, out, &olen);
    }
    if (rr != 1 || olen != (uint32_t)plen || memcmp(out, orig, plen) != 0) {
        atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }
    atomic_fetch_add(&g_joins, 1);

    if (!do_neg)
        return 0;

    /* Wrong key on one half */
    {
        uint8_t w0[2048], w1[2048];
        uint16_t p;
        uint8_t f;
        uint8_t kid2 = (uint8_t)((kid + 1) % N_KEYS);
        memcpy(w0, work, f0len);
        memcpy(w1, f1, f1len);
        if (decf(&g_ctx[kid2], w0, f0len, &p, &f) >= 0 &&
            decf(&g_ctx[kid2], w1, f1len, &p, &f) >= 0)
            atomic_fetch_add(&g_neg_bad, 1);
        else
            atomic_fetch_add(&g_neg_ok, 1);
    }
    /* Bit-flip ciphertext mid-frame */
    {
        uint8_t w0[2048];
        uint16_t p;
        uint8_t f;
        memcpy(w0, work, f0len);
        w0[f0len / 2] ^= 0x01;
        if (decf(ctx, w0, f0len, &p, &f) >= 0)
            atomic_fetch_add(&g_neg_bad, 1);
        else
            atomic_fetch_add(&g_neg_ok, 1);
    }
    return 0;
}

struct thr_arg {
    int tid;
};

static void *worker(void *arg)
{
    struct thr_arg *ta = arg;
    int tid = ta->tid;
    struct frag_table *ft = calloc(1, sizeof(*ft));
    uint8_t orig[2048];
    size_t plen;

    if (!ft)
        return NULL;

    crypto_layer2_bind_worker_idx((uint8_t)tid);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int it = 0; it < ITERS; it++) {
        uint8_t kid = (uint8_t)((tid + it) % N_KEYS);
        int do_neg = ((it % 32) == 0);
        int rev = (it & 1);

        packet_crypto_set_policy_id((uint8_t)(kid + 1));
        plen = fill_udp(orig, PAYLOAD, (unsigned)(tid * 1000003u + (unsigned)it));

        if (!frag_need_split_l2((uint32_t)plen) || !frag_need_split((uint32_t)plen) ||
            !frag_need_split_l4((uint32_t)plen)) {
            atomic_fetch_add(&g_rt_fail, 1);
            continue;
        }

        packet_crypto_set_encrypt_layer(2);
        (void)roundtrip_one(&g_ctx[kid], kid, ft, orig, plen,
                            frag_split_and_encrypt_l2, crypto_layer2_decrypt_fragment,
                            frag_try_reassemble_l2, extract_nonce_l2, rev, do_neg);

        packet_crypto_set_encrypt_layer(3);
        (void)roundtrip_one(&g_ctx[kid], kid, ft, orig, plen,
                            frag_split_and_encrypt, crypto_layer3_decrypt_fragment,
                            frag_try_reassemble, extract_nonce_l3, rev, do_neg);

        packet_crypto_set_encrypt_layer(4);
        (void)roundtrip_one(&g_ctx[kid], kid, ft, orig, plen,
                            frag_split_and_encrypt_l4, crypto_layer4_decrypt_fragment,
                            frag_try_reassemble_l4, extract_nonce_l4, rev, do_neg);
    }

    free(ft);
    return NULL;
}

int main(void)
{
    pthread_t th[N_THREADS];
    struct thr_arg args[N_THREADS];
    int rc = 0;

    g_ntab = calloc(NONCE_TAB, sizeof(*g_ntab));
    if (!g_ntab) {
        fprintf(stderr, "oom nonce\n");
        return 1;
    }

    frag_set_mtu(TEST_FRAG_MTU);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int k = 0; k < N_KEYS; k++) {
        uint8_t master[32];
        memset(master, (uint8_t)(0x20 + k), sizeof(master));
        master[0] = (uint8_t)k;
        if (packet_crypto_init(&g_ctx[k], master) != 0) {
            fprintf(stderr, "init key %d failed\n", k);
            return 1;
        }
        g_ctx[k].policy_id = k + 1;
    }
    packet_crypto_reset_counter();

    printf("GCM frag roundtrip: threads=%d keys=%d iters=%d mtu=%d pad=%d\n",
           N_THREADS, N_KEYS, ITERS, TEST_FRAG_MTU, PAYLOAD);

    for (int t = 0; t < N_THREADS; t++) {
        args[t].tid = t;
        if (pthread_create(&th[t], NULL, worker, &args[t]) != 0)
            return 1;
    }
    for (int t = 0; t < N_THREADS; t++)
        pthread_join(th[t], NULL);

    printf("--- results ---\n");
    printf("splits:          %llu\n", (unsigned long long)atomic_load(&g_splits));
    printf("joins OK:        %llu\n", (unsigned long long)atomic_load(&g_joins));
    printf("roundtrip fails: %d (must 0)\n", atomic_load(&g_rt_fail));
    printf("nonce dups:      %d (must 0)\n", atomic_load(&g_dup));
    printf("neg rejects:     %d\n", atomic_load(&g_neg_ok));
    printf("neg leaks:       %d (must 0)\n", atomic_load(&g_neg_bad));

    if (atomic_load(&g_rt_fail) || atomic_load(&g_dup) || atomic_load(&g_neg_bad) ||
        atomic_load(&g_joins) == 0 || atomic_load(&g_neg_ok) == 0) {
        printf("FAIL\n");
        rc = 1;
    } else {
        printf("PASS: GCM frag L2/L3/L4 split→decrypt→reassemble OK\n");
    }

    free(g_ntab);
    return rc;
}
