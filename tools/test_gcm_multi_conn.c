/*
 * Multi-connection GCM-256 stress: N conns × N threads × L2/L3/L4 (+ frag sample).
 * Looks for nonce reuse, cross-talk, roundtrip fail, frag join corrupt.
 *
 * Build (repo root):
 *   make src/core/fragment.o src/crypto/packet_crypto.o \
 *        src/crypto/crypto_layer2.o src/crypto/crypto_layer3.o \
 *        src/crypto/crypto_layer4.o src/crypto/eth_parse.o
 *   gcc -O2 -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include \
 *     tools/test_gcm_multi_conn.c \
 *     src/core/fragment.o src/crypto/packet_crypto.o \
 *     src/crypto/crypto_layer2.o src/crypto/crypto_layer3.o src/crypto/crypto_layer4.o \
 *     src/crypto/eth_parse.o \
 *     -L./lib -Wl,-rpath,'$ORIGIN/../lib' -lssl -lcrypto -lpthread -lscrypt \
 *     -o tools/test_gcm_multi_conn
 *   LD_LIBRARY_PATH=./lib ./tools/test_gcm_multi_conn
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

#define N_THREADS   8
#define N_KEYS      8
#define N_CONNS     128
#define ITERS       4000 /* per thread; each iter hits 1 conn × L2+L3+L4 */
#define PAYLOAD     900
#define FRAG_PAD    1200
#define TEST_MTU    700
#define FRAG_EVERY  64 /* every Nth iter also stress frag path */
#define NEG_EVERY   64
#define NONCE_B     PACKET_CRYPTO_NONCE_BYTES
#define NONCE_TAB   (1u << 22)

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

struct conn_desc {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
    uint8_t key_id;
    uint16_t conn_id;
};

struct nonce_rec {
    uint8_t used;
    uint8_t key_id;
    uint8_t nonce[NONCE_B];
};

static struct conn_desc g_conns[N_CONNS];
static struct packet_crypto_ctx g_ctx[N_KEYS];
static struct nonce_rec *g_ntab;
static size_t g_nonce_count;
static pthread_mutex_t g_nmu = PTHREAD_MUTEX_INITIALIZER;

static atomic_int g_dup;
static atomic_int g_rt_fail;
static atomic_int g_xtalk_bad; /* wrong-key decrypt succeeded as match */
static atomic_int g_xtalk_ok;
static atomic_int g_flip_ok;
static atomic_int g_flip_bad;
static atomic_int g_frag_fail;
static atomic_int g_frag_corrupt;
static atomic_ullong g_ops;
static atomic_ullong g_frags;
static atomic_int g_dump_left = 6;

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
            g_nonce_count++;
            pthread_mutex_unlock(&g_nmu);
            return 0;
        }
        if (s->key_id == kid && memcmp(s->nonce, n, NONCE_B) == 0) {
            int left = atomic_fetch_sub(&g_dump_left, 1);
            if (left > 0) {
                fprintf(stderr, "DUP (key,nonce) kid=%u n=", kid);
                for (int j = 0; j < NONCE_B; j++)
                    fprintf(stderr, "%02x", n[j]);
                fprintf(stderr, "\n");
            }
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

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xff);
}

static size_t fill_conn_udp(uint8_t *pkt, size_t pad, const struct conn_desc *c, uint32_t seq)
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
    put_u16(ip + 2, (uint16_t)ip_tot);
    ip[8] = 64;
    ip[9] = 17;
    put_u32(ip + 12, c->src_ip);
    put_u32(ip + 16, c->dst_ip);
    uint16_t ck = crypto_calc_ip_checksum(ip, 20);
    put_u16(ip + 10, ck);
    uint8_t *u = ip + 20;
    put_u16(u + 0, c->sport);
    put_u16(u + 2, c->dport);
    put_u16(u + 4, (uint16_t)(8 + pad));
    /* payload: conn_id | seq | pattern */
    if (pad >= 8) {
        put_u16(u + 8, c->conn_id);
        put_u32(u + 10, seq);
        u[14] = c->key_id;
        u[15] = 0xA5;
        for (size_t i = 8; i < pad; i++)
            u[8 + i] = (uint8_t)((c->conn_id * 131u + seq + i) & 0xff);
    } else {
        for (size_t i = 0; i < pad; i++)
            u[8 + i] = (uint8_t)((c->conn_id + i) & 0xff);
    }
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
    if (len < 14 + 20 + NONCE_B)
        return -1;
    int ihl = (pkt[14] & 0x0F) * 4;
    int off = 14 + ihl;
    if (ihl < 20 || len < (size_t)off + NONCE_B)
        return -1;
    memcpy(out, pkt + off, NONCE_B);
    return 0;
}

static int extract_l4(const uint8_t *pkt, size_t len, uint8_t out[NONCE_B])
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

typedef int (*enc_fn)(struct packet_crypto_ctx *, uint8_t *, size_t);
typedef int (*dec_fn)(struct packet_crypto_ctx *, uint8_t *, size_t);
typedef int (*nonce_fn)(const uint8_t *, size_t, uint8_t *);

static int roundtrip_layer(const struct conn_desc *c, const uint8_t *orig, size_t plen,
                           enc_fn enc, dec_fn dec, nonce_fn getn, int layer, int do_neg)
{
    uint8_t work[2048], nonce[NONCE_B];
    int elen, dlen;
    uint8_t kid = c->key_id;

    memcpy(work, orig, plen);
    elen = enc(&g_ctx[kid], work, plen);
    if (elen <= (int)plen || (size_t)elen > sizeof(work)) {
        atomic_fetch_add(&g_rt_fail, 1);
        fprintf(stderr, "RT enc fail conn=%u L%d elen=%d plen=%zu\n", c->conn_id, layer, elen,
                plen);
        return -1;
    }
    atomic_fetch_add(&g_ops, 1);
    if (getn(work, (size_t)elen, nonce) != 0 || nonce_record(kid, nonce) != 0) {
        if (atomic_load(&g_dup) == 0)
            atomic_fetch_add(&g_rt_fail, 1);
        return -1;
    }
    dlen = dec(&g_ctx[kid], work, (size_t)elen);
    if (dlen != (int)plen || memcmp(work, orig, plen) != 0) {
        atomic_fetch_add(&g_rt_fail, 1);
        fprintf(stderr, "RT mismatch conn=%u L%d dlen=%d\n", c->conn_id, layer, dlen);
        return -1;
    }

    if (!do_neg)
        return 0;

    /* Cross-talk: decrypt with another connection's key */
    {
        uint8_t encbuf[2048];
        uint8_t kid2 = (uint8_t)((kid + 1) % N_KEYS);
        int e2, d2;
        memcpy(encbuf, orig, plen);
        e2 = enc(&g_ctx[kid], encbuf, plen);
        if (e2 <= (int)plen)
            return 0;
        atomic_fetch_add(&g_ops, 1);
        if (getn(encbuf, (size_t)e2, nonce) == 0)
            (void)nonce_record(kid, nonce);
        d2 = dec(&g_ctx[kid2], encbuf, (size_t)e2);
        if (d2 == (int)plen && memcmp(encbuf, orig, plen) == 0)
            atomic_fetch_add(&g_xtalk_bad, 1);
        else
            atomic_fetch_add(&g_xtalk_ok, 1);
    }
    /* Bitflip */
    {
        uint8_t encbuf[2048];
        int e2, d2;
        memcpy(encbuf, orig, plen);
        e2 = enc(&g_ctx[kid], encbuf, plen);
        if (e2 <= (int)plen)
            return 0;
        atomic_fetch_add(&g_ops, 1);
        if (getn(encbuf, (size_t)e2, nonce) == 0)
            (void)nonce_record(kid, nonce);
        encbuf[e2 / 2] ^= 0x01;
        d2 = dec(&g_ctx[kid], encbuf, (size_t)e2);
        if (d2 == (int)plen && memcmp(encbuf, orig, plen) == 0)
            atomic_fetch_add(&g_flip_bad, 1);
        else
            atomic_fetch_add(&g_flip_ok, 1);
    }
    return 0;
}

typedef int (*split_fn)(struct packet_crypto_ctx *, uint8_t *, uint32_t, size_t, uint32_t *,
                        uint8_t *, size_t, uint32_t *);
typedef int (*decf_fn)(struct packet_crypto_ctx *, uint8_t *, size_t, uint16_t *, uint8_t *);
typedef int (*reasm_fn)(struct frag_table *, const uint8_t *, uint32_t, uint16_t, uint8_t,
                        uint8_t *, uint32_t *);

static int frag_roundtrip(const struct conn_desc *c, const uint8_t *orig, size_t plen,
                          struct frag_table *ft, split_fn split, decf_fn decf, reasm_fn reasm,
                          nonce_fn getn, int layer)
{
    uint8_t work[2048], f1[2048], h0[2048], h1[2048], out[2048], nonce[NONCE_B];
    uint32_t f0len = 0, f1len = 0, olen = 0;
    uint16_t pid0 = 0, pid1 = 0;
    uint8_t fx0 = 0, fx1 = 0;
    int nd0, nd1, rr;
    uint8_t kid = c->key_id;

    memcpy(work, orig, plen);
    if (split(&g_ctx[kid], work, (uint32_t)plen, sizeof(work), &f0len, f1, sizeof(f1),
              &f1len) != 0) {
        atomic_fetch_add(&g_frag_fail, 1);
        return -1;
    }
    if (getn(work, f0len, nonce) == 0)
        (void)nonce_record(kid, nonce);
    if (getn(f1, f1len, nonce) == 0)
        (void)nonce_record(kid, nonce);

    memcpy(h0, work, f0len);
    memcpy(h1, f1, f1len);
    nd0 = decf(&g_ctx[kid], h0, f0len, &pid0, &fx0);
    nd1 = decf(&g_ctx[kid], h1, f1len, &pid1, &fx1);
    if (nd0 < 0 || nd1 < 0 || pid0 != pid1) {
        atomic_fetch_add(&g_frag_fail, 1);
        return -1;
    }

    frag_table_init(ft);
    rr = reasm(ft, h0, (uint32_t)nd0, pid0, fx0, out, &olen);
    if (rr != 0) {
        atomic_fetch_add(&g_frag_fail, 1);
        return -1;
    }
    rr = reasm(ft, h1, (uint32_t)nd1, pid1, fx1, out, &olen);
    if (rr != 1 || olen != (uint32_t)plen || memcmp(out, orig, plen) != 0) {
        atomic_fetch_add(&g_frag_corrupt, 1);
        fprintf(stderr, "FRAG corrupt conn=%u L%d rr=%d olen=%u\n", c->conn_id, layer, rr, olen);
        return -1;
    }
    atomic_fetch_add(&g_frags, 1);
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
    /* stagger so many threads hit overlapping conn pool */
    unsigned stride = (unsigned)(N_CONNS / N_THREADS);
    if (stride == 0)
        stride = 1;

    if (!ft)
        return NULL;

    crypto_layer2_bind_worker_idx((uint8_t)tid);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int it = 0; it < ITERS; it++) {
        unsigned cid = ((unsigned)tid * stride + (unsigned)it) % N_CONNS;
        const struct conn_desc *c = &g_conns[cid];
        int do_neg = ((it % NEG_EVERY) == 0);
        size_t plen;
        uint32_t seq = (uint32_t)(tid * 1000003u + (unsigned)it);

        packet_crypto_set_policy_id((uint8_t)(c->key_id + 1));
        plen = fill_conn_udp(orig, PAYLOAD, c, seq);

        packet_crypto_set_encrypt_layer(2);
        (void)roundtrip_layer(c, orig, plen, crypto_layer2_encrypt, crypto_layer2_decrypt,
                              extract_l2, 2, do_neg);
        packet_crypto_set_encrypt_layer(3);
        (void)roundtrip_layer(c, orig, plen, crypto_layer3_encrypt, crypto_layer3_decrypt,
                              extract_l3, 3, do_neg);
        packet_crypto_set_encrypt_layer(4);
        (void)roundtrip_layer(c, orig, plen, crypto_layer4_encrypt, crypto_layer4_decrypt,
                              extract_l4, 4, do_neg);

        if ((it % FRAG_EVERY) == 0) {
            size_t fplen = fill_conn_udp(orig, FRAG_PAD, c, seq ^ 0x5a5a5a5a);
            packet_crypto_set_encrypt_layer(2);
            (void)frag_roundtrip(c, orig, fplen, ft, frag_split_and_encrypt_l2,
                                 crypto_layer2_decrypt_fragment, frag_try_reassemble_l2,
                                 extract_l2, 2);
            packet_crypto_set_encrypt_layer(3);
            (void)frag_roundtrip(c, orig, fplen, ft, frag_split_and_encrypt,
                                 crypto_layer3_decrypt_fragment, frag_try_reassemble,
                                 extract_l3, 3);
            packet_crypto_set_encrypt_layer(4);
            (void)frag_roundtrip(c, orig, fplen, ft, frag_split_and_encrypt_l4,
                                 crypto_layer4_decrypt_fragment, frag_try_reassemble_l4,
                                 extract_l4, 4);
        }
    }

    free(ft);
    return NULL;
}

static void init_conns(void)
{
    for (int i = 0; i < N_CONNS; i++) {
        g_conns[i].conn_id = (uint16_t)i;
        g_conns[i].key_id = (uint8_t)(i % N_KEYS);
        g_conns[i].src_ip = 0x0a000001u + (uint32_t)i;         /* 10.0.0.1+i */
        g_conns[i].dst_ip = 0xc0a80001u + (uint32_t)(i % 250); /* 192.168.0.x */
        g_conns[i].sport = (uint16_t)(10000 + i);
        g_conns[i].dport = (uint16_t)(20000 + (i % 1000));
    }
}

int main(void)
{
    pthread_t th[N_THREADS];
    struct thr_arg args[N_THREADS];
    int rc = 0;

    g_ntab = calloc(NONCE_TAB, sizeof(*g_ntab));
    if (!g_ntab) {
        fprintf(stderr, "oom nonce tab\n");
        return 1;
    }

    frag_set_mtu(TEST_MTU);
    init_conns();

    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);

    for (int k = 0; k < N_KEYS; k++) {
        uint8_t master[32];
        memset(master, (uint8_t)(0x60 + k), sizeof(master));
        master[0] = (uint8_t)k;
        master[31] = (uint8_t)(0xC0 + k);
        if (packet_crypto_init(&g_ctx[k], master) != 0) {
            fprintf(stderr, "key %d init fail\n", k);
            return 1;
        }
        g_ctx[k].policy_id = k + 1;
    }
    packet_crypto_reset_counter();

    printf("GCM multi-conn: conns=%d threads=%d keys=%d iters/thread=%d GCM-256 L2+L3+L4\n",
           N_CONNS, N_THREADS, N_KEYS, ITERS);

    for (int t = 0; t < N_THREADS; t++) {
        args[t].tid = t;
        if (pthread_create(&th[t], NULL, worker, &args[t]) != 0)
            return 1;
    }
    for (int t = 0; t < N_THREADS; t++)
        pthread_join(th[t], NULL);

    printf("--- results ---\n");
    printf("encrypt ops:     %llu\n", (unsigned long long)atomic_load(&g_ops));
    printf("unique nonces:   %zu\n", g_nonce_count);
    printf("dup (key,nonce): %d (must 0)\n", atomic_load(&g_dup));
    printf("roundtrip fails: %d (must 0)\n", atomic_load(&g_rt_fail));
    printf("xtalk rejects:   %d\n", atomic_load(&g_xtalk_ok));
    printf("xtalk leaks:     %d (must 0)\n", atomic_load(&g_xtalk_bad));
    printf("bitflip rejects: %d\n", atomic_load(&g_flip_ok));
    printf("bitflip leaks:   %d (must 0)\n", atomic_load(&g_flip_bad));
    printf("frag joins OK:   %llu\n", (unsigned long long)atomic_load(&g_frags));
    printf("frag fails:      %d (must 0)\n", atomic_load(&g_frag_fail));
    printf("frag corrupt:    %d (must 0)\n", atomic_load(&g_frag_corrupt));

    if (atomic_load(&g_dup) || atomic_load(&g_rt_fail) || atomic_load(&g_xtalk_bad) ||
        atomic_load(&g_flip_bad) || atomic_load(&g_frag_fail) || atomic_load(&g_frag_corrupt) ||
        atomic_load(&g_ops) == 0 || atomic_load(&g_xtalk_ok) == 0 ||
        atomic_load(&g_flip_ok) == 0 || atomic_load(&g_frags) == 0) {
        printf("FAIL: multi-conn conflict detected\n");
        rc = 1;
    } else {
        printf("PASS: %d conns × %d threads — no GCM multi-conn conflict\n", N_CONNS, N_THREADS);
    }

    free(g_ntab);
    return rc;
}
