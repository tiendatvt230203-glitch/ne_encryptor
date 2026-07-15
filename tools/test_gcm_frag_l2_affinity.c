/*
 * L2 frag sticky worker affinity: same-worker join OK; cross-table must not join.
 *
 * Build:
 *   gcc -O2 -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include \
 *     tools/test_gcm_frag_l2_affinity.c \
 *     src/core/fragment.o src/crypto/packet_crypto.o \
 *     src/crypto/crypto_layer2.o src/crypto/crypto_layer3.o src/crypto/crypto_layer4.o \
 *     src/crypto/eth_parse.o \
 *     -L./lib -Wl,-rpath,'$ORIGIN/../lib' -lssl -lcrypto -lpthread -lscrypt \
 *     -o tools/test_gcm_frag_l2_affinity
 *   LD_LIBRARY_PATH=./lib ./tools/test_gcm_frag_l2_affinity
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "inc/core/config.h"
#include "inc/core/fragment.h"
#include "inc/crypto/packet_crypto.h"
#include "inc/crypto/crypto_layer2.h"

#define PAYLOAD       1200
#define TEST_FRAG_MTU 700
#define N_CASES       200

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

static int split_only(struct packet_crypto_ctx *ctx, const uint8_t *orig, size_t plen,
                      uint8_t *enc0, uint32_t *e0len, uint8_t *enc1, uint32_t *e1len)
{
    uint8_t work[2048], f1[2048];
    uint32_t f0len = 0, f1len = 0;

    memcpy(work, orig, plen);
    if (frag_split_and_encrypt_l2(ctx, work, (uint32_t)plen, sizeof(work), &f0len, f1,
                                  sizeof(f1), &f1len) != 0)
        return -1;
    memcpy(enc0, work, f0len);
    memcpy(enc1, f1, f1len);
    *e0len = f0len;
    *e1len = f1len;
    return 0;
}

static int decrypt_half(struct packet_crypto_ctx *ctx, uint8_t *half, uint32_t elen,
                        uint32_t *nd, uint16_t *pid, uint8_t *fx)
{
    int d = crypto_layer2_decrypt_fragment(ctx, half, elen, pid, fx);
    if (d < 0)
        return -1;
    *nd = (uint32_t)d;
    return 0;
}

int main(void)
{
    struct packet_crypto_ctx ctx;
    uint8_t master[32];
    struct frag_table *ft0, *ft1;
    int same_ok = 0, same_fail = 0;
    int cross_pending = 0, cross_bad_join = 0;
    int wire_worker_ok = 0, wire_worker_bad = 0;

    frag_set_mtu(TEST_FRAG_MTU);
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_fake_protocol(99);
    packet_crypto_set_policy_id(1);
    packet_crypto_set_encrypt_layer(2);

    memset(master, 0x44, sizeof(master));
    if (packet_crypto_init(&ctx, master) != 0)
        return 1;
    packet_crypto_reset_counter();

    ft0 = calloc(1, sizeof(*ft0));
    ft1 = calloc(1, sizeof(*ft1));
    if (!ft0 || !ft1)
        return 1;

    printf("L2 affinity: same-worker join OK; cross-table must stay pending\n");

    for (int i = 0; i < N_CASES; i++) {
        uint8_t orig[2048], e0[2048], e1[2048], h0[2048], h1[2048], out[2048];
        uint32_t e0len = 0, e1len = 0, n0 = 0, n1 = 0, olen = 0;
        uint16_t pid0 = 0, pid1 = 0;
        uint8_t fx0 = 0, fx1 = 0;
        uint8_t w0 = 0, w1 = 0;
        size_t plen = fill_udp(orig, PAYLOAD, (unsigned)(i * 17 + 3));
        int rr;

        crypto_layer2_bind_worker_idx(0);
        if (split_only(&ctx, orig, plen, e0, &e0len, e1, &e1len) != 0) {
            same_fail++;
            continue;
        }

        /* core_id is on the wire BEFORE decrypt_fragment (decrypt overwrites prefix) */
        if (crypto_layer2_read_worker_idx(e0, e0len, &w0) == 0 &&
            crypto_layer2_read_worker_idx(e1, e1len, &w1) == 0 && w0 == 0 && w1 == 0)
            wire_worker_ok++;
        else
            wire_worker_bad++;

        memcpy(h0, e0, e0len);
        memcpy(h1, e1, e1len);
        if (decrypt_half(&ctx, h0, e0len, &n0, &pid0, &fx0) != 0 ||
            decrypt_half(&ctx, h1, e1len, &n1, &pid1, &fx1) != 0 || pid0 != pid1) {
            same_fail++;
            continue;
        }

        frag_table_init(ft0);
        rr = frag_try_reassemble_l2(ft0, h0, n0, pid0, fx0, out, &olen);
        if (rr != 0) {
            same_fail++;
            continue;
        }
        rr = frag_try_reassemble_l2(ft0, h1, n1, pid1, fx1, out, &olen);
        if (rr == 1 && olen == (uint32_t)plen && memcmp(out, orig, plen) == 0)
            same_ok++;
        else
            same_fail++;

        frag_table_init(ft0);
        frag_table_init(ft1);
        memcpy(h0, e0, e0len);
        memcpy(h1, e1, e1len);
        if (decrypt_half(&ctx, h0, e0len, &n0, &pid0, &fx0) != 0 ||
            decrypt_half(&ctx, h1, e1len, &n1, &pid1, &fx1) != 0) {
            same_fail++;
            continue;
        }
        rr = frag_try_reassemble_l2(ft0, h0, n0, pid0, fx0, out, &olen);
        if (rr != 0) {
            cross_bad_join++;
            continue;
        }
        rr = frag_try_reassemble_l2(ft1, h1, n1, pid1, fx1, out, &olen);
        if (rr == 0)
            cross_pending++;
        else if (rr == 1)
            cross_bad_join++;
        else
            cross_pending++;
    }

    printf("--- results ---\n");
    printf("wire core_id sticky: ok=%d bad=%d\n", wire_worker_ok, wire_worker_bad);
    printf("same-worker joins:   ok=%d fail=%d\n", same_ok, same_fail);
    printf("cross-table:         pending/nojoin=%d bad_join=%d\n", cross_pending,
           cross_bad_join);

    free(ft0);
    free(ft1);

    if (same_ok != N_CASES || same_fail || cross_bad_join || wire_worker_bad ||
        cross_pending != N_CASES) {
        printf("FAIL\n");
        return 1;
    }
    printf("PASS: L2 sticky affinity — same-worker joins; cross-table never joins\n");
    return 0;
}
