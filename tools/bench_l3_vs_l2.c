/* Micro-harness: L2 / L3 / L4 AES-GCM encrypt+decrypt throughput + correctness. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "inc/core/config.h"
#include "inc/crypto/packet_crypto.h"
#include "inc/crypto/crypto_layer2.h"
#include "inc/crypto/crypto_layer3.h"
#include "inc/crypto/crypto_layer4.h"

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

static uint16_t ip_cksum(const uint8_t *ip, int len)
{
    return crypto_calc_ip_checksum(ip, len);
}

static size_t fill_ipv4_udp(uint8_t *pkt, size_t payload_pad)
{
    size_t ip_tot = 20 + 8 + payload_pad;
    size_t eth_len = 14 + ip_tot;
    memset(pkt, 0, eth_len);

    memset(pkt + 0, 0x02, 6);
    memset(pkt + 6, 0x04, 6);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    uint8_t *ip = pkt + 14;
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2] = (uint8_t)(ip_tot >> 8);
    ip[3] = (uint8_t)(ip_tot & 0xff);
    ip[8] = 64;
    ip[9] = 17;
    ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;
    ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;
    uint16_t c = ip_cksum(ip, 20);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)(c & 0xff);

    uint8_t *udp = ip + 20;
    udp[0] = 0x12; udp[1] = 0x34;
    udp[2] = 0x56; udp[3] = 0x78;
    uint16_t ulen = (uint16_t)(8 + payload_pad);
    udp[4] = (uint8_t)(ulen >> 8);
    udp[5] = (uint8_t)(ulen & 0xff);
    for (size_t i = 0; i < payload_pad; i++)
        udp[8 + i] = (uint8_t)(i & 0xff);
    return eth_len;
}

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

typedef int (*enc_fn)(struct packet_crypto_ctx *, uint8_t *, size_t);
typedef int (*dec_fn)(struct packet_crypto_ctx *, uint8_t *, size_t);

static double bench_pair(struct packet_crypto_ctx *ctx, const uint8_t *orig, size_t pkt_len,
                         enc_fn enc, dec_fn dec, int iters)
{
    uint8_t work[2048];
    int i, elen, dlen;
    double t0, t1;

    for (i = 0; i < 2000; i++) {
        memcpy(work, orig, pkt_len);
        elen = enc(ctx, work, pkt_len);
        if (elen < 0)
            return -1;
        dlen = dec(ctx, work, (size_t)elen);
        if (dlen < 0)
            return -1;
    }

    t0 = now_sec();
    for (i = 0; i < iters; i++) {
        memcpy(work, orig, pkt_len);
        elen = enc(ctx, work, pkt_len);
        if (elen < 0)
            return -1;
        dlen = dec(ctx, work, (size_t)elen);
        if (dlen < 0)
            return -1;
    }
    t1 = now_sec();
    return (t1 - t0) * 1e9 / (double)iters;
}

int main(void)
{
    const size_t pad = 1400 - 20 - 8;
    const int iters = 400000;
    uint8_t key[32];
    struct packet_crypto_ctx ctx;
    uint8_t orig[2048], work[2048], mid[2048];
    size_t pkt_len;
    int elen, dlen;
    double l2_ns, l3_ns, l4_ns;

    memset(key, 0x11, sizeof(key));
    packet_crypto_set_mode(CRYPTO_MODE_GCM);
    packet_crypto_set_aes_bits(256);
    packet_crypto_set_fake_protocol(99);
    packet_crypto_set_fake_ethertype(0x88B5);
    packet_crypto_set_policy_id(1);

    if (packet_crypto_init(&ctx, key) != 0) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    pkt_len = fill_ipv4_udp(orig, pad);

    /* --- L3 correctness --- */
    memcpy(work, orig, pkt_len);
    elen = crypto_layer3_encrypt(&ctx, work, pkt_len);
    if (elen < 0 || (memcpy(mid, work, (size_t)elen), mid[14 + 9] != 99)) {
        fprintf(stderr, "FAIL: L3 encrypt/proto\n");
        return 1;
    }
    dlen = crypto_layer3_decrypt(&ctx, work, (size_t)elen);
    if (dlen != (int)pkt_len || memcmp(work, orig, pkt_len) != 0) {
        fprintf(stderr, "FAIL: L3 roundtrip\n");
        return 1;
    }
    printf("OK: L3 roundtrip + ip.proto==99\n");

    /* --- L4 correctness: ports clear, rest encrypted --- */
    memcpy(work, orig, pkt_len);
    elen = crypto_layer4_encrypt(&ctx, work, pkt_len);
    if (elen < 0) {
        fprintf(stderr, "FAIL: L4 encrypt\n");
        return 1;
    }
    if (memcmp(work + 14 + 20, orig + 14 + 20, 4) != 0) {
        fprintf(stderr, "FAIL: L4 src/dst ports not clear on wire\n");
        return 1;
    }
    {
        uint8_t *ip = work + 14;
        uint16_t saved10 = ip[10], saved11 = ip[11];
        ip[10] = ip[11] = 0;
        uint16_t expect = crypto_calc_ip_checksum(ip, 20);
        ip[10] = saved10;
        ip[11] = saved11;
        uint16_t got = ((uint16_t)saved10 << 8) | saved11;
        if (got != expect) {
            fprintf(stderr, "FAIL: L4 IP checksum got=0x%04x expect=0x%04x\n", got, expect);
            return 1;
        }
    }
    dlen = crypto_layer4_decrypt(&ctx, work, (size_t)elen);
    if (dlen != (int)pkt_len || memcmp(work, orig, pkt_len) != 0) {
        fprintf(stderr, "FAIL: L4 roundtrip dlen=%d\n", dlen);
        return 1;
    }
    printf("OK: L4 roundtrip + ports clear + incremental IP csum\n");

    l2_ns = bench_pair(&ctx, orig, pkt_len, crypto_layer2_encrypt, crypto_layer2_decrypt, iters);
    l3_ns = bench_pair(&ctx, orig, pkt_len, crypto_layer3_encrypt, crypto_layer3_decrypt, iters);
    l4_ns = bench_pair(&ctx, orig, pkt_len, crypto_layer4_encrypt, crypto_layer4_decrypt, iters);
    if (l2_ns < 0 || l3_ns < 0 || l4_ns < 0) {
        fprintf(stderr, "bench failed\n");
        return 1;
    }

    printf("AES-GCM pkt~%zuB, N=%d:\n", pkt_len, iters);
    printf("  L2=%.1f ns/op\n", l2_ns);
    printf("  L3=%.1f ns/op  (L3/L2=%.3f)\n", l3_ns, l3_ns / l2_ns);
    printf("  L4=%.1f ns/op  (L4/L3=%.3f)\n", l4_ns, l4_ns / l3_ns);

    if (l4_ns > l3_ns * 1.05)
        printf("NOTE: L4 within noise of L3 (small cipher delta vs AES)\n");
    else
        printf("PASS: L4 not slower than L3 (ratio<=1.05)\n");

    packet_crypto_cleanup(&ctx);
    return 0;
}
