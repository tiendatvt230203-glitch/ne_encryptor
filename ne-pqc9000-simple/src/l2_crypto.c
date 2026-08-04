#include "l2_crypto.h"
#include "config.h"

#include "traffic_crypto.h"
#include "scrypt.h"
#include "eth_parse.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPPROTO_UDP_VAL 17
static const uint8_t SIMPLE_CBC_IV[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

typedef struct {
    uint32_t magic;
    uint16_t id;
    uint8_t idx;
    uint8_t total;
    uint16_t orig_len;
    uint16_t frag_len;
} __attribute__((packed)) simple_frag_hdr_t;

#define SIMPLE_FRAG_MAGIC 0x53465247u /* SFRG */

static SCryptCipherCtx *g_pqc_ctx;
static uint16_t g_frag_id;

static struct {
    uint16_t id;
    uint16_t total_len;
    uint16_t frag0_len;
    uint8_t have_frag0;
    uint8_t buf[NE_PKT_MAX];
} g_reasm;

int l2_crypto_init(void)
{
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "[L2-PQC] trf_pqc_init_global failed\n");
        return -1;
    }
    g_pqc_ctx = scrypt_CipherCtxNew();
    if (!g_pqc_ctx) {
        fprintf(stderr, "[L2-PQC] CipherCtxNew failed\n");
        return -1;
    }
    memset(&g_reasm, 0, sizeof(g_reasm));
    return 0;
}

void l2_crypto_cleanup(void)
{
    if (g_pqc_ctx) {
        scrypt_CipherCtxFree(g_pqc_ctx);
        g_pqc_ctx = NULL;
    }
    trf_pqc_cleanup();
}

int l2_has_enc_marker(const uint8_t *pkt, uint32_t pkt_len)
{
    uint16_t et;

    if (!pkt || pkt_len < ETH_HLEN)
        return 0;
    et = (uint16_t)((pkt[12] << 8) | pkt[13]);
    return et == L2_FAKE_ETHERTYPE;
}

/*
 * L2 encrypt: rewrite ethertype → 0x104A, CBC over L3+ only.
 * No wire nonce / core_id / policy_id (unlike production pqc_l2_option).
 */
static int l2_encrypt_raw(uint8_t *pkt, uint32_t pkt_len, uint32_t capacity)
{
    int et_off = 12;
    int l3_off = ETH_HLEN;
    size_t payload_len;
    int new_len = 0;

    if (!g_pqc_ctx || !pkt || pkt_len < ETH_HLEN + 20)
        return -1;
    if (((pkt[12] << 8) | pkt[13]) != ETH_P_IP)
        return -1;

    payload_len = pkt_len - (size_t)l3_off;
    if ((uint32_t)l3_off + (uint32_t)payload_len > capacity)
        return -1;

    pkt[et_off] = (uint8_t)(L2_FAKE_ETHERTYPE >> 8);
    pkt[et_off + 1] = (uint8_t)(L2_FAKE_ETHERTYPE & 0xFF);

    if (trf_encrypt_payload_cbc(HARD_KEY, SIMPLE_CBC_IV, (int)sizeof(SIMPLE_CBC_IV),
                                pkt + l3_off, (int)payload_len) != TRF_PQC_OK)
        return -1;
    new_len = (int)payload_len;
    return l3_off + new_len;
}

static int l2_decrypt_raw(uint8_t *pkt, uint32_t pkt_len)
{
    int et_off = 12;
    int l3_off = ETH_HLEN;
    int plain_len = 0;
    int enc_len;

    if (!g_pqc_ctx || !pkt || !l2_has_enc_marker(pkt, pkt_len))
        return -1;
    if (pkt_len < ETH_HLEN + 20)
        return -1;

    enc_len = (int)pkt_len - l3_off;
    if (trf_decrypt_payload_cbc(HARD_KEY, SIMPLE_CBC_IV, (int)sizeof(SIMPLE_CBC_IV),
                                pkt + l3_off, enc_len) != TRF_PQC_OK)
        return -1;
    plain_len = enc_len;

    pkt[et_off] = 0x08;
    pkt[et_off + 1] = 0x00;
    return l3_off + plain_len;
}

static int is_udp_ipv4(const uint8_t *pkt, uint32_t len)
{
    int off = crypto_eth_ipv4_offset(pkt, len);
    if (off < 0 || len < (uint32_t)(off + 20))
        return 0;
    return pkt[off + 9] == IPPROTO_UDP_VAL;
}

int l2_encrypt_maybe_fragment(uint8_t *pkt, uint32_t *pkt_len, uint32_t capacity,
                              uint8_t *frag2_out, uint32_t *frag2_len)
{
    uint32_t plain_len;
    uint32_t max_plain_per_frag;
    uint32_t chunk0;
    uint32_t chunk1;
    uint8_t tmp0[NE_PKT_MAX];
    uint8_t tmp1[NE_PKT_MAX];
    simple_frag_hdr_t h0, h1;
    uint16_t id;
    int enc_len;

    if (!pkt || !pkt_len || !frag2_out || !frag2_len)
        return -1;
    *frag2_len = 0;

    (void)crypto_tcp_clamp_mss(pkt, *pkt_len, SIMPLE_MTU, SIMPLE_WIRE_OVERHEAD);

    if (!is_udp_ipv4(pkt, *pkt_len) || *pkt_len <= SIMPLE_UDP_FRAG_MTU) {
        enc_len = l2_encrypt_raw(pkt, *pkt_len, capacity);
        if (enc_len < 0)
            return -1;
        *pkt_len = (uint32_t)enc_len;
        return 0;
    }

    plain_len = *pkt_len - ETH_HLEN;
    max_plain_per_frag = SIMPLE_UDP_FRAG_MTU - ETH_HLEN - sizeof(simple_frag_hdr_t);
    if (max_plain_per_frag < 256)
        return -1;

    chunk0 = plain_len / 2;
    if (chunk0 > max_plain_per_frag)
        chunk0 = max_plain_per_frag;
    chunk1 = plain_len - chunk0;
    if (chunk1 > max_plain_per_frag)
        return -1;

    id = ++g_frag_id;
    memcpy(tmp0, pkt, ETH_HLEN);
    memcpy(tmp1, pkt, ETH_HLEN);

    h0.magic = htonl(SIMPLE_FRAG_MAGIC);
    h0.id = htons(id);
    h0.idx = 0;
    h0.total = 2;
    h0.orig_len = htons((uint16_t)plain_len);
    h0.frag_len = htons((uint16_t)chunk0);

    h1.magic = htonl(SIMPLE_FRAG_MAGIC);
    h1.id = htons(id);
    h1.idx = 1;
    h1.total = 2;
    h1.orig_len = htons((uint16_t)plain_len);
    h1.frag_len = htons((uint16_t)chunk1);

    memcpy(tmp0 + ETH_HLEN, &h0, sizeof(h0));
    memcpy(tmp0 + ETH_HLEN + sizeof(h0), pkt + ETH_HLEN, chunk0);
    memcpy(tmp1 + ETH_HLEN, &h1, sizeof(h1));
    memcpy(tmp1 + ETH_HLEN + sizeof(h1), pkt + ETH_HLEN + chunk0, chunk1);

    enc_len = l2_encrypt_raw(tmp0, ETH_HLEN + sizeof(h0) + chunk0, NE_PKT_MAX);
    if (enc_len < 0)
        return -1;
    memcpy(pkt, tmp0, (size_t)enc_len);
    *pkt_len = (uint32_t)enc_len;

    enc_len = l2_encrypt_raw(tmp1, ETH_HLEN + sizeof(h1) + chunk1, NE_PKT_MAX);
    if (enc_len < 0)
        return -1;
    memcpy(frag2_out, tmp1, (size_t)enc_len);
    *frag2_len = (uint32_t)enc_len;
    return 0;
}

int l2_decrypt_maybe_reassemble(uint8_t *pkt, uint32_t *pkt_len)
{
    int plain_len;
    simple_frag_hdr_t h;
    uint16_t id;
    uint16_t orig_len;
    uint16_t frag_len;

    if (!pkt || !pkt_len)
        return -1;

    plain_len = l2_decrypt_raw(pkt, *pkt_len);
    if (plain_len < 0)
        return -1;
    *pkt_len = (uint32_t)plain_len;

    if (*pkt_len < ETH_HLEN + sizeof(simple_frag_hdr_t))
        return 0;

    memcpy(&h, pkt + ETH_HLEN, sizeof(h));
    if (ntohl(h.magic) != SIMPLE_FRAG_MAGIC || h.total != 2)
        return 0;

    id = ntohs(h.id);
    orig_len = ntohs(h.orig_len);
    frag_len = ntohs(h.frag_len);
    if (orig_len == 0 || orig_len > NE_PKT_MAX - ETH_HLEN)
        return -1;
    if ((uint32_t)ETH_HLEN + sizeof(h) + frag_len > *pkt_len)
        return -1;

    if (h.idx == 0) {
        g_reasm.id = id;
        g_reasm.total_len = orig_len;
        g_reasm.frag0_len = frag_len;
        g_reasm.have_frag0 = 1;
        memcpy(g_reasm.buf, pkt, ETH_HLEN);
        memcpy(g_reasm.buf + ETH_HLEN, pkt + ETH_HLEN + sizeof(h), frag_len);
        return 1; /* stored, not ready */
    }

    if (h.idx == 1 && g_reasm.have_frag0 && g_reasm.id == id) {
        uint32_t need = g_reasm.frag0_len + frag_len;
        if (need != g_reasm.total_len)
            return -1;
        memcpy(g_reasm.buf + ETH_HLEN + g_reasm.frag0_len,
               pkt + ETH_HLEN + sizeof(h), frag_len);
        memcpy(pkt, g_reasm.buf, ETH_HLEN + g_reasm.total_len);
        *pkt_len = ETH_HLEN + g_reasm.total_len;
        g_reasm.have_frag0 = 0;
        return 0;
    }

    return 1;
}
