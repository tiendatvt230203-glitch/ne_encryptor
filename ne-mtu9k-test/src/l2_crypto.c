#include "l2_crypto.h"
#include "config.h"

#include "traffic_crypto.h"
#include "scrypt.h"

#include <string.h>
#include <stdio.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800

static SCryptCipherCtx *g_pqc_ctx;

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

int l2_encrypt(uint8_t *pkt, uint32_t pkt_len, uint32_t capacity)
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
    if ((uint32_t)l3_off + (uint32_t)payload_len + L2_GCM_TAG_BYTES > capacity)
        return -1;

    pkt[et_off] = (uint8_t)(L2_FAKE_ETHERTYPE >> 8);
    pkt[et_off + 1] = (uint8_t)(L2_FAKE_ETHERTYPE & 0xFF);

    if (trf_encrypt_payload_gcm(g_pqc_ctx, HARD_KEY, HARD_NONCE, L2_NONCE_BYTES,
                                HARD_AAD, HARD_AAD_LEN,
                                pkt + l3_off, (int)payload_len, &new_len) != TRF_PQC_OK)
        return -1;
    return l3_off + new_len;
}

int l2_decrypt(uint8_t *pkt, uint32_t pkt_len)
{
    int et_off = 12;
    int l3_off = ETH_HLEN;
    int plain_len = 0;
    int enc_len;

    if (!g_pqc_ctx || !pkt || !l2_has_enc_marker(pkt, pkt_len))
        return -1;
    if (pkt_len < ETH_HLEN + L2_GCM_TAG_BYTES + 20)
        return -1;

    enc_len = (int)pkt_len - l3_off;
    if (trf_decrypt_payload_gcm(g_pqc_ctx, HARD_KEY, HARD_NONCE, L2_NONCE_BYTES,
                                HARD_AAD, HARD_AAD_LEN,
                                pkt + l3_off, enc_len, &plain_len) != TRF_PQC_OK)
        return -1;

    pkt[et_off] = 0x08;
    pkt[et_off + 1] = 0x00;
    return l3_off + plain_len;
}
