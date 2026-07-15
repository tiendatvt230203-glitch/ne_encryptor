#include "../../inc/crypto/packet_crypto.h"
#include "../../inc/core/config.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/types.h"
#include "../../inc/crypto/traffic_crypto.h"
#include "../../inc/crypto/scrypt.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdatomic.h>

#include "pqc_handshake.h"

/* --- thread-local config --- */
static uint16_t g_fake_ethertype_ipv4;
static __thread uint8_t g_fake_protocol = 99;
static __thread int g_encrypt_layer;
static __thread int g_crypto_mode;
static __thread int g_aes_bits = 128;
static __thread uint8_t g_policy_id;

static atomic_uint_fast32_t g_nonce_counter;

/* --- OpenSSL contexts (per thread) --- */
static __thread EVP_CIPHER_CTX *tls_ctr_ctx;
static __thread EVP_CIPHER_CTX *tls_gcm_enc_ctx;
static __thread EVP_CIPHER_CTX *tls_gcm_dec_ctx;

static __thread uint8_t tls_gcm_enc_key[AES_MAX_KEY_SIZE];
static __thread uint8_t tls_gcm_dec_key[AES_MAX_KEY_SIZE];
static __thread uint8_t tls_ctr_key[AES_MAX_KEY_SIZE];
static __thread int tls_gcm_enc_key_len;
static __thread int tls_gcm_dec_key_len;
static __thread int tls_gcm_enc_nonce_len;
static __thread int tls_gcm_dec_nonce_len;
static __thread int tls_ctr_key_len;

static __thread uint8_t tls_nonce_salt[16];
static __thread int tls_salt_initialized;

static EVP_CIPHER_CTX *tls_ctx_get(EVP_CIPHER_CTX **slot)
{
    if (!*slot)
        *slot = EVP_CIPHER_CTX_new();
    return *slot;
}

static int key_size_bytes(void)
{
    return (g_aes_bits == 256) ? 32 : 16;
}

static const EVP_CIPHER *cipher_ctr(void)
{
    return (g_aes_bits == 256) ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
}

static const EVP_CIPHER *cipher_gcm(void)
{
    return (g_aes_bits == 256) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

static int key_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

static void derive_key(const uint8_t master[AES_MAX_KEY_SIZE], uint64_t epoch,
                       uint8_t out[AES_MAX_KEY_SIZE])
{
    int ks = key_size_bytes();
    uint8_t epoch_buf[8];
    unsigned char hmac_out[32];
    unsigned int hmac_len;

    for (int i = 0; i < 8; i++)
        epoch_buf[i] = (uint8_t)(epoch >> (i * 8));

    HMAC(EVP_sha256(), master, ks, epoch_buf, sizeof(epoch_buf), hmac_out, &hmac_len);
    memcpy(out, hmac_out, (size_t)ks);
}

static void pqc_refresh_if_empty(struct packet_crypto_ctx *ctx)
{
    uint8_t new_key[PQC_TRAFFIC_KEY_SZ];

    if (!ctx || ctx->crypto_mode != CRYPTO_MODE_PQC)
        return;
    if (key_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ))
        return;
    if (sig_pqc_diversify_key(ctx->profile_id, ctx->policy_id, new_key) != 0)
        return;
    if (memcmp(ctx->keys[KEY_SLOT_CURRENT], new_key, PQC_TRAFFIC_KEY_SZ) == 0)
        return;

    memcpy(ctx->keys[KEY_SLOT_CURRENT], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_PREV], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_NEXT], new_key, PQC_TRAFFIC_KEY_SZ);
}

static void tls_gcm_invalidate_enc(void)
{
    tls_gcm_enc_key_len = 0;
    if (tls_gcm_enc_ctx)
        EVP_CIPHER_CTX_reset(tls_gcm_enc_ctx);
}

static void tls_gcm_invalidate_dec(void)
{
    tls_gcm_dec_key_len = 0;
    if (tls_gcm_dec_ctx)
        EVP_CIPHER_CTX_reset(tls_gcm_dec_ctx);
}

static int gcm_bind_key(EVP_CIPHER_CTX *evp, int enc, const uint8_t *key, int nonce_len,
                        uint8_t *cached_key, int *cached_key_len, int *cached_nonce_len)
{
    int ks = key_size_bytes();
    int key_changed = *cached_key_len != ks ||
                      memcmp(cached_key, key, (size_t)ks) != 0;
    int nonce_changed = *cached_nonce_len != nonce_len;

    if (!key_changed && !nonce_changed)
        return 0;

    if (EVP_CIPHER_CTX_reset(evp) != 1)
        return -1;

    if (enc) {
        if (EVP_EncryptInit_ex(evp, cipher_gcm(), NULL, NULL, NULL) != 1)
            return -1;
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
            return -1;
        if (EVP_EncryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
            return -1;
    } else {
        if (EVP_DecryptInit_ex(evp, cipher_gcm(), NULL, NULL, NULL) != 1)
            return -1;
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
            return -1;
        if (EVP_DecryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
            return -1;
    }

    memcpy(cached_key, key, (size_t)ks);
    *cached_key_len = ks;
    *cached_nonce_len = nonce_len;
    return 0;
}

/* --- public accessors --- */

int packet_crypto_get_tunnel_hdr_size(void)
{
    return PACKET_CRYPTO_NONCE_BYTES + 2;
}

void crypto_write_l3_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size,
                                   uint8_t policy_id, uint8_t orig_proto)
{
    memcpy(buf, nonce, (size_t)nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = orig_proto;
}

void crypto_read_l3_tunnel_header(const uint8_t *buf, int nonce_size, uint8_t *nonce_out,
                                  uint8_t *proto_flag, uint8_t *policy_id, uint8_t *orig_proto)
{
    memcpy(nonce_out, buf, (size_t)nonce_size);
    if (proto_flag)
        *proto_flag = buf[0] >> 7;
    if (policy_id)
        *policy_id = buf[nonce_size];
    if (orig_proto)
        *orig_proto = buf[nonce_size + 1];
}

void packet_crypto_set_fake_ethertype(uint16_t fake_ipv4)
{
    g_fake_ethertype_ipv4 = fake_ipv4;
}

uint16_t packet_crypto_get_fake_ethertype_ipv4(void)
{
    return g_fake_ethertype_ipv4;
}

void packet_crypto_set_encrypt_layer(int layer)
{
    g_encrypt_layer = layer;
}

void packet_crypto_set_mode(int mode)
{
    g_crypto_mode = mode;
}

int packet_crypto_get_mode(void)
{
    return g_crypto_mode;
}

void packet_crypto_set_aes_bits(int bits)
{
    g_aes_bits = bits;
}

int packet_crypto_get_aes_bits(void)
{
    return g_aes_bits;
}

uint32_t packet_crypto_next_counter(void)
{
    return atomic_fetch_add(&g_nonce_counter, 1) & 0x7FFFFFFFu;
}

void packet_crypto_reset_counter(void)
{
    atomic_store(&g_nonce_counter, 0);
}

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot)
{
    if (!ctx || slot < 0 || slot >= KEY_SLOT_COUNT)
        return NULL;
    return ctx->keys[slot];
}

void packet_crypto_update_keys(struct packet_crypto_ctx *ctx)
{
    pqc_refresh_if_empty(ctx);
}

void packet_crypto_refresh_pqc_keys(struct packet_crypto_ctx *ctx)
{
    uint8_t new_key[PQC_TRAFFIC_KEY_SZ];

    if (!ctx || ctx->crypto_mode != CRYPTO_MODE_PQC)
        return;
    if (sig_pqc_diversify_key(ctx->profile_id, ctx->policy_id, new_key) != 0)
        return;
    memcpy(ctx->keys[KEY_SLOT_CURRENT], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_PREV], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_NEXT], new_key, PQC_TRAFFIC_KEY_SZ);
}

int packet_crypto_init(struct packet_crypto_ctx *ctx, const uint8_t master_key[AES_MAX_KEY_SIZE])
{
    int ks;

    if (!ctx || !master_key)
        return -1;

    ks = key_size_bytes();
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->master_key, master_key, (size_t)ks);
    ctx->initialized = true;

    derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_PREV]);
    derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_CURRENT]);
    derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_NEXT]);
    packet_crypto_reset_counter();

    return tls_ctx_get(&tls_ctr_ctx) ? 0 : -1;
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx)
{
    if (ctx) {
        memset(ctx->master_key, 0, sizeof(ctx->master_key));
        memset(ctx->keys, 0, sizeof(ctx->keys));
        ctx->initialized = false;
    }

    if (tls_ctr_ctx) {
        EVP_CIPHER_CTX_free(tls_ctr_ctx);
        tls_ctr_ctx = NULL;
    }
    if (tls_gcm_enc_ctx) {
        EVP_CIPHER_CTX_free(tls_gcm_enc_ctx);
        tls_gcm_enc_ctx = NULL;
    }
    if (tls_gcm_dec_ctx) {
        EVP_CIPHER_CTX_free(tls_gcm_dec_ctx);
        tls_gcm_dec_ctx = NULL;
    }

    tls_gcm_enc_key_len = 0;
    tls_gcm_dec_key_len = 0;
    tls_ctr_key_len = 0;
}

/* --- AES-CTR --- */

int crypto_aes_ctr_with_key(const uint8_t key[AES_MAX_KEY_SIZE], const uint8_t iv[AES128_IV_SIZE],
                            uint8_t *data, int len)
{
    EVP_CIPHER_CTX *evp;
    int ks, out_len, final_len;
    int key_changed;

    if (len <= 0)
        return 0;

    evp = tls_ctx_get(&tls_ctr_ctx);
    if (!evp){
        printf("Het ram\n");
        return -1;
    }

    ks = key_size_bytes();
    if (tls_ctr_key_len != ks) {
        key_changed = 1;
    }
    else if (memcmp(tls_ctr_key, key, (size_t)ks) != 0) {
        key_changed = 1;
    } 
    else {
        key_changed = 0;
    }
    
    if (key_changed) {
        if (EVP_EncryptInit_ex(evp, cipher_ctr(), NULL, key, iv) != 1)
            return -1;
        memcpy(tls_ctr_key, key, (size_t)ks);
        tls_ctr_key_len = ks;
    } 
    else if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, iv) != 1) {
        return -1;
    }

    if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1)
        return -1;

    final_len = 0;
    EVP_EncryptFinal_ex(evp, data + out_len, &final_len);
    return 0;
}

int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE], const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len, uint8_t tag_out[AES_GCM_TAG_SIZE])
{
    EVP_CIPHER_CTX *evp;
    int out_len;

    if (len <= 0)
        return 0;
    if (!key || !nonce || !data || !tag_out)
        return -1;  
    
    evp = tls_ctx_get(&tls_gcm_enc_ctx);
    if (!evp) {
        printf("Het ram gcm\n");
        return -1;
    }
    if (gcm_bind_key(evp, 1, key, nonce_len, tls_gcm_enc_key, &tls_gcm_enc_key_len,
                     &tls_gcm_enc_nonce_len) != 0) {
        tls_gcm_invalidate_enc();
        return -1;
    }

    if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) {
        tls_gcm_invalidate_enc();
        return -1;
    }
    if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) {
        tls_gcm_invalidate_enc();
        return -1;
    }
    if (EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1) {
        tls_gcm_invalidate_enc();
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1) {
        tls_gcm_invalidate_enc();
        return -1;
    }
    return 0;
}

int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE], const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len, const uint8_t tag[AES_GCM_TAG_SIZE])
{  
    EVP_CIPHER_CTX *evp;
    int out_len;

    if (len <= 0)
        return 0;
    if (!key || !nonce || !data || !tag)
        return -1;

    evp = tls_ctx_get(&tls_gcm_dec_ctx);
    if (!evp)
        return -1;

    if (gcm_bind_key(evp, 0, key, nonce_len, tls_gcm_dec_key, &tls_gcm_dec_key_len,
                     &tls_gcm_dec_nonce_len) != 0) {
        tls_gcm_invalidate_dec();
        return -1;
    }

    if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) {
        tls_gcm_invalidate_dec();
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) {
        tls_gcm_invalidate_dec();
        return -1;
    }
    if (EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1) {
        tls_gcm_invalidate_dec();
        return -1;
    }
    if (EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1) {
        tls_gcm_invalidate_dec();
        return -1;
    }
    return 0;
}

/* --- nonce / wire header --- */

void crypto_generate_nonce(uint32_t counter, uint8_t proto_flag, uint8_t *out_nonce,
                           int *out_nonce_len)
{
    const int ns = PACKET_CRYPTO_NONCE_BYTES;

    out_nonce[0] = (uint8_t)((proto_flag << 7) | ((counter >> 24) & 0x7F));
    out_nonce[1] = (uint8_t)((counter >> 16) & 0xFF);
    out_nonce[2] = (uint8_t)((counter >> 8) & 0xFF);
    out_nonce[3] = (uint8_t)(counter & 0xFF);

    if (!tls_salt_initialized) {
        RAND_bytes(tls_nonce_salt, (int)sizeof(tls_nonce_salt));
        tls_salt_initialized = 1;
    }
    memcpy(out_nonce + 4, tls_nonce_salt, (size_t)(ns - 4));
    *out_nonce_len = ns;
}

void crypto_nonce_to_iv(const uint8_t *nonce, int nonce_size, uint8_t iv[AES128_IV_SIZE])
{
    memcpy(iv, nonce, (size_t)nonce_size);
    if (nonce_size < AES128_IV_SIZE)
        memset(iv + nonce_size, 0, (size_t)(AES128_IV_SIZE - nonce_size));
}

void crypto_write_counter(uint8_t *packet, const uint8_t *nonce, int nonce_size, uint8_t policy_id)
{
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();

    packet[12] = (uint8_t)(fake >> 8);
    packet[13] = (uint8_t)(fake & 0xFF);
    packet[CRYPTO_L2_POLICY_OFF] = policy_id;
    memcpy(packet + CRYPTO_L2_NONCE_OFF, nonce, (size_t)nonce_size);
}

void crypto_read_counter(const uint8_t *packet, int nonce_size, uint8_t *nonce_out,
                         uint8_t *policy_id, uint8_t *proto_flag)
{
    if (policy_id)
        *policy_id = packet[CRYPTO_L2_POLICY_OFF];
    memcpy(nonce_out, packet + CRYPTO_L2_NONCE_OFF, (size_t)nonce_size);
    if (proto_flag)
        *proto_flag = (uint8_t)(nonce_out[0] >> 7);
}

/* --- checksums --- */

uint16_t crypto_calc_ip_checksum(const uint8_t *ip_hdr, int hdr_len)
{
    uint32_t sum = 0;

    for (int i = 0; i < hdr_len; i += 2) {
        uint16_t word = (uint16_t)((uint16_t)ip_hdr[i] << 8);
        if (i + 1 < hdr_len)
            word |= ip_hdr[i + 1];
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

void crypto_ipv4_checksum_replace_word(uint8_t *ip_hdr, uint16_t old_word, uint16_t new_word)
{
    uint32_t sum;
    uint16_t hc;

    if (!ip_hdr || old_word == new_word)
        return;

    hc = (uint16_t)(((uint16_t)ip_hdr[10] << 8) | ip_hdr[11]);
    /* HC' = ~(~HC + ~m + m')  (RFC 1624) */
    sum = (uint32_t)(~hc & 0xFFFFu) + (uint32_t)(~old_word & 0xFFFFu) + (uint32_t)new_word;
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    hc = (uint16_t)(~sum);
    ip_hdr[10] = (uint8_t)(hc >> 8);
    ip_hdr[11] = (uint8_t)(hc & 0xFF);
}

uint16_t crypto_calc_tcp_checksum(const uint8_t *ip_hdr, int ip_hdr_len, const uint8_t *tcp_seg,
                                  int tcp_seg_len)
{
    uint32_t sum = 0;

    if (ip_hdr_len < 20 || tcp_seg_len < 20)
        return 0;

    sum += ((uint16_t)ip_hdr[12] << 8) | ip_hdr[13];
    sum += ((uint16_t)ip_hdr[14] << 8) | ip_hdr[15];
    sum += ((uint16_t)ip_hdr[16] << 8) | ip_hdr[17];
    sum += ((uint16_t)ip_hdr[18] << 8) | ip_hdr[19];
    sum += 6;
    sum += (uint16_t)(tcp_seg_len & 0xFFFF);

    for (int i = 0; i < tcp_seg_len; i += 2) {
        uint16_t word;
        if (i == 16 && i + 2 <= tcp_seg_len) {
            word = 0;
        } else {
            word = (uint16_t)((uint16_t)tcp_seg[i] << 8);
            if (i + 1 < tcp_seg_len)
                word |= tcp_seg[i + 1];
        }
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t crypto_calc_udp_checksum(const uint8_t *ip_hdr, int ip_hdr_len, const uint8_t *udp_seg,
                                  int udp_seg_len)
{
    uint32_t sum = 0;
    uint16_t udp_len;

    if (ip_hdr_len < 20 || udp_seg_len < 8)
        return 0;

    udp_len = (uint16_t)(((uint16_t)udp_seg[4] << 8) | udp_seg[5]);
    if (udp_len < 8)
        udp_len = 8;
    if (udp_len > (uint16_t)udp_seg_len)
        udp_len = (uint16_t)udp_seg_len;

    sum += ((uint16_t)ip_hdr[12] << 8) | ip_hdr[13];
    sum += ((uint16_t)ip_hdr[14] << 8) | ip_hdr[15];
    sum += ((uint16_t)ip_hdr[16] << 8) | ip_hdr[17];
    sum += ((uint16_t)ip_hdr[18] << 8) | ip_hdr[19];
    sum += 17;
    sum += udp_len;

    for (int i = 0; i < (int)udp_len; i += 2) {
        uint16_t word = (uint16_t)((uint16_t)udp_seg[i] << 8);
        if (i + 1 < (int)udp_len)
            word |= udp_seg[i + 1];
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}


int packet_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len)
{
    packet_crypto_update_keys(ctx);

    switch (g_encrypt_layer) {
    case 2:
        return crypto_layer2_decrypt(ctx, packet, pkt_len);
    case 3:
        return crypto_layer3_decrypt(ctx, packet, pkt_len);
    case 4:
        return crypto_layer4_decrypt(ctx, packet, pkt_len);
    default:
        return -1;
    }
}

void packet_crypto_set_fake_protocol(uint8_t proto)
{
    g_fake_protocol = proto;
}

uint8_t packet_crypto_get_fake_protocol(void)
{
    return g_fake_protocol;
}

void packet_crypto_set_policy_id(uint8_t policy_id)
{
    g_policy_id = policy_id;
}

uint8_t packet_crypto_get_policy_id(void)
{
    return g_policy_id;
}