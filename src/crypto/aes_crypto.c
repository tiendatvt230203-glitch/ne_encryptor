#include "../../inc/crypto/aes_crypto.h"

#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

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
static __thread int tls_gcm_enc_aes_bits;
static __thread int tls_gcm_dec_aes_bits;
static __thread int tls_ctr_aes_bits;

static EVP_CIPHER_CTX *tls_ctx_get(EVP_CIPHER_CTX **slot)
{
    if (!*slot)
        *slot = EVP_CIPHER_CTX_new();
    return *slot;
}

static int key_size_bytes(int aes_bits)
{
    return (aes_bits == 256) ? 32 : 16;
}

static const EVP_CIPHER *cipher_ctr(int aes_bits)
{
    return (aes_bits == 256) ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
}

static const EVP_CIPHER *cipher_gcm(int aes_bits)
{
    return (aes_bits == 256) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

static void tls_gcm_invalidate_enc(void)
{
    tls_gcm_enc_key_len = 0;
    tls_gcm_enc_aes_bits = 0;
    if (tls_gcm_enc_ctx)
        EVP_CIPHER_CTX_reset(tls_gcm_enc_ctx);
}

static void tls_gcm_invalidate_dec(void)
{
    tls_gcm_dec_key_len = 0;
    tls_gcm_dec_aes_bits = 0;
    if (tls_gcm_dec_ctx)
        EVP_CIPHER_CTX_reset(tls_gcm_dec_ctx);
}

static int gcm_bind_key(EVP_CIPHER_CTX *evp, int enc, const uint8_t *key, int nonce_len,
                        int aes_bits, uint8_t *cached_key, int *cached_key_len,
                        int *cached_nonce_len, int *cached_aes_bits)
{
    int ks = key_size_bytes(aes_bits);
    int key_changed = *cached_key_len != ks || *cached_aes_bits != aes_bits ||
                      memcmp(cached_key, key, (size_t)ks) != 0;
    int nonce_changed = *cached_nonce_len != nonce_len;

    if (!key_changed && !nonce_changed)
        return 0;

    if (EVP_CIPHER_CTX_reset(evp) != 1)
        return -1;

    if (enc) {
        if (EVP_EncryptInit_ex(evp, cipher_gcm(aes_bits), NULL, NULL, NULL) != 1)
            return -1;
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
            return -1;
        if (EVP_EncryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
            return -1;
    } else {
        if (EVP_DecryptInit_ex(evp, cipher_gcm(aes_bits), NULL, NULL, NULL) != 1)
            return -1;
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
            return -1;
        if (EVP_DecryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
            return -1;
    }

    memcpy(cached_key, key, (size_t)ks);
    *cached_key_len = ks;
    *cached_nonce_len = nonce_len;
    *cached_aes_bits = aes_bits;
    return 0;
}

int crypto_aes_ctr_with_key(const uint8_t key[AES_MAX_KEY_SIZE], const uint8_t iv[AES128_IV_SIZE],
                            uint8_t *data, int len, int aes_bits)
{
    EVP_CIPHER_CTX *evp;
    int ks, out_len, final_len;
    int key_changed;

    if (len <= 0)
        return 0;

    evp = tls_ctx_get(&tls_ctr_ctx);
    if (!evp) {
        printf("Het ram\n");
        return -1;
    }

    ks = key_size_bytes(aes_bits);
    if (tls_ctr_key_len != ks || tls_ctr_aes_bits != aes_bits)
        key_changed = 1;
    else if (memcmp(tls_ctr_key, key, (size_t)ks) != 0)
        key_changed = 1;
    else
        key_changed = 0;

    if (key_changed) {
        if (EVP_EncryptInit_ex(evp, cipher_ctr(aes_bits), NULL, key, iv) != 1)
            return -1;
        memcpy(tls_ctr_key, key, (size_t)ks);
        tls_ctr_key_len = ks;
        tls_ctr_aes_bits = aes_bits;
    } else if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, iv) != 1) {
        return -1;
    }

    if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1)
        return -1;

    final_len = 0;
    EVP_EncryptFinal_ex(evp, data + out_len, &final_len);
    return 0;
}

int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE], const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len, uint8_t tag_out[AES_GCM_TAG_SIZE], int aes_bits)
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
    if (gcm_bind_key(evp, 1, key, nonce_len, aes_bits, tls_gcm_enc_key, &tls_gcm_enc_key_len,
                     &tls_gcm_enc_nonce_len, &tls_gcm_enc_aes_bits) != 0) {
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
                           uint8_t *data, int len, const uint8_t tag[AES_GCM_TAG_SIZE], int aes_bits)
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

    if (gcm_bind_key(evp, 0, key, nonce_len, aes_bits, tls_gcm_dec_key, &tls_gcm_dec_key_len,
                     &tls_gcm_dec_nonce_len, &tls_gcm_dec_aes_bits) != 0) {
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
