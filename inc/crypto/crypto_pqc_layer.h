#ifndef CRYPTO_PQC_LAYER_H
#define CRYPTO_PQC_LAYER_H

#include "packet_crypto.h"
#include "traffic_crypto.h"
#include "pqc_handshake.h"
#include "scrypt.h"
#include <stdio.h>
static inline int crypto_mode_is_pqc(void) {
    return packet_crypto_get_mode() == CRYPTO_MODE_PQC;
}

static inline int crypto_mode_uses_gcm_tag(void) {
    int mode = packet_crypto_get_mode();
    return mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC;
}

typedef struct crypto_pqc_sess {
    const byte *key;
    const byte *aad;
    int aad_len;
} crypto_pqc_sess_t;

static const byte HARDCODED_AAD[] = {
    0x54, 0x45, 0x53, 0x54, 0x5f, 0x41, 0x41, 0x44
};
static inline int crypto_pqc_key_is_all_zero(const byte *key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (key[i] != 0) {
            return 0;
        }
    }
    return 1;
}
static inline int crypto_pqc_sess_load(struct packet_crypto_ctx *ctx, crypto_pqc_sess_t *sess) {
    if (!ctx || !sess)
        return -1;
    packet_crypto_update_keys(ctx);
    const byte *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;
    if (crypto_pqc_key_is_all_zero(key, PQC_TRAFFIC_KEY_SZ)) {
        fprintf(stderr,
                "[PQC-KEY] invalid CURRENT key (all-zero) for profile=%d policy=%d; blocking PQC crypto path\n",
                ctx->profile_id, ctx->policy_id);
        return -1;
    }
    sess->key = key;
    sess->aad = HARDCODED_AAD;
    sess->aad_len = 12;
    return 0;
}

static inline int crypto_pqc_generate_nonce(byte nonce[CRYPTO_PQC_NONCE_BYTES]) {
    return trf_pqc_generate_nonce(nonce) == TRF_PQC_OK ? 0 : -1;
}

static inline int crypto_pqc_encrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len) {
    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx)
        return -1;
    int rc = trf_encrypt_payload_gcm(ctx, sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                     sess->aad, sess->aad_len, data, len, out_len);
    scrypt_CipherCtxFree(ctx);
    return rc == TRF_PQC_OK ? 0 : -1;
}

static inline int crypto_pqc_decrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len) {
    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx)
        return -1;
    int rc = trf_decrypt_payload_gcm(ctx, sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                     sess->aad, sess->aad_len, data, len, out_len);
    scrypt_CipherCtxFree(ctx);
    return rc == TRF_PQC_OK ? 0 : -1;
}

#endif
