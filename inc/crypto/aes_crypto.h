#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include <stdint.h>

#define AES_MAX_KEY_SIZE   32
#define AES128_IV_SIZE     16
#define AES_GCM_TAG_SIZE   16

int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           uint8_t tag_out[AES_GCM_TAG_SIZE],
                           int aes_bits);

int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           const uint8_t tag[AES_GCM_TAG_SIZE],
                           int aes_bits);

int crypto_aes_ctr_with_key(const uint8_t key[AES_MAX_KEY_SIZE],
                            const uint8_t iv[AES128_IV_SIZE],
                            uint8_t *data, int len,
                            int aes_bits);

#endif
