#ifndef NE_MTU9K_L2_CRYPTO_H
#define NE_MTU9K_L2_CRYPTO_H

#include <stdint.h>

int l2_crypto_init(void);
void l2_crypto_cleanup(void);
int l2_has_enc_marker(const uint8_t *pkt, uint32_t pkt_len);
int l2_encrypt(uint8_t *pkt, uint32_t pkt_len, uint32_t capacity);
int l2_decrypt(uint8_t *pkt, uint32_t pkt_len);

#endif
