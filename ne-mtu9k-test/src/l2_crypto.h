#ifndef NE_MTU9K_L2_CRYPTO_H
#define NE_MTU9K_L2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int l2_crypto_init(void);
void l2_crypto_cleanup(void);

/* In-place L2 encrypt: IPv4 frame → fake ethertype + wire hdr + ciphertext+tag.
 * Returns new packet length, or -1. */
int l2_encrypt(uint8_t *pkt, uint32_t pkt_len, uint32_t capacity);

/* In-place L2 decrypt: fake ethertype frame → IPv4.
 * Returns new packet length, or -1. */
int l2_decrypt(uint8_t *pkt, uint32_t pkt_len);

int l2_has_enc_marker(const uint8_t *pkt, uint32_t pkt_len);

#endif
