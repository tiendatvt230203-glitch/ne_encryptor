#include "../../inc/crypto/packet_crypto.h"
#include "../../inc/crypto/traffic_crypto.h"
#include "../../inc/core/config.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdatomic.h>
#include <string.h>

#include "pqc_handshake.h"

static atomic_uint_fast32_t g_nonce_counter;

static __thread uint8_t tls_nonce_salt[16];
static __thread int tls_salt_initialized;

static int key_size_bytes(int aes_bits)
{
    return (aes_bits == 256) ? 32 : 16;
}

static int key_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i])
            return 1;
    }
    return 0;
}

static void derive_key(const uint8_t master[AES_MAX_KEY_SIZE], int aes_bits, uint64_t epoch,
                       uint8_t out[AES_MAX_KEY_SIZE])
{
    int ks = key_size_bytes(aes_bits);
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

int packet_crypto_init(struct packet_crypto_ctx *ctx, const uint8_t master_key[AES_MAX_KEY_SIZE],
                       int aes_bits)
{
    int ks;

    if (!ctx || !master_key)
        return -1;
    if (aes_bits != 128 && aes_bits != 256)
        aes_bits = 128;

    ks = key_size_bytes(aes_bits);
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->master_key, master_key, (size_t)ks);
    ctx->aes_bits = aes_bits;
    ctx->initialized = true;

    derive_key(ctx->master_key, aes_bits, 0, ctx->keys[KEY_SLOT_PREV]);
    derive_key(ctx->master_key, aes_bits, 0, ctx->keys[KEY_SLOT_CURRENT]);
    derive_key(ctx->master_key, aes_bits, 0, ctx->keys[KEY_SLOT_NEXT]);
    packet_crypto_reset_counter();

    return 0;
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx)
{
    if (!ctx)
        return;
    memset(ctx->master_key, 0, sizeof(ctx->master_key));
    memset(ctx->keys, 0, sizeof(ctx->keys));
    ctx->initialized = false;
}

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
