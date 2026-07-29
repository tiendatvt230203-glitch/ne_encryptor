#include "l4pqc_rss.h"
#include "l4pqc_crypto.h"

#include "../../../inc/crypto/packet_crypto.h"
#include "../../../inc/core/config.h"
#include "../../../src/crypto/pqc/include/traffic_crypto.h"

#include <stdio.h>
#include <string.h>

static uint8_t g_static_key[32];
static int g_static_key_len;

void l4pqc_crypto_set_static_key(const uint8_t *key, int len)
{
    if (!key || len <= 0 || len > 32)
        return;
    memcpy(g_static_key, key, (size_t)len);
    g_static_key_len = len;
}

int l4pqc_crypto_init_ctx(struct packet_crypto_ctx *ctx,
                          const struct l4pqc_config *cfg)
{
    uint8_t zero[AES_MAX_KEY_SIZE];

    if (!ctx || !cfg)
        return -1;
    if (trf_pqc_init_global() != TRF_PQC_OK) {
        fprintf(stderr, "[L4PQC] scrypt init failed\n");
        return -1;
    }
    memset(zero, 0, sizeof(zero));
    memset(ctx, 0, sizeof(*ctx));
    if (packet_crypto_init(ctx, zero, 256) != 0)
        return -1;

    ctx->crypto_mode = CRYPTO_MODE_PQC;
    ctx->profile_id = cfg->profile_id;
    ctx->policy_id = cfg->policy_id;
    ctx->wire_id = cfg->policy_wire_id;
    ctx->aes_bits = 256;
    ctx->initialized = true;

    if (g_static_key_len > 0) {
        memcpy(ctx->keys[KEY_SLOT_PREV], g_static_key, (size_t)g_static_key_len);
        memcpy(ctx->keys[KEY_SLOT_CURRENT], g_static_key, (size_t)g_static_key_len);
        memcpy(ctx->keys[KEY_SLOT_NEXT], g_static_key, (size_t)g_static_key_len);
    }
    return 0;
}
