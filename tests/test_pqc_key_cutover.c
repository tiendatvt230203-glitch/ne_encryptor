#include "crypto/packet_crypto.h"
#include "crypto_pqc_layer.h"
#include "traffic_crypto.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot)
{
    if (!ctx || slot < 0 || slot >= KEY_SLOT_COUNT)
        return NULL;
    return ctx->keys[slot];
}

static int encrypt_with(const uint8_t key[PQC_TRAFFIC_KEY_SZ],
                        const uint8_t nonce[CRYPTO_PQC_NONCE_BYTES],
                        uint8_t *buf, int len)
{
    crypto_pqc_sess_t sess = {
        .key = key,
        .aad = HARDCODED_AAD,
        .aad_len = 12,
    };
    int out_len = 0;

    assert(crypto_pqc_encrypt_payload(&sess, nonce, buf, len, &out_len) == 0);
    return out_len;
}

static void expect_decrypt(struct packet_crypto_ctx *ctx,
                           const uint8_t nonce[CRYPTO_PQC_NONCE_BYTES],
                           uint8_t *buf, int encrypted_len,
                           const uint8_t *plain, int plain_len)
{
    int out_len = 0;

    assert(crypto_pqc_decrypt_payload_resilient(
               ctx, nonce, buf, encrypted_len, &out_len) == 0);
    assert(out_len == plain_len);
    assert(memcmp(buf, plain, (size_t)plain_len) == 0);
}

int main(void)
{
    static const uint8_t plain[] = "PQC cutover must not drop this packet";
    const uint8_t nonce[CRYPTO_PQC_NONCE_BYTES] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    uint8_t old_key[PQC_TRAFFIC_KEY_SZ];
    uint8_t new_key[PQC_TRAFFIC_KEY_SZ];
    uint8_t buf[256];
    struct packet_crypto_ctx ctx;
    int encrypted_len;

    memset(old_key, 0x31, sizeof(old_key));
    memset(new_key, 0xa7, sizeof(new_key));
    assert(trf_pqc_init_global() == TRF_PQC_OK);

    /* Initiator still encrypts CURRENT=old, but has responder's new key in
     * NEXT before it sends READY. It must decrypt responder's new traffic. */
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.keys[KEY_SLOT_CURRENT], old_key, sizeof(old_key));
    memcpy(ctx.keys[KEY_SLOT_NEXT], new_key, sizeof(new_key));
    memcpy(buf, plain, sizeof(plain));
    encrypted_len = encrypt_with(new_key, nonce, buf, (int)sizeof(plain));
    expect_decrypt(&ctx, nonce, buf, encrypted_len, plain, (int)sizeof(plain));

    /* Responder has committed CURRENT=new and retains PREV=old, so packets
     * already in flight from the initiator continue to decrypt. */
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.keys[KEY_SLOT_CURRENT], new_key, sizeof(new_key));
    memcpy(ctx.keys[KEY_SLOT_PREV], old_key, sizeof(old_key));
    memcpy(buf, plain, sizeof(plain));
    encrypted_len = encrypt_with(old_key, nonce, buf, (int)sizeof(plain));
    expect_decrypt(&ctx, nonce, buf, encrypted_len, plain, (int)sizeof(plain));

    trf_pqc_cleanup();
    puts("PQC staged key cutover: ok");
    return 0;
}
