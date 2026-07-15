#include "../../inc/crypto/crypto_policy_utils.h"

#include "../../inc/core/config.h"
#include "../../inc/crypto/packet_crypto.h"

#include <stddef.h>

void crypto_apply_default_from_cfg(const struct app_config *cfg) {
    if (!cfg)
        return;
    packet_crypto_set_mode(cfg->crypto_mode);
    packet_crypto_set_aes_bits(cfg->aes_bits);
    if (cfg->encrypt_layer == 3)
        packet_crypto_set_fake_protocol((uint8_t)(cfg->fake_protocol & 0xFF));
    packet_crypto_set_policy_id(0);

    packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
}

void crypto_apply_from_policy(const struct crypto_policy *cp) {
    if (!cp)
        return;

    packet_crypto_set_mode(cp->crypto_mode);
    packet_crypto_set_aes_bits(cp->aes_bits);

    if (cp->action == POLICY_ACTION_ENCRYPT_L2)
        packet_crypto_set_encrypt_layer(2);
    else if (cp->action == POLICY_ACTION_ENCRYPT_L3)
        packet_crypto_set_encrypt_layer(3);
    else if (cp->action == POLICY_ACTION_ENCRYPT_L4)
        packet_crypto_set_encrypt_layer(4);

    if (cp->action == POLICY_ACTION_ENCRYPT_L3) {
        uint8_t fp = packet_crypto_get_fake_protocol();
        packet_crypto_set_fake_protocol(fp ? fp : 99);
    }
    packet_crypto_set_policy_id((uint8_t)cp->id);
}