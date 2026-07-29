#include "pqc_handshake.h"
#include "l4pqc_crypto.h"

#include "../../../inc/core/config.h"

#include <string.h>

static uint8_t g_stub_key[PQC_TRAFFIC_KEY_SZ];
static int g_stub_key_ready;
static struct app_config g_stub_cfg;

void l4pqc_stub_set_key(const uint8_t *key, int len)
{
    if (!key || len <= 0 || len > PQC_TRAFFIC_KEY_SZ)
        return;
    memset(g_stub_key, 0, sizeof(g_stub_key));
    memcpy(g_stub_key, key, (size_t)len);
    g_stub_key_ready = 1;
}

void l4pqc_stub_cfg_init(uint8_t wire_id)
{
    memset(&g_stub_cfg, 0, sizeof(g_stub_cfg));
    g_stub_cfg.policy_count = 1;
    g_stub_cfg.policies[0].id = wire_id;
    g_stub_cfg.policies[0].action = POLICY_ACTION_ENCRYPT_L4;
    g_stub_cfg.policies[0].crypto_mode = CRYPTO_MODE_PQC;
    g_stub_cfg.policies[0].aes_bits = 256;
}

const struct app_config *l4pqc_stub_cfg(void)
{
    return &g_stub_cfg;
}

int sig_pqc_diversify_key(int profile_id, int policy_id, uint8_t *out_policy_key)
{
    (void)profile_id;
    (void)policy_id;
    if (!out_policy_key || !g_stub_key_ready)
        return -1;
    memcpy(out_policy_key, g_stub_key, PQC_TRAFFIC_KEY_SZ);
    return 0;
}

int sig_pqc_handshake_start(int profile_id, const char *wan_ifname, const char *peer_ip)
{
    (void)profile_id;
    (void)wan_ifname;
    (void)peer_ip;
    return 0;
}

void pqc_handshake_start_all_profiles(struct app_config *cfg)
{
    (void)cfg;
}
