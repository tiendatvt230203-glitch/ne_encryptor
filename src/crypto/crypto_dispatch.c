#include "../../inc/crypto/crypto_dispatch.h"

#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"

#include <string.h>
#include <unistd.h>

static int lookup_policy_index(const struct crypto_dispatch_ctx *dctx,
                               const struct crypto_policy *policies,
                               int policy_count,
                               int *index_by_wire_id,
                               uint8_t wire_id) {
    if (!policies || policy_count <= 0)
        return -1;

    if (dctx && index_by_wire_id) {
        int pi = index_by_wire_id[wire_id];
        if (pi >= 0 && pi < policy_count)
            return pi;
    }

    for (int pi = 0; pi < policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &policies[pi];
        if (!cp)
            continue;
        if ((uint8_t)cp->id == wire_id)
            return pi;
    }
    return -1;
}

int crypto_l3_extract_policy_id(const struct app_config *cfg,
                                uint8_t *pkt,
                                uint32_t pkt_len,
                                uint8_t *policy_id_out) {
    if (!cfg || !pkt || !policy_id_out || pkt_len < 14 + 20)
        return -1;

    if ((((uint16_t)pkt[12] << 8) | pkt[13]) != 0x0800)
        return -1;

    int l3_off = 14;
    int ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20 || pkt_len < (uint32_t)(l3_off + ip_hdr_len + 1))
        return -1;

    uint8_t marker = packet_crypto_get_fake_protocol();
    if (marker == 0)
        marker = 99;
    if (pkt[l3_off + 9] != marker)
        return -1;

    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = l3_off + ip_hdr_len;
    if (pkt_len < (uint32_t)(tunnel_off + tunnel_hdr_size))
        return -1;

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
            continue;
        const int ns = PACKET_CRYPTO_NONCE_BYTES;
        if (tunnel_off + ns + 1 >= (int)pkt_len)
            continue;
        if (pkt[tunnel_off + ns] != (uint8_t)cp->id)
            continue;
        *policy_id_out = (uint8_t)cp->id;
        return 0;
    }
    return -1;
}

int crypto_l4_extract_policy_id_ipv4(const struct app_config *cfg,
                                      uint8_t *pkt,
                                      uint32_t pkt_len,
                                      uint8_t *policy_id_out) {
    if (!cfg || !pkt || !policy_id_out)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    uint8_t ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + 4))
        return -1;

    uint8_t ip_proto = pkt[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return -1;
    int transport_off = l3_off + ip_hdr_len;
    if (transport_off >= (int)pkt_len)
        return -1;
    int wire_port_len = crypto_layer4_wire_port_len();

    int tunnel_off = transport_off + wire_port_len;
    if (tunnel_off >= (int)pkt_len)
        return -1;

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L4)
            continue;
        const int ns = PACKET_CRYPTO_NONCE_BYTES;
        if (tunnel_off + ns + 1 >= (int)pkt_len)
            continue;
        uint8_t magic = pkt[tunnel_off + ns + 1];
        if (magic != CRYPTO_L4_TUNNEL_MAGIC && magic != CRYPTO_L4_FRAG_MAGIC)
            continue;
        if (pkt[tunnel_off + ns] != (uint8_t)cp->id)
            continue;
        *policy_id_out = (uint8_t)cp->id;
        return 0;
    }

    return -1;
}

int crypto_decrypt_packet_auto_by_action(
    int crypto_enabled,
    struct app_config *cfg,
    struct crypto_dispatch_ctx *dctx,
    int action_layer,
    uint8_t *pkt, uint32_t *pkt_len,
    uint8_t *scratch, size_t scratch_sz) {

    if (!crypto_enabled || !cfg || !dctx || !dctx->base_ctx || !pkt || !pkt_len)
        return -1;

    if (cfg->policy_count <= 0) {
        crypto_apply_default_from_cfg(cfg);
        int new_len = packet_decrypt(dctx->base_ctx, pkt, *pkt_len);
        if (new_len < 0) return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    if (action_layer == POLICY_ACTION_ENCRYPT_L3) {
        uint8_t policy_id = 0;
        if (crypto_l3_extract_policy_id(cfg, pkt, *pkt_len, &policy_id) != 0)
            return 0;
        int pi = lookup_policy_index(dctx,
                                     dctx->policies, dctx->policy_count,
                                     dctx->policy_index_by_wire_id,
                                     policy_id);
        if (pi >= 0 && dctx->per_policy_ready && dctx->per_policy_ready[pi]) {
            const struct crypto_policy *cp = &dctx->policies[pi];
            crypto_apply_from_policy(cp);
            int new_len = crypto_layer3_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
            if (new_len >= 0 && new_len < (int)*pkt_len) {
                *pkt_len = (uint32_t)new_len;
                return 0;
            }
        }

        if (dctx->prev_grace_active && dctx->prev_policies && dctx->prev_policy_count > 0) {
            int ppi = lookup_policy_index(dctx,
                                          dctx->prev_policies, dctx->prev_policy_count,
                                          dctx->prev_policy_index_by_wire_id,
                                          policy_id);
            if (ppi >= 0 && dctx->prev_per_policy_ready && dctx->prev_per_policy_ready[ppi]) {
                const struct crypto_policy *cp_prev = &dctx->prev_policies[ppi];
                crypto_apply_from_policy(cp_prev);
                int new_len = crypto_layer3_decrypt(&dctx->prev_per_policy_ctx[ppi], pkt, *pkt_len);
                if (new_len >= 0 && new_len < (int)*pkt_len) {
                    *pkt_len = (uint32_t)new_len;
                    return 0;
                }
            }
        }
        return -1;
    }

    if (action_layer == POLICY_ACTION_ENCRYPT_L4) {
        int l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
        if (l3_off < 0)
            return 0;

        uint8_t ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
        if (ip_hdr_len < 20)
            return 0;
        if (*pkt_len < (uint32_t)(l3_off + ip_hdr_len + 4))
            return 0;

        uint8_t ip_proto = pkt[l3_off + 9];
        if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
            return 0;
        int transport_off = l3_off + ip_hdr_len;
        if (transport_off >= (int)*pkt_len)
            return 0;
        if (*pkt_len < (uint32_t)(transport_off + 4))
            return 0;


        uint8_t policy_id = 0;
        if (crypto_l4_extract_policy_id_ipv4(cfg, pkt, *pkt_len, &policy_id) != 0)
            return 0;
        int pi = lookup_policy_index(dctx,
                                     dctx->policies, dctx->policy_count,
                                     dctx->policy_index_by_wire_id,
                                     policy_id);
        if (pi >= 0 && dctx->per_policy_ready && dctx->per_policy_ready[pi]) {
            const struct crypto_policy *cp = &dctx->policies[pi];
            crypto_apply_from_policy(cp);
            int new_len = crypto_layer4_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
            if (new_len >= 0 && new_len < (int)*pkt_len) {
                *pkt_len = (uint32_t)new_len;
                return 0;
            }
        }

        if (dctx->prev_grace_active && dctx->prev_policies && dctx->prev_policy_count > 0) {
            int ppi = lookup_policy_index(dctx,
                                          dctx->prev_policies, dctx->prev_policy_count,
                                          dctx->prev_policy_index_by_wire_id,
                                          policy_id);
            if (ppi >= 0 && dctx->prev_per_policy_ready && dctx->prev_per_policy_ready[ppi]) {
                const struct crypto_policy *cp_prev = &dctx->prev_policies[ppi];
                crypto_apply_from_policy(cp_prev);
                int new_len = crypto_layer4_decrypt(&dctx->prev_per_policy_ctx[ppi], pkt, *pkt_len);
                if (new_len >= 0 && new_len < (int)*pkt_len) {
                    *pkt_len = (uint32_t)new_len;
                    return 0;
                }
            }
        }
        return -1;
    }


    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != action_layer)
            continue;
        if (!dctx->per_policy_ready || !dctx->per_policy_ready[pi])
            continue;

        if (*pkt_len > scratch_sz)
            return -1;

        if (scratch)
            memcpy(scratch, pkt, *pkt_len);

        crypto_apply_from_policy(cp);
        int new_len = -1;
        if (action_layer == POLICY_ACTION_ENCRYPT_L2)
            new_len = crypto_layer2_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
        else if (action_layer == POLICY_ACTION_ENCRYPT_L3)
            new_len = crypto_layer3_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
        else if (action_layer == POLICY_ACTION_ENCRYPT_L4)
            new_len = crypto_layer4_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
        if (new_len < 0) {
            if (scratch)
                memcpy(pkt, scratch, *pkt_len);
            continue;
        }
        if (new_len >= (int)*pkt_len) {
            if (scratch)
                memcpy(pkt, scratch, *pkt_len);
            continue;
        }
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    return -1;
}