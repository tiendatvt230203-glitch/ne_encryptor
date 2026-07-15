#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/core/config.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_pqc_layer.h"
#include <string.h>

#define L4_WIRE_PORT_LEN   4

static void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L4_TUNNEL_MAGIC;
}

static void l4_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L4_FRAG_MAGIC;
}

static int l4_is_tunnel_header(const uint8_t *buf, int nonce_size) {
    if (buf[nonce_size + 1] != CRYPTO_L4_TUNNEL_MAGIC)
        return 0;
    if (!crypto_mode_is_pqc() && (buf[0] & 0x80) != 0)
        return 0;
    return 1;
}

static int get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto,
                                  size_t remaining) {
    if (ip_proto == 6) {
        if (remaining < 20)
            return -1;
        int data_off = ((transport_hdr[12] >> 4) & 0x0F) * 4;
        if (data_off < 20 || (size_t)data_off > remaining)
            return -1;
        return data_off;
    }
    if (ip_proto == 17) {
        if (remaining < 8)
            return -1;
        return 8;
    }
    if (ip_proto == 1) {
        if (remaining < 4)
            return -1;
        return 4;
    }
    return -1;
}

int crypto_layer4_get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto,
                                         size_t remaining) {
    return get_transport_hdr_size(transport_hdr, ip_proto, remaining);
}

int crypto_layer4_wire_port_len(void) {
    return L4_WIRE_PORT_LEN;
}

int crypto_layer4_frag_meta_len(void) {
    int meta = L4_WIRE_PORT_LEN + packet_crypto_get_tunnel_hdr_size() + FRAG_L4_HDR_SIZE;
    if (crypto_mode_uses_gcm_tag())
        meta += AES_GCM_TAG_SIZE;
    return meta;
}

static void l4_fix_ipv4_totlen_and_cksum(uint8_t *packet, int l3_off, int ip_hdr_len,
                                         size_t ip_payload_len) {
    uint8_t *ip = packet + l3_off;
    uint16_t old_totlen = ((uint16_t)ip[2] << 8) | ip[3];
    uint16_t new_totlen = (uint16_t)(ip_hdr_len + ip_payload_len);
    (void)ip_hdr_len;

    if (old_totlen == new_totlen)
        return;
    ip[2] = (uint8_t)(new_totlen >> 8);
    ip[3] = (uint8_t)(new_totlen & 0xFF);
    crypto_ipv4_checksum_replace_word(ip, old_totlen, new_totlen);
}

#define L4_TCP_CKSUM_OFF  16
#define L4_UDP_LEN_OFF    4
#define L4_UDP_CKSUM_OFF  6

int crypto_layer4_fixup_packet(uint8_t *packet, size_t pkt_len) {
    if (!packet || pkt_len < 14 + 20)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return -1;

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    if (pkt_len < (size_t)(l3_off + ip_hdr_len + 8))
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    size_t transport_len = pkt_len - (size_t)transport_off;
    uint8_t ip_proto = packet[l3_off + 9];

    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, transport_len);

    if (ip_proto == 17) {
        uint8_t *udp = packet + transport_off;
        uint16_t udp_len = (uint16_t)transport_len;
        udp[L4_UDP_LEN_OFF] = (uint8_t)(udp_len >> 8);
        udp[L4_UDP_LEN_OFF + 1] = (uint8_t)(udp_len & 0xFF);
        udp[L4_UDP_CKSUM_OFF] = 0;
        udp[L4_UDP_CKSUM_OFF + 1] = 0;
        uint16_t udp_cksum = crypto_calc_udp_checksum(packet + l3_off, ip_hdr_len,
                                                      udp, (int)transport_len);
        udp[L4_UDP_CKSUM_OFF] = (uint8_t)(udp_cksum >> 8);
        udp[L4_UDP_CKSUM_OFF + 1] = (uint8_t)(udp_cksum & 0xFF);
    } else if (ip_proto == 6 && transport_len >= 20) {
        uint8_t *tcp = packet + transport_off;
        tcp[L4_TCP_CKSUM_OFF] = 0;
        tcp[L4_TCP_CKSUM_OFF + 1] = 0;
        uint16_t tcp_cksum = crypto_calc_tcp_checksum(packet + l3_off, ip_hdr_len,
                                                      tcp, (int)transport_len);
        tcp[L4_TCP_CKSUM_OFF] = (uint8_t)(tcp_cksum >> 8);
        tcp[L4_TCP_CKSUM_OFF + 1] = (uint8_t)(tcp_cksum & 0xFF);
    }
    return 0;
}

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    if (pkt_len < (size_t)transport_off)
        return -1;
    size_t remaining = pkt_len - (size_t)transport_off;
    int transport_hdr_size = get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0)
        return (int)pkt_len;

    int plain_off = transport_off + L4_WIRE_PORT_LEN;
    size_t plain_len = pkt_len - (size_t)plain_off;
    if (plain_len == 0)
        return (int)pkt_len;

    if (crypto_mode_is_pqc()) {
        const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
        int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;
        int tunnel_off = plain_off;
        int enc_off = tunnel_off + tunnel_hdr_size;

        if (crypto_pqc_sess_load(ctx, &pqc) != 0)
            return -1;
        if (crypto_pqc_generate_nonce(nonce) != 0)
            return -1;

        memmove(packet + enc_off, packet + plain_off, plain_len);
        if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off, (int)plain_len, &new_len) != 0)
            return -1;

        l4_write_tunnel_header(packet + tunnel_off, nonce, pqc_nonce_size);

        int total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
        size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len;
        l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
        return (int)(pkt_len + (size_t)total_overhead);
    }

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    uint32_t counter = packet_crypto_next_counter();

    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    int tunnel_off = plain_off;
    int enc_off = tunnel_off + tunnel_hdr_size;

    /* Memmove once, then encrypt (same order as L3 / L2). */
    memmove(packet + enc_off, packet + plain_off, plain_len);
    l4_write_tunnel_header(packet + tunnel_off, nonce, nonce_size);

    if (is_gcm) {
        uint8_t tag[AES_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off, (int)plain_len,
                                   tag) != 0)
            return -1;
        memcpy(packet + enc_off + plain_len, tag, AES_GCM_TAG_SIZE);
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)plain_len) != 0)
            return -1;
    }

    int total_overhead = tunnel_hdr_size + (is_gcm ? AES_GCM_TAG_SIZE : 0);
    size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + plain_len;
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);

    return (int)(pkt_len + (size_t)total_overhead);
}

int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    if (pkt_len < (size_t)transport_off)
        return -1;
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return (int)pkt_len;
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + L4_WIRE_PORT_LEN;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size) ||
        !l4_is_tunnel_header(packet + tunnel_off, nonce_size))
        return (int)pkt_len;

    if (crypto_mode_is_pqc()) {
        const int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int dec_len = 0;
        int enc_off = tunnel_off + tunnel_hdr_size;

        memcpy(nonce, packet + tunnel_off, pqc_nonce_size);
        if (crypto_pqc_sess_load(ctx, &pqc) != 0)
            return -1;
        if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                       (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
            return -1;

        memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
        {
            int total_overhead = tunnel_hdr_size + AES_GCM_TAG_SIZE;
            int new_len = (int)(pkt_len - (size_t)total_overhead);
            size_t ip_payload_len = (size_t)(new_len - l3_off - ip_hdr_len);
            l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
            return new_len;
        }
    }

    uint8_t nonce[16];
    memcpy(nonce, packet + tunnel_off, nonce_size);
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];
    size_t total_after_tunnel = pkt_len - (size_t)enc_off;

    if (is_gcm) {
        if (total_after_tunnel < AES_GCM_TAG_SIZE)
            return -1;
        enc_len = total_after_tunnel - AES_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);
    } else {
        enc_len = total_after_tunnel;
    }

    int total_overhead = tunnel_hdr_size + (is_gcm ? AES_GCM_TAG_SIZE : 0);
    uint8_t *work_ptr = packet + enc_off;

    if (is_gcm) {
        /* Match L3: AEAD authenticates; try CURRENT only. */
        const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
        if (!key)
            return -1;
        if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0)
            return -1;
        memmove(packet + transport_off + L4_WIRE_PORT_LEN, work_ptr, enc_len);
        {
            int new_len = (int)(pkt_len - (size_t)total_overhead);
            size_t ip_payload_len = (size_t)(new_len - l3_off - ip_hdr_len);
            /* Payload bit-identical to pre-encrypt; L4 checksum stays valid. */
            l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
            return new_len;
        }
    }

    /* CTR: trial PREV/NEXT needs a ciphertext snapshot. */
    {
        uint8_t backup[2048];
        int has_backup = (enc_len <= sizeof(backup));
        int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

        if (has_backup)
            memcpy(backup, work_ptr, enc_len);

        for (int k = 0; k < KEY_SLOT_COUNT; k++) {
            const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
            uint8_t iv[AES128_IV_SIZE];

            if (!key)
                continue;
            if (k > 0 && has_backup)
                memcpy(work_ptr, backup, enc_len);

            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0)
                continue;

            memmove(packet + transport_off + L4_WIRE_PORT_LEN, work_ptr, enc_len);
            {
                int new_len = (int)(pkt_len - (size_t)total_overhead);
                size_t ip_payload_len = (size_t)(new_len - l3_off - ip_hdr_len);
                l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
                return new_len;
            }
        }
    }
    return -1;
}

static void l4_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

static void l4_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int crypto_layer4_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len) {
    if (!ctx || !ctx->initialized || !out_buf || !out_len || !wire_ports || !enc_plain)
        return -1;
    if (enc_plain_len == 0)
        return -1;

    if (crypto_mode_is_pqc()) {
        int nonce_size = CRYPTO_PQC_NONCE_BYTES;
        int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
        int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + AES_GCM_TAG_SIZE;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;
        size_t need = (size_t)(14 + ip_hdr_len + L4_WIRE_PORT_LEN + total_overhead + enc_plain_len);

        if (need > out_max)
            return -1;

        int offset = 0;
        memcpy(out_buf, eth_hdr, 14);
        offset += 14;
        memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
        offset += ip_hdr_len;
        memcpy(out_buf + offset, wire_ports, L4_WIRE_PORT_LEN);
        offset += L4_WIRE_PORT_LEN;

        if (crypto_pqc_sess_load(ctx, &pqc) != 0)
            return -1;
        if (crypto_pqc_generate_nonce(nonce) != 0)
            return -1;

        int tunnel_off = offset;
        int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
        memmove(out_buf + enc_off, enc_plain, enc_plain_len);

        l4_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
        l4_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

        if (crypto_pqc_encrypt_payload(&pqc, nonce, out_buf + enc_off, (int)enc_plain_len, &new_len) != 0)
            return -1;

        size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len;
        l4_fix_ipv4_totlen_and_cksum(out_buf, 14, ip_hdr_len, ip_payload_len);
        *out_len = (uint32_t)(enc_off + new_len);
        return 0;
    }

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + (is_gcm ? AES_GCM_TAG_SIZE : 0);
    size_t need = (size_t)(14 + ip_hdr_len + L4_WIRE_PORT_LEN + total_overhead + enc_plain_len);
    if (need > out_max)
        return -1;

    int offset = 0;
    memcpy(out_buf, eth_hdr, 14);
    offset += 14;
    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;
    memcpy(out_buf + offset, wire_ports, L4_WIRE_PORT_LEN);
    offset += L4_WIRE_PORT_LEN;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    packet_crypto_update_keys(ctx);
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    int tunnel_off = offset;
    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    memmove(out_buf + enc_off, enc_plain, enc_plain_len);

    l4_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
    l4_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

    if (is_gcm) {
        uint8_t tag[AES_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, out_buf + enc_off, (int)enc_plain_len,
                                   tag) != 0)
            return -1;
        memcpy(out_buf + enc_off + enc_plain_len, tag, AES_GCM_TAG_SIZE);
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, out_buf + enc_off, (int)enc_plain_len) != 0)
            return -1;
    }

    size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + enc_plain_len;
    l4_fix_ipv4_totlen_and_cksum(out_buf, 14, ip_hdr_len, ip_payload_len);

    *out_len = (uint32_t)(enc_off + enc_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0));
    return 0;
}

int crypto_layer4_encrypt_fragment0_inplace(struct packet_crypto_ctx *ctx,
    uint8_t *packet, int ip_hdr_len, uint32_t frag0_plain_len,
    uint16_t pkt_id, size_t out_max, uint32_t *out_len)
{
    uint8_t *ip;
    uint8_t wire_ports[L4_WIRE_PORT_LEN];
    int tunnel_off;
    int enc_off;
    int tunnel_hdr_size;
    size_t need;

    if (!ctx || !ctx->initialized || !packet || !out_len || ip_hdr_len < 20 ||
        frag0_plain_len < (uint32_t)ip_hdr_len + L4_WIRE_PORT_LEN)
        return -1;

    ip = packet + 14;
    /* Ports live in the transport header; save before sliding plaintext. */
    memcpy(wire_ports, packet + 14 + ip_hdr_len, L4_WIRE_PORT_LEN);

    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    tunnel_off = 14 + ip_hdr_len + L4_WIRE_PORT_LEN;
    enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;

    if (crypto_mode_is_pqc()) {
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int new_len = 0;
        int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + AES_GCM_TAG_SIZE;

        need = (size_t)enc_off + frag0_plain_len + AES_GCM_TAG_SIZE;
        if (need > out_max)
            return -1;

        memmove(packet + enc_off, ip, frag0_plain_len);
        memcpy(packet + 14 + ip_hdr_len, wire_ports, L4_WIRE_PORT_LEN);

        if (crypto_pqc_sess_load(ctx, &pqc) != 0)
            return -1;
        if (crypto_pqc_generate_nonce(nonce) != 0)
            return -1;

        l4_write_tunnel_header_frag(packet + tunnel_off, nonce, CRYPTO_PQC_NONCE_BYTES);
        l4_write_frag_tag(packet + tunnel_off + tunnel_hdr_size, pkt_id, 0);

        if (crypto_pqc_encrypt_payload(&pqc, nonce, packet + enc_off,
                                       (int)frag0_plain_len, &new_len) != 0)
            return -1;

        l4_fix_ipv4_totlen_and_cksum(packet, 14, ip_hdr_len,
                                        L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len);
        *out_len = (uint32_t)(enc_off + new_len);
        return 0;
    }

    {
        int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
        int nonce_size = packet_crypto_get_nonce_size();
        int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + (is_gcm ? AES_GCM_TAG_SIZE : 0);
        uint32_t counter;
        uint8_t nonce[16];
        int nonce_len;
        const uint8_t *key;

        need = (size_t)enc_off + frag0_plain_len + (is_gcm ? AES_GCM_TAG_SIZE : 0);
        if (need > out_max)
            return -1;

        memmove(packet + enc_off, ip, frag0_plain_len);
        memcpy(packet + 14 + ip_hdr_len, wire_ports, L4_WIRE_PORT_LEN);

        counter = packet_crypto_next_counter();
        crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);
        packet_crypto_update_keys(ctx);
        key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
        if (!key)
            return -1;

        l4_write_tunnel_header_frag(packet + tunnel_off, nonce, nonce_size);
        l4_write_frag_tag(packet + tunnel_off + tunnel_hdr_size, pkt_id, 0);

        if (is_gcm) {
            uint8_t tag[AES_GCM_TAG_SIZE];
            if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off,
                                       (int)frag0_plain_len, tag) != 0)
                return -1;
            memcpy(packet + enc_off + frag0_plain_len, tag, AES_GCM_TAG_SIZE);
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)frag0_plain_len) != 0)
                return -1;
        }

        l4_fix_ipv4_totlen_and_cksum(packet, 14, ip_hdr_len,
                                        L4_WIRE_PORT_LEN + (size_t)total_overhead + frag0_plain_len);
        *out_len = (uint32_t)need;
        return 0;
    }
}

int crypto_layer4_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return -1;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    if (pkt_len < (size_t)transport_off)
        return -1;
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return -1;
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + L4_WIRE_PORT_LEN;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE))
        return -1;
    if (packet[tunnel_off + nonce_size + 1] != CRYPTO_L4_FRAG_MAGIC)
        return -1;

    l4_read_frag_tag(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    if (crypto_mode_is_pqc()) {
        int pqc_nonce_size = CRYPTO_PQC_NONCE_BYTES;
        int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
        crypto_pqc_sess_t pqc;
        byte nonce[CRYPTO_PQC_NONCE_BYTES];
        int dec_len = 0;

        memcpy(nonce, packet + tunnel_off, pqc_nonce_size);
        if (crypto_pqc_sess_load(ctx, &pqc) != 0)
            return -1;
        if (crypto_pqc_decrypt_payload(&pqc, nonce, packet + enc_off,
                                       (int)(pkt_len - (size_t)enc_off), &dec_len) != 0)
            return -1;
        memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
        return (int)(transport_off + L4_WIRE_PORT_LEN + dec_len);
    }

    uint8_t nonce[16];
    memcpy(nonce, packet + tunnel_off, nonce_size);
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    size_t total_after = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES_GCM_TAG_SIZE];

    if (is_gcm) {
        if (total_after < AES_GCM_TAG_SIZE)
            return -1;
        enc_len = total_after - AES_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES_GCM_TAG_SIZE);
    } else {
        enc_len = total_after;
    }

    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    if (has_backup)
        memcpy(backup, packet + enc_off, enc_len);

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key)
            continue;

        uint8_t *work = packet + enc_off;
        if (k > 0 && has_backup)
            memcpy(work, backup, enc_len);

        if (is_gcm) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work, (int)enc_len, tag) != 0)
                continue;
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work, (int)enc_len) != 0)
                continue;
        }

        memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, enc_len);
        return (int)(transport_off + L4_WIRE_PORT_LEN + enc_len);
    }
    return -1;
}