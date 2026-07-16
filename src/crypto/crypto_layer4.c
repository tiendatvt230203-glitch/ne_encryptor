#include "../../inc/crypto/crypto_layer4_internal.h"
#include "../../inc/core/config.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_pqc_layer.h"

void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L4_TUNNEL_MAGIC;
}

void l4_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L4_FRAG_MAGIC;
}

int l4_is_tunnel_header(const uint8_t *buf, int nonce_size) {
    if (buf[nonce_size + 1] != CRYPTO_L4_TUNNEL_MAGIC)
        return 0;
    if (!crypto_mode_is_pqc() && (buf[0] & 0x80) != 0)
        return 0;
    return 1;
}

int l4_get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto,
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
    return l4_get_transport_hdr_size(transport_hdr, ip_proto, remaining);
}

int crypto_layer4_wire_port_len(void) {
    return L4_WIRE_PORT_LEN;
}

int crypto_layer4_frag_meta_len(void) {
    int mode = packet_crypto_get_mode();
    int meta = L4_WIRE_PORT_LEN + packet_crypto_get_tunnel_hdr_size() + FRAG_L4_HDR_SIZE;

    if (mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC)
        meta += AES_GCM_TAG_SIZE;
    return meta;
}

void l4_fix_ipv4_totlen_and_cksum(uint8_t *packet, int l3_off, int ip_hdr_len,
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

void l4_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

void l4_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

/* ---------- Public dispatchers ---------- */

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    int l3_off;
    uint8_t ip_proto;
    int ip_hdr_len;
    int transport_off;
    size_t remaining;
    int transport_hdr_size;
    int plain_off;
    size_t plain_len;

    if (!ctx || !ctx->initialized || !packet)
        return -1;

    l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    ip_proto = packet[l3_off + 9];

    ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    transport_off = l3_off + ip_hdr_len;
    if (pkt_len < (size_t)transport_off)
        return -1;
    remaining = pkt_len - (size_t)transport_off;
    transport_hdr_size = l4_get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0)
        return (int)pkt_len;

    plain_off = transport_off + L4_WIRE_PORT_LEN;
    plain_len = pkt_len - (size_t)plain_off;
    if (plain_len == 0)
        return (int)pkt_len;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer4_ctr_encrypt(ctx, packet, pkt_len, l3_off, ip_hdr_len,
                                         plain_off, plain_len);
    case CRYPTO_MODE_GCM:
        return crypto_layer4_gcm_encrypt(ctx, packet, pkt_len, l3_off, ip_hdr_len,
                                         plain_off, plain_len);
    case CRYPTO_MODE_PQC:
        return crypto_layer4_pqc_encrypt(ctx, packet, pkt_len, l3_off, ip_hdr_len,
                                         plain_off, plain_len);
    default:
        return -1;
    }
}

int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    int l3_off;
    uint8_t ip_proto;
    int ip_hdr_len;
    int transport_off;
    int nonce_size;
    int tunnel_hdr_size;
    int tunnel_off;

    if (!ctx || !ctx->initialized || !packet)
        return -1;

    l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    ip_proto = packet[l3_off + 9];

    ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    transport_off = l3_off + ip_hdr_len;
    if (pkt_len < (size_t)transport_off)
        return -1;
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return (int)pkt_len;
    nonce_size = packet_crypto_get_nonce_size();
    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    tunnel_off = transport_off + L4_WIRE_PORT_LEN;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size) ||
        !l4_is_tunnel_header(packet + tunnel_off, nonce_size))
        return (int)pkt_len;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer4_ctr_decrypt(ctx, packet, pkt_len, l3_off, ip_hdr_len,
                                         transport_off, tunnel_off, tunnel_hdr_size, nonce_size);
    case CRYPTO_MODE_GCM:
        return crypto_layer4_gcm_decrypt(ctx, packet, pkt_len, l3_off, ip_hdr_len,
                                         transport_off, tunnel_off, tunnel_hdr_size, nonce_size);
    case CRYPTO_MODE_PQC:
        return crypto_layer4_pqc_decrypt(ctx, packet, pkt_len, l3_off, ip_hdr_len,
                                         transport_off, tunnel_off, tunnel_hdr_size);
    default:
        return -1;
    }
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

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer4_ctr_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                                         wire_ports, enc_plain, enc_plain_len,
                                                         pkt_id, frag_index, out_buf, out_max,
                                                         out_len);
    case CRYPTO_MODE_GCM:
        return crypto_layer4_gcm_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                                         wire_ports, enc_plain, enc_plain_len,
                                                         pkt_id, frag_index, out_buf, out_max,
                                                         out_len);
    case CRYPTO_MODE_PQC:
        return crypto_layer4_pqc_encrypt_fragment_single(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                                         wire_ports, enc_plain, enc_plain_len,
                                                         pkt_id, frag_index, out_buf, out_max,
                                                         out_len);
    default:
        return -1;
    }
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

    if (!ctx || !ctx->initialized || !packet || !out_len || ip_hdr_len < 20 ||
        frag0_plain_len < (uint32_t)ip_hdr_len + L4_WIRE_PORT_LEN)
        return -1;

    ip = packet + 14;
    /* Ports live in the transport header; save before sliding plaintext. */
    memcpy(wire_ports, packet + 14 + ip_hdr_len, L4_WIRE_PORT_LEN);

    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    tunnel_off = 14 + ip_hdr_len + L4_WIRE_PORT_LEN;
    enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer4_ctr_encrypt_fragment0_inplace(ctx, packet, ip_hdr_len,
                                                           frag0_plain_len, pkt_id, out_max,
                                                           out_len, ip, wire_ports, tunnel_off,
                                                           enc_off, tunnel_hdr_size);
    case CRYPTO_MODE_GCM:
        return crypto_layer4_gcm_encrypt_fragment0_inplace(ctx, packet, ip_hdr_len,
                                                           frag0_plain_len, pkt_id, out_max,
                                                           out_len, ip, wire_ports, tunnel_off,
                                                           enc_off, tunnel_hdr_size);
    case CRYPTO_MODE_PQC:
        return crypto_layer4_pqc_encrypt_fragment0_inplace(ctx, packet, ip_hdr_len,
                                                           frag0_plain_len, pkt_id, out_max,
                                                           out_len, ip, wire_ports, tunnel_off,
                                                           enc_off, tunnel_hdr_size);
    default:
        return -1;
    }
}

int crypto_layer4_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    int l3_off;
    uint8_t ip_proto;
    int ip_hdr_len;
    int transport_off;
    int nonce_size;
    int tunnel_hdr_size;
    int tunnel_off;

    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;

    l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return -1;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    ip_proto = packet[l3_off + 9];

    ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    transport_off = l3_off + ip_hdr_len;
    if (pkt_len < (size_t)transport_off)
        return -1;
    if (ip_proto != 6 && ip_proto != 17 && ip_proto != 1)
        return -1;
    nonce_size = packet_crypto_get_nonce_size();
    tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    tunnel_off = transport_off + L4_WIRE_PORT_LEN;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE))
        return -1;
    if (packet[tunnel_off + nonce_size + 1] != CRYPTO_L4_FRAG_MAGIC)
        return -1;

    l4_read_frag_tag(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    switch (packet_crypto_get_mode()) {
    case CRYPTO_MODE_CTR:
        return crypto_layer4_ctr_decrypt_fragment(ctx, packet, pkt_len, transport_off,
                                                  tunnel_off, tunnel_hdr_size, nonce_size);
    case CRYPTO_MODE_GCM:
        return crypto_layer4_gcm_decrypt_fragment(ctx, packet, pkt_len, transport_off,
                                                  tunnel_off, tunnel_hdr_size, nonce_size);
    case CRYPTO_MODE_PQC:
        return crypto_layer4_pqc_decrypt_fragment(ctx, packet, pkt_len, transport_off,
                                                  tunnel_off, tunnel_hdr_size);
    default:
        return -1;
    }
}
