#ifndef NE_MTU9K_CONFIG_H
#define NE_MTU9K_CONFIG_H

#include <stdint.h>

/* Fill before running — ice NICs on sep */
#define IF_LAN "enp1s0f0np0"
#define IF_WAN "enp2s0f0np0"

/*
 * 1 = L2 PQC (fake ethertype 0x104A + in-place crypto)
 * 0 = bypass forward
 * Pure L2 bridge: eth dst/src MACs are never rewritten.
 */
#ifndef MODE_L2_PQC
#define MODE_L2_PQC 1
#endif

#define L2_FAKE_ETHERTYPE 0x104Au

/*
 * Wire format: ethertype 0x104A + CBC ciphertext only.
 * No nonce / core_id / policy_id on the wire (IV is local/fixed).
 */
static const uint8_t HARD_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

#define NE_FRAME      4096u
#define NE_PKT_MAX    16384u
#define NE_N_FRAMES   65536u
#define NE_RING       8192u
#define NE_BATCH      64u
#define NE_FQ_PREFILL 1024u
#define NE_MAX_FRAGS  8u
#define NE_MAX_QUEUES 64

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XDP_USE_SG
#define XDP_USE_SG (1 << 4)
#endif
#ifndef XDP_PKT_CONTD
#define XDP_PKT_CONTD (1 << 0)
#endif

/* Distinct from production lib/lan.o — never share names */
#define SIMPLE_MTU          9000u
#define SIMPLE_WIRE_OVERHEAD 64u
#define SIMPLE_UDP_FRAG_MTU 9000u

#define MTU9K_LAN_BPF "lib/pqc9000_lan.o"
#define MTU9K_WAN_BPF "lib/pqc9000_wan.o"

#endif
