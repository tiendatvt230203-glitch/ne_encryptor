#ifndef NE_MTU9K_CONFIG_H
#define NE_MTU9K_CONFIG_H

#include <stdint.h>

/* Fill before running */
#define IF_LAN "eth0"
#define IF_WAN "eth1"

/* Far-end MAC only. Local iface MACs come from the NIC. */
#define REMOTE_MAC { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 }

/*
 * 1 = L2 PQC (fake ethertype 0x104A + in-place crypto)
 * 0 = bypass forward
 */
#ifndef MODE_L2_PQC
#define MODE_L2_PQC 1
#endif

/* Default L2 encrypt marker (production pqc_l2_option) */
#define L2_FAKE_ETHERTYPE 0x104Au

#define L2_NONCE_BYTES   12
#define L2_GCM_TAG_BYTES 16

static const uint8_t HARD_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* Fixed nonce both sides — not written into the frame */
static const uint8_t HARD_NONCE[L2_NONCE_BYTES] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab
};

static const uint8_t HARD_AAD[8] = {
    0x54, 0x45, 0x53, 0x54, 0x5f, 0x41, 0x41, 0x44
};
#define HARD_AAD_LEN 12

#define NE_FRAME 16384u
#define NE_N_FRAMES   1572864u
#define NE_RING       8192u
#define NE_BATCH      64u
#define NE_FQ_PREFILL 4096u

#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif

#endif /* NE_MTU9K_CONFIG_H */
