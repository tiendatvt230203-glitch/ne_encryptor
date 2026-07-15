#ifndef FRAGMENT_H
#define FRAGMENT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "config.h"
#include "eth_parse.h"
#include "packet_crypto.h"
#include "crypto_layer4.h"
#include "crypto_layer2.h"
#include "crypto_layer3.h"

#define FRAG_L4_HDR_SIZE    4
#define FRAG_MTU            1500
/** Slot reassembly state đồng thời */
#define FRAG_TABLE_SIZE     4096
#define FRAG_TIMEOUT_NS     (200ULL * 1000000ULL)

struct frag_entry {
    uint16_t pkt_id;
    uint8_t  first[1600];            /** Buffer chứa frist */
    uint8_t  second[1600];           /** Buffer chứa second */
    uint32_t first_len;              /** Kích thước của mảnh frist mảnh lớn*/
    uint32_t second_len;             /** Kích thước của mảnh second mảnh nhỏ*/
    uint8_t eth_hdr[ETH_L2_HDR_MAX];  
    uint8_t eth_len;
    uint64_t timestamp_ns;            /** Thời gian chờ 2 mảnh cùng id cùng một gói tin gốc để thực hiện giải mã */
    uint8_t  got_first;               /** Cờ đánh dấu mảnh first nếu = 1 thì đã có mảnh 0 (frag_index = 0)*/
    uint8_t  got_second;              /** Cờ đánh dấu mảnh second nếu = 1 thì đã có mảnh 1 (frag_index = 1)*/
};

/** Mảng frag table */
struct frag_table {
    struct frag_entry entries[FRAG_TABLE_SIZE];
};

uint16_t frag_next_pkt_id(void);
void frag_set_mtu(uint32_t mtu);
uint32_t frag_get_mtu(void);

void frag_table_init(struct frag_table *ft);

void frag_table_gc_at(struct frag_table *ft, uint64_t now_ns);


static inline int frag_need_split(uint32_t pkt_len) {
    return (pkt_len + crypto_layer3_frag_meta_len()) > frag_get_mtu();
}


static inline int frag_need_split_l4(uint32_t pkt_len) {
    int overhead = crypto_layer4_wire_port_len() + packet_crypto_get_tunnel_hdr_size() +
                   FRAG_L4_HDR_SIZE;
    if (packet_crypto_get_mode() == 1)
        overhead += 16;
    return (pkt_len + overhead) > frag_get_mtu();
}


static inline int frag_need_split_l2(uint32_t pkt_len) {
    int overhead = crypto_layer2_frag_meta_len();
    return (pkt_len + overhead) > frag_get_mtu();
}

int frag_split_and_encrypt(struct packet_crypto_ctx *ctx,
                           uint8_t *pkt_data, uint32_t pkt_len,
                           size_t frag0_max, uint32_t *frag0_len,
                           uint8_t *frag1, size_t frag1_max,
                           uint32_t *frag1_len);

int frag_is_fragment(const struct app_config *cfg,
                     const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index);

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len);

int frag_split_and_encrypt_l4(struct packet_crypto_ctx *ctx,
                              uint8_t *pkt_data, uint32_t pkt_len,
                              size_t frag0_max, uint32_t *frag0_len,
                              uint8_t *frag1, size_t frag1_max,
                              uint32_t *frag1_len);

int frag_is_fragment_l4(const struct app_config *cfg,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index);

int frag_try_reassemble_l4(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len);

int frag_split_and_encrypt_l2(struct packet_crypto_ctx *ctx,
                              uint8_t *pkt_data, uint32_t pkt_len,
                              size_t frag0_max, uint32_t *frag0_len,
                              uint8_t *frag1, size_t frag1_max,
                              uint32_t *frag1_len);

int frag_is_fragment_l2(const struct app_config *cfg,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index);

int frag_try_reassemble_l2(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len);

#endif