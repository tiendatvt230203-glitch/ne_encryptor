#ifndef ETH_PARSE_H
#define ETH_PARSE_H

#include <stddef.h>
#include <stdint.h>

#define ETH_L2_HDR_MAX  18

/** Vị trí byte bắt đầu của IPv4 (0x45): Trả về vị trí (ví dụ: 14, 18), -1 = Lỗi */
int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len);
/** Trả về độ dài tiền tố L2: 12 = Thường, 16 = VLAN, -1=Lỗi */
int crypto_eth_inner_et_off(const uint8_t *pkt, size_t pkt_len);
/** Độ dài của tiền tố trước EthenetType nếu là gói bình thường sẽ là 14B gói Vlan là 16B */
int crypto_eth_l2_prefix_len(const uint8_t *pkt, size_t pkt_len);
/** Check xem gói tin có phải IPv4 không: 1 = Đúng (True), 0 = Sai (False) */
int crypto_pkt_is_ipv4(const uint8_t *pkt, size_t pkt_len);
/** Ghi đè mã EtherType chuẩn của IPv4 (0x0800) vào vị trí chỉ định sau khi giải mã xong*/
void crypto_eth_set_ipv4_et(uint8_t *pkt, int inner_et_off);

#endif