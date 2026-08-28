# Kế hoạch tích hợp song song MTU 1500 và 9000

## 1. Mục tiêu

Cho phép dataplane xử lý đồng thời frame Ethernet chuẩn (~1514 B, MTU 1500) và jumbo (~9014 B, MTU 9000) trên cùng source code, cùng process và cùng tập worker.

Ràng buộc bắt buộc:

- WAN vẫn attach native XDP ở `XDP_FLAGS_DRV_MODE`.
- AF_XDP vẫn dùng `XDP_COPY | XDP_USE_NEED_WAKEUP`; không chuyển sang SKB/generic XDP hoặc zero-copy.
- Đường 1500 B giữ nguyên fast path hiện tại: một AF_XDP descriptor, không coalesce, không cấp phát buffer jumbo và không thay đổi logic mã hóa hiện có.
- Jumbo chỉ đi vào nhánh mới khi RX/TX thực sự là nhiều descriptor (`XDP_PKT_CONTD`).
- Một WAN có thể MTU 1500 trong khi WAN khác MTU 9000. Quyết định split/mã hóa phải dựa trên WAN đích, không dùng một MTU toàn cục.

Trong tài liệu này gọi driver là **i40e**, theo source và tài liệu hiện có của dự án. Trước triển khai cần xác nhận bằng `ethtool -i <wan-iface>`; nếu driver thực tế là biến thể khác, cần xác minh lại hỗ trợ native XDP multi-buffer tương đương.

## 2. Điều kiện nền tảng

| Hạng mục | Điều kiện triển khai |
| --- | --- |
| Kernel | Linux 6.8 hoặc mới hơn; kernel 5.15 hiện tại không đủ i40e XDP multi-buffer cho MTU 9000. |
| NIC | i40e hỗ trợ `NETDEV_XDP_ACT_RX_SG` khi native XDP được attach. |
| BPF | Program phải khai báo `SEC("xdp.frags")` / `BPF_F_XDP_HAS_FRAGS`. |
| AF_XDP | Giữ `XDP_COPY`, bổ sung `XDP_USE_SG`; vẫn giữ `XDP_USE_NEED_WAKEUP`. |
| UMEM | Giữ chunk 2048 B: 1500 B dùng 1 chunk, 9000 B dùng chuỗi chunk. |
| Interface | Chỉ các WAN cần jumbo đặt `ip link set dev <if> mtu 9000`; WAN 1500 giữ nguyên. |

Không bật `legacy-rx` của i40e: path đó không đủ an toàn cho frame 9000 khi XDP hoạt động.

## 3. Kiến trúc đích

```text
NIC i40e (MTU 9000) -- native XDP drv, xdp.frags -- AF_XDP COPY + SG
       frame 1500  --------------------------------> 1 descriptor -> fast path hiện tại
       frame 9000  --------------------------------> CONTD...final -> coalesce -> jumbo path

NIC i40e (MTU 1500) -- native XDP drv, xdp.frags -- AF_XDP COPY + SG
       frame <=1500 -------------------------------> 1 descriptor -> fast path hiện tại
```

`xdp.frags` không phải một mode chỉ dành cho jumbo: program này vẫn xử lý packet linear 1500 B. `XDP_USE_SG` cũng không làm thay đổi format packet nhỏ; descriptor của packet 1500 vẫn có `options == 0`.

## 4. Phân luồng packet và nguyên tắc bảo toàn băng thông 1500 B

| Loại packet | RX AF_XDP | Xử lý userspace | TX AF_XDP |
| --- | --- | --- | --- |
| <= 2048 B (bao gồm 1500 + overhead PQC) | 1 descriptor, `options == 0` | Dùng nguyên `recv_queue`/`ne_packet` hiện tại | 1 descriptor hiện tại |
| > 2048 B, jumbo | Chuỗi descriptor có `XDP_PKT_CONTD` | Ghép tuyến tính vào buffer jumbo, rồi đưa một `ne_packet` vào pipeline | Chuỗi descriptor SG hoặc gather trước TX |

Không đưa packet 1500 qua buffer coalesce, không thay `NE_FRAME=2048`, không tăng mọi UMEM chunk lên 16K. Nhờ vậy cost copy, cache footprint và số descriptor của traffic 1500 không đổi.

## 5. Các hạng mục triển khai

### Giai đoạn A — kiểm tra môi trường và feature gate

1. Xác nhận kernel >= 6.8, driver, firmware và `NETDEV_XDP_ACT_RX_SG`.
2. Thử attach một `xdp.frags` tối thiểu ở `XDP_FLAGS_DRV_MODE` trên một WAN lab MTU 9000.
3. Tạo capability check lúc khởi động: nếu interface MTU > 1500 nhưng kernel/NIC/socket không hỗ trợ RX SG thì fail rõ ràng, không âm thầm drop jumbo.
4. Giữ feature flag runtime, ví dụ `xdp_sg_enabled`; mặc định tắt cho đến khi hoàn tất thử nghiệm.

Điểm chạm chính: `src/core/iface/profile_xdp.c`, `src/core/iface/xdp_interface.c`.

### Giai đoạn B — BPF nhận cả frame nhỏ và jumbo

1. Đổi section của program trong `bpf/lan.c` và `bpf/wan.c` từ `SEC("xdp")` sang `SEC("xdp.frags")`.
2. Bỏ hoặc nới điều kiện `PATH_MTU=1500` đang DROP frame lớn trong `bpf/lan.c`; vẫn giữ các check an toàn cho Ethernet/VLAN/ARP/IPv4 và redirect theo queue.
3. Không dùng `ctx->data_end - ctx->data` để kết luận tổng độ dài jumbo, vì đó chỉ là linear head. Khi cần độ dài đầy đủ, dùng helper tương thích `bpf_xdp_get_buff_len`.
4. Xác minh program chỉ parse header ở vùng linear; nếu cần đọc dữ liệu ngoài vùng linear, dùng helper load bytes phù hợp thay vì dereference trực tiếp.

Tiêu chí: packet 1500 tiếp tục redirect đúng như trước; packet 9000 không bị BPF drop vì length check.

### Giai đoạn C — AF_XDP SG nhưng vẫn COPY + drv

1. Trong `xdp_interface.c`, giữ `XDP_COPY | XDP_USE_NEED_WAKEUP` và chỉ thêm `XDP_USE_SG` khi feature gate bật.
2. Giữ UMEM chunk `NE_FRAME=2048` và cơ chế fill/completion queue hiện tại.
3. Xử lý RX descriptor theo state machine:
   - `options == 0`: publish ngay như code hiện tại.
   - `XDP_PKT_CONTD`: tích lũy desc cho đến desc cuối, kiểm tra số segment và tổng length, rồi coalesce.
4. Nếu batch kết thúc giữa chuỗi `CONTD`, giữ state sang poll kế tiếp; không drop hoặc nhầm packet kế bên.
5. Có giới hạn cứng số segment, tổng length và timeout assembler để chống cạn UMEM do chuỗi lỗi.

Tiêu chí: hot path 1500 không có branch coalesce nặng; jumbo tạo đúng một `ne_packet` hoàn chỉnh.

### Giai đoạn D — buffer và TX jumbo

1. Bổ sung pool/buffer jumbo giới hạn riêng cho packet đã coalesce. Không dùng `opt_entry`/buffer reassembly 1600 B của path split 1500 cho jumbo nguyên packet.
2. Bảo đảm ownership và release của toàn bộ địa chỉ UMEM trong mọi nhánh lỗi/coalesce fail.
3. TX giữ một descriptor với packet <= `NE_FRAME`; với jumbo, triển khai chuỗi TX descriptor có `XDP_PKT_CONTD` hoặc gather có kiểm soát.
4. Xử lý TX backpressure theo **packet**, không chỉ theo descriptor: không gửi nửa chuỗi jumbo khi ring không còn đủ slot.

Tiêu chí: frame jumbo đi hết RX → crypto → TX, không leak chunk và không làm nghẽn queue 1500.

### Giai đoạn E — MTU theo WAN đích và crypto

Hiện `resolve_runtime_frag_mtu()` trong `src/core/forwarder/forwarder.c` lấy MTU nhỏ nhất toàn cục, còn `crypto_option_get_mtu()` là một giá trị global. Cơ chế này bắt buộc phải thay trước khi bật mix 1500/9000.

1. Lưu MTU thực tế trong runtime state của từng WAN/tx slot.
2. Chọn WAN/tx slot trước khi quyết định `need_split`.
3. Truyền MTU của WAN đích vào PQC encrypt/split thay vì đọc global MTU.
4. WAN 1500: giữ nguyên điều kiện split, MSS clamp và buffer join hiện tại.
5. WAN 9000: nếu `plaintext + PQC overhead <= WAN MTU`, gửi một GCM frame, không đưa vào bảng fragment/join.
6. Nếu scheduler có thể đổi WAN sau khi quyết định split, pin packet vào WAN đã chọn đến khi transmit xong.

Điểm chạm dự kiến: `src/core/forwarder/forwarder.c`, `src/crypto/common/crypto_option_router.c`, `src/crypto/pqc/pqc_l2_option.c`, `src/core/dataplane/local_egress.c`, `src/core/dataplane/wan_ingress.c`.

### Giai đoạn F — quan sát, giới hạn và rollout

Thêm counter theo interface/queue:

- RX packet 1500 fast path, RX SG packet, số segment jumbo, coalesce success/fail.
- TX jumbo, TX thiếu descriptor, completion backlog.
- Drop theo lý do: BPF length/parser, SG không hỗ trợ, assembler overflow/timeout, jumbo pool exhausted.
- Số UDP split theo từng WAN MTU để xác nhận WAN 9000 thực sự không bị ép theo 1500.

Rollout theo thứ tự:

1. Lab: một WAN MTU 9000, traffic 1500 và 9000 trộn cùng queue.
2. Canary: bật SG trên một WAN, WAN còn lại 1500; feature flag vẫn có thể tắt.
3. Production: mở dần WAN 9000; theo dõi pps, throughput, drop và CPU của traffic 1500 so với baseline.

Rollback: tắt feature flag SG, trả MTU WAN về 1500 và attach lại BPF linear cũ. Không thay đổi schema DB hoặc format policy để rollback được độc lập.

## 6. Kế hoạch kiểm thử chấp nhận

| Nhóm | Kịch bản | Kết quả bắt buộc |
| --- | --- | --- |
| Compatibility | NIC MTU 9000 nhận mix 64 B, 1500 B, 1514 B | Tất cả đi fast path 1 desc, throughput 1500 không giảm đáng kể so với baseline. |
| Jumbo RX | UDP/TCP 8K–9K qua WAN 9000 | Không BPF drop, coalesce đúng length và không leak UMEM. |
| Mixed WAN | Một WAN 1500, một WAN 9000; scheduler gửi packet xen kẽ | Packet chọn WAN 1500 vẫn split; packet chọn WAN 9000 không split nếu vừa MTU. |
| Crypto | PQC encrypt/decrypt packet 1500 và 9000 | Header, nonce, key rotation và reorder vẫn đúng. |
| Loss/reorder | Drop/mất một segment AF_XDP SG, TX ring gần đầy | Không publish packet lỗi, toàn bộ chunk được trả lại, 1500 không kẹt sau jumbo lỗi. |
| Soak | Traffic mix liên tục + rekey PQC | Không tăng dần RAM/UMEM starvation, không downtime khi đổi key. |
| Rollback | Tắt SG khi không có jumbo | 1500 hoạt động lại bằng path cũ mà không cần đổi policy/DB. |

## 7. Rủi ro cần chặn trước merge

1. Bật MTU 9000 khi còn kernel 5.15: i40e native XDP có thể từ chối attach; đây là blocker, không phải lỗi logic userspace.
2. Bật `xdp.frags` nhưng thiếu `XDP_USE_SG`: jumbo sẽ bị drop trước userspace.
3. Chỉ tăng global crypto MTU thành 9000: packet bị chọn vào WAN 1500 có thể vượt MTU và mất gói.
4. Cho mọi packet qua coalesce: sẽ làm giảm hiệu năng traffic 1500, trái mục tiêu.
5. Gửi một phần chuỗi TX jumbo: peer nhận frame hỏng; TX phải reserve đủ descriptors trước submit.
6. Dùng buffer fragment 1500 cho jumbo: overflow hoặc drop do các cấu trúc hiện tại được sizing quanh 1600/2048 B.

## 8. Tiêu chí hoàn tất

Tính năng chỉ được coi là hoàn tất khi một binary duy nhất, cùng `drv + XDP_COPY`, chạy ổn định cả WAN MTU 1500 và WAN MTU 9000; packet 1500 vẫn đi 1 descriptor fast path; packet 9000 đi SG path; và crypto chọn MTU theo WAN đích thay vì global minimum.

Tài liệu nền chi tiết về các giả định hiện trạng nằm tại `DATAPLANE_AI_TRAINING.md`, mục 20.0a–20.12.

## 9. Runbook thực thi cho AI — làm theo đúng thứ tự này

Phần này là chỉ dẫn triển khai, không phải mô tả ý tưởng. Không làm giai đoạn sau khi gate của giai đoạn trước chưa pass. Không trộn refactor PQC/key-management vào nhánh MTU.

### 9.1 Bước 0 — chụp baseline và khóa hành vi 1500 hiện tại

Trước thay đổi, ghi lại theo từng NIC/queue:

```text
kernel, driver, firmware, MTU, số queue
pps/throughput/CPU với frame 64 B, 512 B, 1500 B
drop XDP, RX ring full, FQ empty, TX ring full, CQ pending
UDP split rate, UDP reassembly timeout, crypto failure
```

Chạy workload 1500 hiện có trước và sau từng giai đoạn. Một thay đổi chỉ được giữ khi packet `options == 0` vẫn đi cùng đường code cũ và baseline 1500 không có regression đáng kể. Đừng lấy throughput jumbo để che regression pps của 1500.

### 9.2 Bước 1 — thêm capability model, chưa bật jumbo

Sửa `inc/core/iface/interface.h` và `src/core/iface/xdp_interface.c` để mỗi `struct ne_iface` biết:

```c
uint32_t mtu;                 /* SIOCGIFMTU thực tế của NIC */
bool xdp_sg_enabled;          /* chỉ true khi toàn bộ capability pass */
bool jumbo_enabled;           /* mtu > 1500 && xdp_sg_enabled */
```

Thêm feature flag cấu hình, ví dụ `xdp_sg_enabled=0` mặc định. Khi flag tắt, binary phải tạo XSK y hệt hiện tại: `XDP_COPY | XDP_USE_NEED_WAKEUP`, program XDP linear cũ, MTU >1500 phải bị từ chối bằng thông báo rõ ràng.

Khi flag bật trên một NIC MTU 9000, kiểm tra theo thứ tự:

1. Kernel có UAPI `XDP_USE_SG` và program BPF có thể load với `BPF_F_XDP_HAS_FRAGS`.
2. NIC/driver báo RX scatter-gather XDP; attach native drv thực sự thành công.
3. XSK bind `XDP_COPY | XDP_USE_NEED_WAKEUP | XDP_USE_SG` thành công.
4. Nếu một điều kiện sai: không attach half-working rồi để kernel drop jumbo. Hủy setup NIC đó hoặc yêu cầu hạ MTU về 1500.

**Gate B1:** build và khởi động 1500 không đổi; startup log hiện rõ `mtu`, `drv`, `copy`, `sg` cho từng interface.

### 9.3 Bước 2 — BPF frags, vẫn chưa sửa userspace SG

Đổi `bpf/lan.c` và `bpf/wan.c` sang `SEC("xdp.frags")`; đảm bảo loader đặt flag tương ứng trước `bpf_object__load`. Giữ `XDP_FLAGS_DRV_MODE` ở `profile_xdp.c`.

Sửa check frame length theo quy tắc:

```text
Packet 1500: vẫn validate Ethernet/VLAN/IPv4 như trước, vẫn redirect xsks_map.
Packet jumbo: không DROP chỉ vì lớn hơn 1514.
Header: chỉ dereference byte chứng minh nằm trong linear head.
Tổng length: dùng bpf_xdp_get_buff_len(ctx), không dùng data_end - data.
```

Không cố parse toàn bộ L4 payload trong BPF. BPF chỉ cần phân loại/redirect an toàn; crypto và parser sâu vẫn nằm userspace sau khi packet đã được coalesce.

Trong giai đoạn này, feature flag SG phải vẫn tắt ở production: `xdp.frags` có thể xử lý 1500, nhưng native jumbo tới XSK khi socket chưa SG sẽ bị drop. Chỉ test jumbo trên lab khi giai đoạn RX SG đã sẵn sàng.

**Gate B2:** attach drv với program `xdp.frags` thành công ở NIC MTU 9000; traffic 1500 pass theo baseline.

### 9.4 Bước 3 — định nghĩa ownership packet trước khi sửa RX

`struct ne_packet` hiện chỉ có `addr` là offset UMEM. Điều đó chỉ biểu diễn được một chunk 2048 B, không thể biểu diễn packet 9000 đã ghép. Không được nhét một pointer heap vào `addr` và gọi `ne_packet_data()` như cũ: sẽ biến pointer thành offset UMEM và corrupt memory.

Thêm storage class rõ ràng, ví dụ:

```c
enum ne_packet_storage {
    NE_PACKET_UMEM = 0,       /* addr là offset UMEM, <= NE_FRAME */
    NE_PACKET_JUMBO = 1,      /* jumbo_buf là buffer từ jumbo pool */
};

struct ne_packet {
    uint64_t addr;
    uint32_t len;
    uint8_t storage;
    /* dir/wan_idx/local_idx/tx_slot giữ nguyên */
};
```

Thêm helper duy nhất và thay mọi dereference trực tiếp:

```c
uint8_t *ne_packet_data_ref(struct ne_pair *p, const struct ne_packet *pkt);
void ne_packet_release(struct ne_pair *p, struct ne_packet *pkt);
```

Với `NE_PACKET_UMEM`, helper dùng `ne_packet_data(p, pkt->addr)` và release trả `ne_frame_free`. Với `NE_PACKET_JUMBO`, `addr` là handle của jumbo pool (không phải pointer tùy ý), helper lấy base của jumbo pool và release trả block pool. Không để caller tự quyết định cách free.

Các điểm phải chuyển sang helper trước khi bật jumbo:

- `src/core/dataplane/local_egress.c`
- `src/core/dataplane/wan_ingress.c`
- `src/core/dataplane/arp_bridge.c`
- `src/core/dataplane/packet_util.c`
- `src/core/iface/xdp_interface.c` (RX, TX, reclaim/error path)
- tất cả code clone/copy `struct ne_packet` và các ring queue.

**Gate B3:** không còn dataplane call nào giả định mọi `addr` đều là UMEM. Test 1500 vẫn chỉ tạo `NE_PACKET_UMEM`.

### 9.5 Bước 4 — thiết kế RAM và pool jumbo trước khi viết coalesce

Giữ `NE_FRAME=2048`. Với `NE_N_FRAMES=1,048,576`, UMEM hiện dùng chính xác:

```text
1,048,576 × 2,048 = 2,147,483,648 B = 2 GiB
```

Một Ethernet frame jumbo tối đa cần budget không phải đúng 9000 mà là frame wire + headroom. Chọn block **16 KiB** (power-of-two), đủ cho Ethernet/VLAN, PQC overhead, alignment và frame đến khoảng 9K. Một RX 9000 với UMEM 2048 dùng khoảng `ceil(9014 / 2048) = 5` descriptor/chunk.

Không lấy 5 chunk UMEM để giữ lâu sau RX: các chunk đó phải được trả FQ ngay sau khi copy, nếu không jumbo sẽ làm cạn UMEM và ảnh hưởng 1500. Coalesce từ 5 chunk UMEM vào một block 16 KiB rồi return cả 5 chunk về pool/FQ ngay trong RX stage.

Pool khởi điểm an toàn cho rollout (phải có config, không hard-code):

| Cấu hình | Jumbo pool | RAM pool | Ý nghĩa |
| --- | ---: | ---: | --- |
| Lab | 256 block × 16 KiB | 4 MiB | đủ debug, dễ thấy overflow |
| Canary | 1,024 block × 16 KiB | 16 MiB | burst jumbo vừa phải |
| Production khởi điểm | 4,096 block × 16 KiB | 64 MiB | đủ cho queue/burst, cần đo thực tế |
| Production lớn | 8,192 block × 16 KiB | 128 MiB | chỉ bật khi telemetry chứng minh cần |

Tổng RAM dataplane ban đầu xấp xỉ **2 GiB UMEM + jumbo pool + ring/crypto/reassembly**. Với 4,096 block là tối thiểu khoảng **2.06 GiB** chỉ tính UMEM và jumbo pool. Không đổi `NE_N_FRAMES` khi chưa có số liệu FQ starvation; giảm nó làm 1500 dễ drop, tăng nó tốn thêm 2 KiB cho mỗi frame.

Đặt high-watermark, counter `jumbo_pool_empty`, và policy khi pool hết: drop **chỉ jumbo packet mới**, trả toàn bộ RX chunk, ghi counter; tuyệt đối không block crypto worker và không lấy buffer của packet 1500.

**Gate B4:** có jumbo pool giới hạn, ownership rõ, không leak qua ASan/soak test; traffic 1500 không cấp phát từ pool này.

### 9.6 Bước 5 — RX SG coalesce state machine

Mỗi `struct ne_xsk_queue` cần RX assembler state riêng vì một chuỗi `XDP_PKT_CONTD` có thể kết thúc ở lần poll kế tiếp:

```text
IDLE
  descriptor options == 0        -> publish UMEM packet ngay
  descriptor has XDP_PKT_CONTD   -> allocate jumbo block, copy first, state=ASSEMBLING

ASSEMBLING
  descriptor has XDP_PKT_CONTD   -> append, giữ state
  descriptor final (no CONTD)    -> append, validate, publish one JUMBO packet, state=IDLE
  error/oversize/pool exhausted  -> discard chain, return every UMEM addr, state=DROP_UNTIL_FINAL

DROP_UNTIL_FINAL
  descriptor has CONTD           -> return addr, continue
  descriptor final               -> return addr, state=IDLE
```

Quy tắc bắt buộc:

1. Copy `d->len` byte từ chunk UMEM đúng offset; validate `d->len <= NE_FRAME` và tổng `<= NE_JUMBO_MAX_FRAME` trước copy.
2. Một descriptor `options == 0` khi assembler đang `ASSEMBLING` là malformed: abort chain, release cả hai; không coi nó là packet mới trước khi state đã reset.
3. `NE_BATCH_SIZE=64` đếm **descriptor**, không phải packet. Không cắt state ở descriptor thứ 64.
4. Chỉ publish vào `ne_ring` sau final descriptor thành công. Pipeline crypto không được nhìn thấy nửa packet.
5. Sau copy mỗi descriptor, release chunk về UMEM ownership. Không submit FQ từ worker khác không sở hữu queue; dùng cơ chế refill queue hiện tại để trả frame đúng owner.
6. Không timeout chuỗi đang được kernel deliver bình thường giữa poll; timeout chỉ dùng để dọn state bị kẹt khi queue bị reset/teardown, và phải release pool block.

Fast path phải nằm đầu vòng lặp:

```c
if (likely(d->options == 0 && asm_state == IDLE)) {
    /* nguyên code 1500: ghi ne_packet UMEM, không copy */
    continue;
}
/* chỉ packet SG hoặc malformed mới vào slow path */
```

**Gate B5:** mix 1500/jumbo trên cùng RX ring; 1500 vẫn 1 descriptor, jumbo publish đúng một job, `ne_pool_free_count()` ổn định qua soak.

### 9.7 Bước 6 — TX: chọn chiến lược, không gửi nửa jumbo

Chọn và ghi rõ một chiến lược trước code:

**Khuyến nghị:** TX scatter-gather từ jumbo block bằng nhiều TX descriptor, mỗi descriptor trỏ tới UMEM chunk đã được copy từ jumbo block. Điều này giữ XDP COPY, không cần zero-copy, và không ép toàn bộ pool thành 16 KiB.

Thay `tx_drain_queue()` hiện tại vì nó clamp `d->len` về `max_frame` (2048), khiến jumbo bị cắt im lặng. Thuật toán mới:

1. Peek job đầu ring, tính `segments = ceil(job.len / NE_FRAME)` nếu `NE_PACKET_JUMBO`, ngược lại `1`.
2. Gọi `xsk_prod_nb_free()` với **segments**, không phải số job. Nếu thiếu slot, không pop job.
3. Với jumbo, lấy đủ `segments` UMEM frames trước; nếu lấy thiếu, trả các frame đã lấy và không pop job.
4. Reserve đủ `segments`, copy từng lát <=2048 từ jumbo block sang UMEM frame, set `d->addr`, `d->len`; đặt `XDP_PKT_CONTD` cho mọi descriptor trừ descriptor cuối.
5. Submit cả chuỗi một lần, sau đó mới pop/release jumbo job ownership phù hợp. UMEM TX frames chỉ được free khi completion queue trả về.
6. Với `NE_PACKET_UMEM` <=2048, giữ exact code path 1 descriptor cũ.

Batch TX phải đặt giới hạn theo descriptor (ví dụ 32/64) nhưng không được tách một packet jumbo qua hai submit khi API/protocol không cho phép. Nếu batch còn 3 slot mà jumbo cần 5, để jumbo lại queue cho lượt sau.

**Gate B6:** tx 9000 không bị clamp 2048, không còn missing/CQ leak, TX 1500 vẫn 1 desc và order trong ring được giữ.

### 9.8 Bước 7 — sửa scheduler trước crypto để MTU theo WAN đích

Hiện `local_egress.c` gọi `crypto_option_need_split()` trước khi `wan_dp` trở thành quyết định không đổi, còn `crypto_option_get_mtu()` là global. Đây là thứ tự sai cho mix WAN.

Thay đổi contract theo thứ tự:

```text
1. Classify flow/policy.
2. Scheduler chọn wan_dp + tx_slot một lần.
3. Lấy effective_wire_mtu từ fwd->pair.wans[wan_dp].mtu.
4. Encrypt/split dùng effective_wire_mtu.
5. Gắn wan_dp/tx_slot vào job; từ đây không scheduler lại packet đó.
6. Push đúng ring của WAN đã chọn.
```

Không giữ API `crypto_option_need_split(id, proto, pkt_len)` cho PQC nếu API đó còn đọc MTU global. Đổi thành một trong hai dạng rõ ràng:

```c
int crypto_option_need_split_for_mtu(crypto_option_id id,
                                     crypto_proto_class proto,
                                     uint32_t pkt_len, uint32_t wire_mtu);
int crypto_option_split_for_mtu(..., uint32_t wire_mtu, ...);
```

`l2_udp_need_split()` và `l2_split()` trong `pqc_l2_option.c` phải nhận `wire_mtu` argument; xóa dependency `crypto_option_get_mtu()` khỏi path per-packet. `crypto_option_set_mtu()` chỉ có thể giữ tạm cho compatibility/default, không được quyết định packet trong mix WAN.

### 9.9 Bước 8 — ma hóa/giải mã theo loại packet

#### Bypass

- Không mã hóa, không thêm PQC overhead.
- Chọn WAN trước, kiểm tra `job.len <= WAN MTU + L2 header`; WAN 1500 không được nhận packet 9000 bypass.
- Nếu ingress jumbo đi ra WAN 1500, policy phải drop có counter hoặc dùng cơ chế fragmentation L3 riêng đã được phê duyệt; không tự truncate.

#### PQC UDP ra WAN 1500

Giữ nguyên format/logic hiện có. Với overhead `OPT_FRAG_META_LEN = 47`:

```text
pkt_len + 47 <= 1500  -> L2_UDP_KIND_FULL, 1 GCM frame, vẫn có epoch/seq cho reorder
pkt_len + 47 > 1500   -> FRAG0 + FRAG1, 2 GCM frame, dùng opt_table để join ở peer
```

`FRAG0` chứa IPv4 + UDP header + phần đầu payload; `FRAG1` chứa phần payload còn lại. Không đổi marker/shim, nonce, datagram_id, epoch, sequence, timeout join hay UDP reorder của path 1500.

#### PQC UDP ra WAN 9000

```text
pkt_len + 47 <= wan_mtu (9000) -> L2_UDP_KIND_FULL, một GCM frame, không vào split/reassembly table
pkt_len + 47 > wan_mtu          -> chưa hỗ trợ mặc định; drop + counter hoặc thiết kế fragmentation nhiều mảnh riêng
```

Không dùng `opt_table` 1500/1600 cho jumbo `FULL`: packet đã decrypt là full IPv4 packet và đi thẳng vào UDP reorder bằng `epoch/seq`. Vì packet jumbo đang ở jumbo block, buffer output của decrypt/reorder cũng phải chấp nhận storage class jumbo; không ghi 9000 byte vào buffer 2048.

#### PQC UDP nhận từ WAN

1. RX SG coalesce hoàn tất trước parser marker/PQC.
2. Nếu marker PQC không có: Bypass/ARP xử lý theo policy; không cố decrypt.
3. Nếu `L2_UDP_KIND_FULL`: decrypt tại chỗ trong storage tương ứng, set `(epoch, seq)`, chuyển UDP reorder.
4. Nếu `FRAG0`/`FRAG1`: đây là path MTU 1500 cũ; chỉ gọi reassembly khi tổng length nằm trong giới hạn `opt_entry`. Không dùng reassembly 1500 để ghép một jumbo SG packet.
5. Sau reorder/join, forward local: local interface MTU 1500 phải có rule rõ ràng (MSS hoặc drop/fragment policy). Không được phát 9000 trực tiếp ra NIC 1500.

#### PQC TCP

TCP không dùng L2 UDP split/reassembly. Cơ chế chính là MSS clamp **theo đường đi thực tế** trước khi TCP data lớn được tạo:

```text
MSS cap = WAN MTU - IPv4 header length - TCP header length - PQC wire overhead
```

- TCP flow đã pin WAN 1500: clamp theo 1500 và overhead PQC, giữ đúng hành vi hiện tại.
- TCP flow pin WAN 9000: có thể clamp theo 9000 và overhead PQC nếu cả hai đầu LAN/WAN đều cho phép jumbo; nếu egress phía local chỉ 1500, vẫn clamp 1500.
- Không dùng hằng `CRYPTO_OPT_FRAG_MTU_DEFAULT` trong `local_egress.c`/`wan_ingress.c` cho clamp sau khi có mix WAN. Truyền path MTU đã chọn.
- Nếu scheduler hiện per-packet với nhiều WAN MTU khác nhau, TCP phải **flow-pin theo MTU nhỏ nhất của các WAN có thể được dùng cho flow đó**, hoặc pin flow vào một WAN cố định. Không thể quảng bá MSS 9000 rồi gửi segment kế tiếp qua WAN 1500.

#### ARP, ICMP, OSPF và non-UDP/TCP

Giữ logic PQC/bypass hiện có, nhưng validate final wire length theo WAN đã chọn. Không đưa chúng vào UDP split table. Nếu packet lớn hơn WAN MTU, drop + counter cho đến khi có thiết kế protocol-specific được duyệt.

### 9.10 Bước 9 — hướng truyền 9000 đến LAN 1500 phải có chính sách

Một NIC MTU 9000 có thể nhận packet 9000; việc decrypt thành công không có nghĩa local egress MTU 1500 truyền được packet đó. Chọn một policy explicit trước rollout:

| Ingress | Egress | Hành động ban đầu an toàn |
| --- | --- | --- |
| WAN 9000 | LAN 9000 | forward jumbo nguyên packet |
| WAN 9000 | LAN 1500 | TCP đã MSS clamp: không phát sinh jumbo; UDP jumbo: drop + MTU counter, hoặc triển khai IPv4 fragmentation ở một task riêng |
| WAN 1500 | LAN 9000 | forward packet đã được join/decrypt; không tự tạo jumbo |
| WAN 1500 | LAN 1500 | giữ nguyên |

Không thêm IP fragmentation vào cùng PR với XDP SG/PQC MTU. Nó thay đổi semantics, MTU discovery và security surface. Đợt đầu chỉ hỗ trợ end-to-end jumbo cho path có cả ingress/egress đủ MTU; mixed direction phải bị chặn có quan sát.

### 9.11 Bước 10 — thứ tự merge và gate bắt buộc

| PR | Nội dung | Không được làm trong PR đó | Gate merge |
| --- | --- | --- | --- |
| 1 | Capability/config/log MTU per iface | Không xdp.frags/SG | 1500 build + baseline pass |
| 2 | BPF `xdp.frags`, bỏ DROP 1514 an toàn | Không userspace SG production | drv attach lab + 1500 pass |
| 3 | `ne_packet` storage abstraction + jumbo pool | Không publish SG | ownership/release test pass |
| 4 | RX SG assembler/coalesce | Không TX jumbo/crypto MTU | mixed RX + no leak |
| 5 | TX SG + backpressure | Không per-WAN crypto MTU | 9K L2 loop test + 1500 regression test |
| 6 | Scheduler pin + MTU per WAN API | Không thay PQC format | 1500/9000 mixed WAN routing test |
| 7 | PQC UDP/TCP integration | Không IP fragmentation | crypto + rekey + soak pass |
| 8 | Telemetry/canary/rollback | Không schema DB | production acceptance pass |

Mỗi PR phải giữ `xdp_sg_enabled=0` hoạt động. Khi feature flag tắt, binary phải hành xử như phiên bản 1500 trước dự án này.

### 9.12 Checklist cuối cùng trước bật production

- [ ] Kernel >=6.8 và i40e native drv `xdp.frags` attach pass trên từng WAN jumbo.
- [ ] XSK vẫn log `XDP_COPY`; có thêm `XDP_USE_SG`, không có `XDP_ZEROCOPY`.
- [ ] 1500 RX/TX đúng một descriptor; counter fast path tăng, counter coalesce không tăng cho traffic 1500.
- [ ] Jumbo RX/TX có số segment đúng, không truncation ở 2048.
- [ ] MTU được lấy theo `wan_dp` đã pin; không còn global minimum chi phối PQC split/MSS.
- [ ] UDP 1500: FULL/split/reassembly/reorder y nguyên; UDP 9000: FULL một GCM khi vừa MTU.
- [ ] TCP không thể đổi từ WAN 9000 sang WAN 1500 sau khi đã quảng bá MSS jumbo.
- [ ] Jumbo pool, UMEM pool, CQ/FQ counts ổn định trong soak; mọi drop trả đủ ownership.
- [ ] WAN 9000 -> LAN 1500 có drop counter/policy rõ, không silent truncate.
- [ ] Feature flag rollback hoạt động và test lại path 1500 sau rollback.

## 10. Gộp băng thông khi có cả 1500 và 9000 — byte-aware scheduler

### 10.1 Kết luận audit hiện trạng (phải sửa trước khi bật jumbo)

Hiện tại không được coi UI bandwidth là chính xác theo byte:

1. Core legacy `window_bytes`, bảng flow mutex/GC và các API `flow_table_get_wan*` đã được gỡ vì không có caller dataplane.
2. `flow_table_pick_wan_per_packet()` và `flow_table_pick_wan_per_flow_packet()` còn lại dùng smooth WRR với **mỗi datagram là một đơn vị**, không phải một byte. Với traffic parse được 5-tuple (`flow_ok=true`), `fwd_wan_pick_for_local()` hiện gọi biến thể *per-flow state* nhưng vẫn gọi nó cho **mỗi datagram**; state chỉ làm phase WRR riêng cho flow, không làm flow sticky/window.
3. `wan.window_size` vẫn là dữ liệu compatibility ở loader DB (DB/schema nằm ngoài phạm vi cleanup core) nhưng không còn consumer trong dataplane. UI không được hiển thị nó như một scheduler đang hoạt động.

Ví dụ UI nhập WAN0/WAN1 = 50/50:

```text
WRR theo packet:  1 packet 9000 -> WAN0, 1 packet 1500 -> WAN1
Byte wire gần đúng: WAN0 = 9000 B, WAN1 = 1500 B
Kết quả: WAN0 ~86%, WAN1 ~14%, dù UI là 50/50.
```

Do đó chỉ nâng MTU/XDP mà giữ scheduler cũ là sai yêu cầu. Bước 7 của phần trước phải mở rộng thành byte-aware scheduling dưới đây.

### 10.2 Contract UI mới, không mơ hồ

Không cần đổi schema DB để định nghĩa contract; chỉ dùng các field UI đã có khi chúng tồn tại. UI/backend phải thể hiện đúng ý nghĩa sau:

| Field UI | Ý nghĩa bắt buộc | Đơn vị accounting |
| --- | --- | --- |
| `bandwidth_weight_percent` / `weight` | Tỷ phần **wire bytes transmit** mục tiêu của WAN trong profile. Không cần tổng đúng 100; scheduler chuẩn hóa theo tổng weight dương. `0` vẫn là ARP-only. | Byte trên wire sau PQC/split, gồm Ethernet/PQC overhead. |
| `perpacket` | `ON`: chọn WAN cho từng **datagram gốc**, nhưng lựa chọn theo byte-aware, không theo số packet. `OFF`: giữ WAN cho một flow-window rồi mới chọn lại. | Không thay đổi nghĩa của weight. |
| `window_kb` | Chỉ áp dụng khi `perpacket=OFF`: số **wire bytes** tối đa một flow giữ WAN hiện tại trước khi được chọn WAN lại. Không phải số packet và không phải buffer reorder. | `window_kb * 1024`, clamp tối thiểu 1 jumbo frame. |

`perpacket=ON` là mode cần dùng để gộp đầy hai đường. `window_kb` trong mode này chỉ là metric/telemetry optional, **không được âm thầm đổi scheduler sang sticky**.

Nếu UI hiện không có toggle `perpacket` hoặc không trả `window_kb`, phải ghi rõ default trong log/config; không được giả vờ một giá trị database chưa load đang có hiệu lực.

### 10.3 Đơn vị charge chuẩn: wire bytes của một datagram gốc

Mọi quyết định cân bằng và counter UI dùng cùng một đại lượng:

```text
charge_bytes = tổng d->len sẽ được submit ra một WAN
               cho đúng một datagram gốc
```

| Policy / kết quả | `charge_bytes` |
| --- | --- |
| Bypass | Ethernet frame length thực tế gửi ra WAN. |
| PQC UDP FULL (1500 hoặc 9000) | `len` sau `crypto_option_encrypt`. |
| PQC UDP split ra WAN 1500 | `frag0_len + frag1_len`; charge **một lần**, không charge lại tail fragment. |
| PQC TCP/ICMP/OSPF | `len` sau encrypt. |
| Packet drop trước enqueue | 0; reservation phải rollback. |

Không dùng plaintext length làm accounting cuối cùng, vì PQC overhead và UDP split làm lệch tỷ lệ. Không dùng packet count, UMEM descriptor count, hay byte decrypt inbound để so với weight UI outbound.

Để chọn WAN trước khi mã hóa, thêm hàm dự đoán thuần (không ghi state):

```c
uint32_t crypto_option_estimate_wire_len(crypto_option_id id,
                                         crypto_proto_class proto,
                                         uint32_t plain_len,
                                         uint32_t wan_mtu);
```

Hàm này phải dùng chính công thức/format với encrypt và split:

- UDP 1500 `FULL`/`FRAG0+FRAG1` được dự đoán đúng tổng wire length.
- UDP 9000 `FULL` được dự đoán một frame.
- Bypass trả plain Ethernet wire length.

Sau encrypt, luôn reconcile bằng actual `len` hoặc `l1+l2`. Nếu difference khác 0 thì điều chỉnh reservation trước khi commit; đồng thời tăng counter `sched_estimate_error_bytes`. Mục tiêu sau soak là error bằng 0 hoặc có lý do được ghi rõ.

### 10.4 Thuật toán bắt buộc cho `perpacket=ON`: weighted least-wire-byte

Không dùng round-robin theo packet nữa. Với mỗi profile, duy trì state scheduler theo WAN live:

```c
struct wan_byte_sched {
    _Atomic uint64_t reserved_wire_bytes[MAX_INTERFACES];
    _Atomic uint64_t committed_wire_bytes[MAX_INTERFACES];
    _Atomic uint64_t dropped_reserved_bytes[MAX_INTERFACES];
    uint64_t epoch_start_ns;
};
```

Khi có một datagram gốc với candidate WAN `i`, tính `estimate_i` theo **MTU của WAN i**, rồi chọn WAN có normalized projected service nhỏ nhất:

```text
score_i = (reserved_wire_bytes[i] + estimate_i) / weight_i
chọn i có score_i nhỏ nhất, chỉ trong WAN live, weight_i > 0, còn TX capacity
```

So sánh bằng cross multiplication 128-bit, không dùng floating point:

```text
(reserved_i + estimate_i) * weight_best
    < (reserved_best + estimate_best) * weight_i
```

Ngay sau khi chọn, atomically reserve `estimate_i`. Nếu nhiều crypto worker cùng chọn, race chỉ tạo sai lệch ngắn hạn; reservation làm các lựa chọn sau thấy tải đã được hứa. Khi encrypt/push thành công, cộng actual vào `committed_wire_bytes`; khi encrypt fail, queue full hoặc policy drop, subtract reservation và tăng `dropped_reserved_bytes`.

Pseudo-flow bắt buộc:

```text
parse + policy
  -> build live WAN candidates
  -> estimate wire size cho TỪNG candidate (MTU 1500/9000 có thể khác)
  -> byte_scheduler_reserve(candidate, estimate) => wan_dp + reservation
  -> encrypt/split theo wan_dp đã pin
  -> push đủ một datagram (FULL hoặc cặp FRAG0/FRAG1)
       success: reconcile reservation với actual, commit
       failure: rollback reservation, free toàn bộ frame/buffer
```

Không chuyển WAN sau encrypt chỉ vì ring đầy: packet đã được format theo MTU WAN đã pin. Nếu rollback rồi retry candidate khác, phải encrypt lại từ plaintext immutable copy; đợt đầu nên drop + counter để tránh reuse ciphertext/frame sai. Đặc biệt không được gửi `FRAG0` WAN0 và `FRAG1` WAN1.

Với UI 50/50 và mix 9000/1500, thuật toán sẽ đưa nhiều packet 1500 hơn vào WAN đang thiếu byte, cho đến khi **tổng byte wire** hai WAN xấp xỉ bằng nhau. Đây là kết quả đúng; số packet/descriptors giữa WAN sẽ không còn bằng nhau.

### 10.5 `perpacket=OFF`: window byte thực sự, không phải window giả

Mode này không nhằm đạt stripe tối đa; nó giảm reorder bằng cách giữ một flow trên một WAN trong một khoảng byte.

Tạo state flow-window mới, tách biệt với smooth-WRR cache hiện có:

```c
int current_wan;
uint64_t window_wire_bytes;       /* đã commit trong phase hiện tại */
uint64_t window_limit_wire_bytes; /* WAN/window_kb tại lúc chọn phase */
uint64_t mtu_class;               /* bảo vệ TCP không đổi MSS/path */
```

Luồng xử lý:

1. Flow mới: byte scheduler chọn WAN, lưu `current_wan`, `window_limit_wire_bytes = window_kb * 1024` của WAN/profile đó.
2. Mỗi datagram commit thành công: tăng `window_wire_bytes` bằng **actual wire bytes**.
3. Khi `window_wire_bytes >= window_limit_wire_bytes`, chỉ packet **kế tiếp** mới được chọn WAN lại; reset counter sau khi reservation mới commit.
4. Drop không làm tăng window. ARP không vào flow/window scheduler.
5. Clamp `window_limit_wire_bytes` tối thiểu `NE_JUMBO_MAX_FRAME` (16 KiB) để một packet 9000 không khiến state lật nhiều lần do window quá nhỏ.

Với TCP, không đổi WAN giữa các MTU class sau khi MSS đã clamp. Hai lựa chọn an toàn:

- pin TCP hết lifetime flow vào một WAN; hoặc
- chỉ cho TCP chọn lại trong nhóm WAN cùng effective path MTU/MSS.

Không dùng `window_kb` để cứ N packet đổi WAN: packet 9000 và 1500 phải tiêu thụ window theo byte actual.

### 10.6 Nạp và validate `window_kb` từ UI

Audit phải xác nhận query DB/API hiện có thực sự trả field `window_kb`. Source hiện đang set `wan->window_size = WAN_REORDER_WINDOW_KB * 1024`, nên đây là việc cần làm rõ trước code scheduler:

1. Nếu cột/field UI đã tồn tại: mở rộng loader để parse nó, validate số nguyên, đổi sang bytes với overflow check, rồi log `window_kb` theo WAN.
2. Nếu UI không gửi field: dùng default rõ ràng, ví dụ `10240 KiB`, và UI phải hiển thị đó là default chứ không hiển thị giá trị người dùng chưa được áp dụng.
3. `window_kb=0`: reject config hoặc định nghĩa `0 = perpacket only`; không để chia/modulo zero hoặc sticky vĩnh viễn không chủ ý.
4. Đừng dùng `WAN_REORDER_WINDOW_KB` để gọi là bandwidth window nếu nó đồng thời dùng cho UDP reorder; tách tên/config để tránh người vận hành đổi reorder window nhưng vô tình đổi bonding behavior.

Việc này có thể chỉ cần đọc field đang có; không yêu cầu thay đổi `schema.sql`. Nếu field chưa tồn tại, dừng ở default/validation và yêu cầu quyết định UI/schema riêng, không tự tạo cột.

### 10.7 Queue pressure, failover và weight UI

Byte scheduler chỉ chọn giữa candidate `live && weight > 0 && tx_has_room`.

- Nếu WAN đầy ring: không reserve nó trong lượt này; ghi `scheduler_excluded_tx_full`. Khi có room, nó tự được chọn lại vì cumulative bytes của nó thấp hơn.
- Nếu WAN down/drain: bỏ candidate và **không** phân phối lại bằng packet count. Tỷ lệ được chuẩn hóa lại trên weight của WAN còn live.
- Khi UI đổi weight: giữ cumulative byte state sẽ làm convergence chậm. Tạo epoch mới: snapshot telemetry cũ, reset `reserved/committed` logical scheduler về 0 cho pool weight mới, rồi dùng cơ chế blend thời gian hiện có ở `wan_scheduler.c` để thay weight dần. Không reset khi vẫn còn reservation chưa finalize; đợi reservation count về 0 hoặc giữ hai epoch song song.
- Weight 0: không đưa data vào byte scheduler; ARP bridge vẫn giữ hành vi riêng hiện tại.

### 10.8 Counter/CLI bắt buộc để đối chiếu UI

Thêm counter outbound theo profile/WAN, resettable theo epoch:

```text
ui_weight
target_share = weight / sum(live positive weight)
wire_bytes_committed
wire_bytes_tx_completed
reserved_bytes
estimate_error_bytes
packets, descriptors, full_udp, split_datagrams, jumbo_datagrams
tx_ring_full_exclusions, reservation_rollbacks, drops
actual_share = wire_bytes_tx_completed / sum(all WAN tx completed)
share_error_pp = (actual_share - target_share) * 100
```

UI/CLI phải hiển thị cả **target** và **actual wire-byte share**; không lấy packet count làm “băng thông”. Đối với PQC split, `split_datagrams=1` nhưng `descriptors/frames=2` là bình thường.

Đo acceptance theo hai cửa sổ:

- Cửa sổ ngắn: tối thiểu 10 MiB đã transmit hoặc 10 giây.
- Cửa sổ dài: tối thiểu 1 GiB đã transmit hoặc 5 phút.

Trong điều kiện hai WAN không bị physical cap và đủ offered load, actual share phải nằm trong sai số đã quy định (ví dụ ±3 percentage points cho cửa sổ ngắn, ±1 point cho cửa sổ dài). Nếu một WAN bị link cap/queue-full, UI phải báo `capacity-limited`, không coi đó là lỗi weight scheduler.

### 10.9 Test matrix riêng cho bandwidth bonding

| Mode | Traffic | WAN MTU / UI weight | Điều phải chứng minh |
| --- | --- | --- | --- |
| perpacket ON | chỉ 1500 | 1500/1500, 50/50; rồi 70/30 | Actual wire bytes hội tụ 50/50 và 70/30; baseline 1500 không giảm. |
| perpacket ON | mix ngẫu nhiên 1500 + 9000 | 9000/9000, 50/50 | Packet count có thể lệch, wire bytes phải 50/50. |
| perpacket ON | 1500 UDP cần split + 9000 UDP FULL | WAN0=1500, WAN1=9000, 50/50 | `FRAG0+FRAG1` cùng WAN0; actual wire bytes vẫn khớp UI. |
| perpacket ON | 90% jumbo, 10% small | 9000/9000, 70/30 | Không có WAN nào nhận 70% packet thay vì 70% byte. |
| perpacket OFF | một TCP + nhiều UDP | mixed MTU, `window_kb` khác nhau | Flow only reselect sau actual wire-byte window; TCP không đổi MTU/MSS class. |
| failover | một WAN down/full giữa test | 50/50 | Reservation rollback đúng; WAN sống nhận 100% không leak/negative accounting. |
| UI reload | 50/50 -> 80/20 | mix 1500/9000 | Ratio chuyển êm qua blend epoch, counter target/actual rõ. |

### 10.10 Thứ tự thay đổi code cho scheduler (sau phần XDP SG)

1. Viết test/unit test cho estimator: same plaintext + MTU 1500/9000 -> expected FULL/split aggregate wire length.
2. Thêm per-WAN MTU runtime và pin `wan_dp` như mục 9.8.
3. Thêm byte scheduler/reservation API trong `wan_scheduler.c`; giữ scheduler cũ sau feature flag để so sánh.
4. Sửa `local_egress.c`: estimate tất cả candidate, reserve một candidate, encrypt, push, commit/rollback.
5. Sửa split path: pair fragment là một accounting unit, commit only khi `ne_ring_try_push_pair()` thành công.
6. Sửa TX completion stats để `wire_bytes_tx_completed` là nguồn kiểm chứng thực tế, không chỉ scheduled bytes.
7. Sau khi perpacket ON pass, mới nối `window_kb` cho perpacket OFF; không dùng window mode để che lỗi byte ratio của perpacket ON.
8. Cập nhật UI/CLI và tài liệu `DATAPLANE_AI_TRAINING.md` để bỏ mọi mô tả scheduler theo packet-count cũ.

**Điều kiện hoàn tất:** UI 50/50, 70/30 hoặc weight khác phải đo bằng byte wire thực tế và giữ đúng trong traffic 1500, traffic 9000 và mix; số packet, số XDP descriptor, số fragment không phải tiêu chí cân băng thông.
