# NE MAC Learn — Dataplane: luồng và logic

Mô tả **cách hệ thống đang chạy**: forward gói, gộp kênh WAN, mã hóa L2 PQC, chia đa core. Không gồm Postgres / schema / reload DB / vault (`src/db/*`).

UDP cắt/rã ráp: **§16**, rã ráp chi tiết để tối ưu **§16.8**. Gộp kênh per-packet: **§7**, **§18**. Vì sao 2 WAN OOO còn 1 WAN ổn: **§17**. Lớp mã hóa: **§19**. AF_XDP / UMEM: **§20**. i40e + 5.15→6.8: **§20.0**. **1500 và 9000 cùng chạy**, mode **drv + `XDP_COPY`**: **§20.0a**.

**Bài đo 1 LAN + 1 WAN (2026-08-27):** UDP 10 stream ~100s → **8.38 Gbit/s**, loss **0.16%**, OOO **45 / 71.3M**. Cùng L2 PQC, cùng cắt UDP ×2; chỉ khác một path. 2 WAN per-packet thì OOO lớn — chi tiết §7.7.

---

## 0. Sản phẩm là gì

`network-encryptor` là **L2 encryptor + WAN bonder** chạy userspace trên AF_XDP.

Máy có N NIC LAN (phía client) và M NIC WAN (phía đường truyền). Gói vào LAN:

1. Parse 5-tuple, chọn crypto policy.
2. **Bypass** → không mã hóa, vẫn gộp kênh, RX/TX cores only.
3. **Encrypt** → mã hóa L2 PQC trên crypto core, ghi marker + worker_idx lên wire, gộp kênh per-packet ra WAN.
4. **ARP** → bridge LAN↔WAN, mã hóa key tĩnh, **không** đi bypass, **không** vào WRR data.

Chiều ngược: WAN RX đọc marker / worker_idx → đúng crypto core giải mã / ráp fragment → MAC FDB → TX LAN.

Cách thiết kế hiện tại:

- **Gộp kênh = per packet.** Mỗi datagram data tự pick WAN (WRR). Một connect rải cả 2 WAN; WAN không khóa theo 5-tuple.
- 1 TCP/UDP connect = **1 crypto core** (AES + bảng reasm per-worker). Đó là chia core, khác gộp kênh.
- TX slot sticky theo flow, độc lập với WAN (một consumer trên một cột ring).
- Bypass không vào core crypto 3–8: RX LAN/WAN tự `push_to_wan` / `forward`.

---

## 1. Bản đồ file (chỉ dataplane)

| File | Việc |
|------|------|
| `inc/core/util/cpu_map.h` | Pin CPU cứng: RX LAN / TX / CRYPTO / RX WAN |
| `src/core/util/cpu_map.c` | Validate CPU online, không trùng |
| `inc/core/forwarder/forwarder.h` | `struct forwarder`, ring topology |
| `src/core/forwarder/forwarder.c` | Spawn thread, RX/TX/crypto loop |
| `src/core/forwarder/wan_scheduler.c` | Pool WAN, WRR per-packet, drain/join/failover gate |
| `src/core/forwarder/crypto_runtime.c` | Ctx mã hóa per policy, sync key PQC, frag GC |
| `src/core/dataplane/local_egress.c` | LAN→WAN: policy, pick WAN, encrypt/bypass/ARP |
| `src/core/dataplane/wan_ingress.c` | WAN→LAN: decrypt, reasm, FDB |
| `src/core/dataplane/crypto_route.c` | Sticky flow → crypto worker + TX slot |
| `src/core/dataplane/idle.c` | Adaptive idle + eventfd wake |
| `src/core/dataplane/arp_bridge.c` | ARP encrypt/bridge, không bị weight=0 chặn |
| `src/core/dataplane/packet_util.c` | `dp_parse_flow`, `dp_ring_push` |
| `src/core/flow/flow_table.c` | `flow_table_pick_wan_per_packet` (live) |
| `src/core/flow/mac_learn.c` | FDB MAC cho WAN→LAN unicast |
| `src/core/iface/xdp_interface.c` | UMEM, AF_XDP RX/TX, ring MPSC |
| `bpf/lan.c` | XDP LAN: ARP+IPv4 → AF_XDP |
| `bpf/wan.c` | XDP WAN: ARP / NE-ARP / IPv4 TCP/UDP/ICMP/OSPF → AF_XDP; CFM PASS kernel |
| `src/crypto/common/packet_crypto.c` | 3 key slot, diversify PQC |
| `src/crypto/common/crypto_option_router.c` | Dispatch encrypt/decrypt/split |
| `src/crypto/common/eth_parse.c` | Marker, policy_id, worker_idx, MSS clamp |
| `src/crypto/pqc/pqc_l2_option.c` | L2 PQC encrypt/decrypt/frag, ghi worker_idx |
| `src/crypto/pqc/pqc_handshake.c` | Handshake + rotate key 30 ngày |
| `src/crypto/options/bypass.c` | No-op crypto ops |
| `inc/crypto/eth_parse.h` | Wire layout 0x104A / 0x1048 |
| `inc/core/dataplane/dp_idle.h` | Wake ID encoding |

Tài liệu này không gồm `src/db/*`, Postgres, vault. `config_reload` chỉ xuất hiện khi gọi `fwd_wan_*` / `fwd_crypto_*`.

---

## 2. CPU map — vì sao chia thế này

File: `inc/core/util/cpu_map.h`. Máy 12 logical CPU (0–11).

```
CPU  0     RX LAN          1 thread  local_rx_thread
CPU  1,2,9,10   TX         4 thread  tx_thread (slot 0..3)
CPU  3,4,5,6,7,8  CRYPTO   6 thread  crypto_worker_thread
CPU 11     RX WAN          1 thread  wan_rx_thread
```

Macro:

- `NE_RX_LAN_SLOTS = 1`
- `NE_TX_SLOTS = 4`
- `NE_CRYPTO_WORKERS = 6`
- `NE_RX_WAN_SLOTS = 1`

**Vì sao không để TX nằm cạnh RX LAN:** RX LAN (0) phải hút AF_XDP saturating. TX là syscall `sendto` / xsk copy-mode nặng memcpy. Tách physical core. Crypto (AES-NI) chiếm 6 core giữa vì 1 connect = 1 core mã hóa; nhiều connect thì least-loaded rải 3–8.

**TX 4 core (1,2,9,10):** mỗi TX slot **độc quyền** một cột ring `mid_to_wan[*][slot]` và `mid_to_local[*][slot]`. Một consumer / một slot = không reorder trong flow sticky. Số slot thực tế = `min(NE_TX_SLOTS, min queue_count mọi NIC live)`.

`ne_cpu_map_validate()` từ chối CPU offline / ngoài cpuset / gán trùng. Thread control (không dataplane) pin sang CPU thừa, không dùng CPU 0 (RX LAN).

---

## 3. Ring topology

`struct forwarder` (`forwarder.h`):

```
local_to_mid[NE_CRYPTO_WORKERS]              LAN RX  → crypto worker w
wan_to_mid[NE_CRYPTO_WORKERS]                WAN RX  → crypto worker w
mid_to_wan[wan_dp][NE_CRYPTO_WORKERS]        crypto/bypass → TX slot  (index 2 = TX slot, không phải worker)
mid_to_local[local_idx][NE_CRYPTO_WORKERS]   crypto/bypass → TX slot
```

Index thứ hai của `mid_to_*` **là TX slot** (0..active_tx_slots-1). Mảng khai báo `NE_CRYPTO_WORKERS` (6) cho headroom; live chỉ dùng 4 slot TX. `dp_out_ring_idx()` TLS chọn cột này.

`push_to_wan` (`local_egress.c`):

```
ri = dp_out_ring_idx();
dp_ring_push(fwd, &fwd->mid_to_wan[wan_dp][ri], job);
```

Hàng đợi:

| Ring | Producer | Consumer | Ý nghĩa |
|------|----------|----------|---------|
| `local_to_mid[w]` | LAN RX | crypto w | Encrypt + ARP local |
| `wan_to_mid[w]` | WAN RX | crypto w | Decrypt + ARP wan |
| `mid_to_wan[dp][slot]` | crypto hoặc RX bypass | tx_thread slot | TX WAN dp |
| `mid_to_local[li][slot]` | crypto hoặc RX bypass | tx_thread slot | TX LAN li |

UMEM: `NE_FRAME=2048`, `NE_N_FRAMES=1<<20`, `NE_RING=16384`, `NE_BATCH_SIZE=64`.

`struct ne_packet`: `addr` (UMEM offset), `len`, `dir`, `wan_idx`, `local_idx`, `tx_slot`.

---

## 4. Luồng thread (`forwarder.c`)

`forwarder_run` tạo theo thứ tự: LAN RX → TX → CRYPTO → WAN RX. Mỗi thread `pin_cpu`.

### 4.1 LAN RX — `local_rx_thread` (CPU 0)

```
ne_refill_fq_local_slot
ne_recv_local_slot(batch, 64)
với mỗi gói:
  nếu dataplane_local_needs_mid():
      wi, tx_slot = dp_crypto_pick_local_worker()
      job.tx_slot = tx_slot
      push local_to_mid[wi]
      ne_dp_idle_wake(NE_DP_WAKE_CRYPTO(wi))
  else:   /* bypass — KHÔNG đụng crypto core */
      dp_out_ring_bind(dp_pick_tx_slot())
      dataplane_process_local()   // ngay trên RX
ne_recv_release_local_slot
```

`dataplane_local_needs_mid`:

- ARP → **1** (luôn mid, key tĩnh trên crypto worker)
- `crypto_enabled == 0` → 0
- policy BYPASS → 0
- còn lại (encrypt) → 1

### 4.2 Crypto worker — `crypto_worker_thread` (CPU 3–8)

Bind lúc start:

```
dp_crypto_worker_bind(worker_idx)     // TLS worker + default tx_slot = worker % nslots
crypto_option_bind_worker_idx(...)    // ghi worker_idx lên wire lúc encrypt
crypto_l2_pqc_bind_pair(&fwd->pair)   // reasm dùng UMEM pair này
```

Loop (comment trong code: *Encrypt / decrypt / reasm only. Bypass never queues here.*):

```
pop wan_to_mid[w]  → dataplane_process_wan
pop local_to_mid[w] → dp_out_ring_bind(job.tx_slot); dataplane_process_local
mỗi 2048 vòng: fwd_crypto_frag_gc_worker_tick(w)
idle → ne_dp_idle_arm(NE_DP_WAKE_CRYPTO(w))
```

LAN job **phải** `dp_out_ring_bind(job.tx_slot)` vì TX slot đã chọn lúc RX, độc lập worker.

### 4.3 WAN RX — `wan_rx_thread` (CPU 11)

Giống LAN. `dataplane_wan_needs_mid`: ARP hoặc L2 marker → mid. Bypass IPv4 trần → RX tự `dataplane_process_wan`.

Encrypt: `dp_crypto_pick_wan_worker` đọc **worker_idx trên wire** → đúng core đã mã hóa (reasm table per-worker). Sai core = fragment không ráp được.

### 4.4 TX — `tx_thread` (CPU 1,2,9,10)

Mỗi slot:

```
ne_drain_cq_local/wan(tx_slot)          // trả frame UMEM
burst TX mọi LAN  mid_to_local[*][slot]
burst TX mọi WAN  mid_to_wan[*][slot]   (bỏ WAN stopped)
idle → NE_DP_WAKE_TX(slot)
```

Slot 0 kiêm maintenance: reload apply, `dp_maint_tick` (GC flow, stats) dưới `runtime_lock` trylock.

TX drain **mọi WAN** ở đúng slot của mình. Load TX lệch khi traffic chỉ vào 1 WAN × 1 tx_slot (đúng bệnh bài test 1 connect sticky WAN cũ).

---

## 5. Idle / wake — vì sao `ne_dp_idle_arm` tốn CPU

`idle.c` + `dp_idle.h`. Không busy-poll 100% (trừ `NE_DP_BUSY_POLL=1`).

Wake ID:

```
0..5  = crypto worker 0..5     NE_DP_WAKE_CRYPTO(w)
6..9  = TX slot 0..3           NE_DP_WAKE_TX(slot) = 6 + slot
```

Trạng thái theo thời gian idle:

| Phase | Thời gian | Hành vi |
|-------|-----------|---------|
| Hot | < 5 µs | `cpu_relax` / pause |
| Warm | 5–25 µs | `nanosleep(5µs)` |
| Cold | > 25 µs | set sleeping, `poll(eventfd, 1ms)` |

RX threads `wake_id = -1`: cold-poll **AF_XDP fd**, không eventfd crypto/TX.

Ai wake:

- Push `local_to_mid` / `wan_to_mid` → `ne_dp_idle_wake(CRYPTO(wi))`
- Push output ring → `ne_dp_idle_wake_tx_worker(ring_idx)` → TX slot `ring_idx % NE_TX_SLOTS`
- `forwarder_stop` → `ne_dp_idle_wake_all`

Bài test Core 5 ~40% `ne_dp_idle_arm`: worker được gán cho connect nhưng **không có việc encrypt** (hoặc connect dính core khác). Thread vẫn vào idle state machine. Không phải bug mã hóa; đó là core crypto **được pin + idle**. 1 connect chỉ được **một** core mã hóa — core crypto còn lại phải gần idle. Nếu thấy core thứ hai ~40% `ne_dp_idle_arm` trong khi 1 connect, đó là idle path chứ không phải encrypt song song.

---

## 6. Sticky crypto + TX — `crypto_route.c`

Bảng `g_route_table[8192][8]` (8-way). Key 5-tuple **chuẩn hóa hướng** (IP/port nhỏ hơn đứng trước) để 2 chiều cùng entry.

Chỉ TCP/UDP được sticky. ICMP/OSPF/khác → hash packet, không insert.

Gói đầu tiên của flow:

1. Lookup miss.
2. Lock insert (chỉ first packet; lookup sau lock-free).
3. Worker = least-loaded `g_worker_connection_count`.
4. TX slot = least-loaded `g_tx_connection_count` (**độc lập** worker).
5. Entry immutable. Comment: *Never evict a live immutable entry: remapping an established TCP flow can reorder packets.* Set đầy → fallback hash, không đuổi entry cũ.

`dp_crypto_pick_local_worker` = `dp_flow_route_get(pkt, -1)`.

`dp_crypto_pick_wan_worker`:

- ARP → giống LAN (hash/sticky ARP 5-tuple nếu parse được).
- Data encrypt: đọc `worker_idx` byte trên header L2. Nếu byte < 6 dùng trực tiếp; không thì map CPU id → worker.

`dp_pick_tx_slot` (bypass): hash 5-tuple → TX slot, **không** đụng crypto worker, **không** insert route table.

`dp_out_ring_bind` / `dp_out_ring_idx`: TLS. Mọi `push_to_wan` dùng giá trị này.

**Vì sao 1 connect = 1 crypto core (cố ý):**

1. AES-GCM context + cache line nóng trên 1 core.
2. Bảng reasm UDP fragment keyed `(profile_slot, worker_idx)` — 2 fragment cùng datagram phải cùng worker.
3. Wire mang `worker_idx` để WAN RX không hash lại (hash sau encrypt khác 5-tuple plaintext).
4. Đổi worker giữa chừng = reorder + reasm fail + TCP retransmission.

Một TCP/UDP flow không chạy song song trên 6 core crypto. Hết 6 core khi có nhiều connect. Bài test “1 connect 7G”: **một** core được gán ~100% AES; các core crypto khác idle / `ne_dp_idle_arm`.

---

## 7. Gộp kênh WAN — path đang chạy (per-packet)

Gộp kênh hiện tại là **từng datagram một lần WRR**, không dính WAN theo 5-tuple. Crypto worker và TX slot mới sticky theo flow — chúng không chọn WAN.

Khi **2 WAN**, UDP iperf OOO rất cao (cùng lúc loss vẫn thấp). Khi **1 WAN**, cùng mã hóa/cắt gói thì OOO gần 0 (§7.7 D). Tắt per-packet (sticky/window) cũng giảm OOO vì mỗi flow dính một đường — đó là **hết stripe**, không còn gộp kênh. Chi tiết thuật toán §7.2–7.6, số đo §7.7, từng bước §18, phân tích hệ số ×2 §17.

### 7.1 Cách pick đang làm

`fwd_wan_pick_for_local` **luôn** gọi `flow_table_pick_wan_per_packet`. Tham số 5-tuple / `flow_ok` / `window_bytes` bị `(void)`: pick **không** nhìn flow.

Lịch sử: một bản sticky TCP theo WAN khiến 2 NIC mà traffic một đường. `flow_table_get_wan` / `flow_table_get_wan_profile` vẫn nằm trong `flow_table.c` (window 10MB + drain 1s) nhưng **dataplane không gọi**.

### 7.2 Per-packet chạy trên datagram nào, lúc nào

Chỉ chiều **LAN → WAN**, trong `dataplane_process_local`, **sau** chọn policy, **trước** encrypt/split:

```
pick_profile_policy(...)
wan_dp = fwd_wan_pick_for_local(fwd, profile_idx, flow_ok, 5tuple..., window_bytes)
if (wan_dp < 0 || !fwd_wan_has_tx_room(fwd, wan_dp))
    drop          // mất gói ngay tại encryptor, iperf = Lost
BYPASS? push_to_wan(wan_dp)
else encrypt_to_wan(..., wan_dp)   // split UDP vẫn dùng ĐÚNG wan_dp này cho cả 2 mảnh
```

Một lần pick = **một datagram plaintext** (một job UMEM từ LAN). Không pick lại cho frag1.

Không chạy trên: ARP (bridge tự chọn WAN), chiều WAN→LAN (đã mã hóa, FDB ra LAN), CFM.

Bypass cũng pick per-packet — gói không mã hóa vẫn stripe 2 WAN.

Nhiều crypto worker gọi song song. Counter **global**, không per-worker, không per-flow.

### 7.3 `fwd_wan_pick_for_local` — từng bước

File: `src/core/forwarder/wan_scheduler.c`.

1. `fwd_wan_build_profile_pool(profile)` → mảng `allowed_wans[]` (index **config** WAN, không phải dp slot) + `allowed_weights[]`. Chỉ WAN weight>0, live, không failover-exclude, không admin-hold, không drain-cấm-traffic-mới. Join ramp scale weight 0→target. Dead WAN: cộng weight vào các WAN còn sống (trừ weight=0 cố ý). Drain taper: WAN đang rút vẫn trong pool với weight giảm 5s.
2. `pool_n == 0` → `pick_least_loaded_wan` (độ sâu `mid_to_wan`).
3. `flow_table_pick_wan_per_packet(allowed_wans, allowed_weights, pool_n)` → `wan_cfg`.
4. `fwd_wan_live_dp_for_cfg(wan_cfg)` → dataplane index. Fail → `fwd_wan_dp_for_legacy_cfg` (đang drain).
5. `!fwd_wan_dp_ok_for_new_traffic(dp)` → fallback least-loaded.

Output là **dp slot** để `push_to_wan` / `push_split_to_wan`.

`fwd_wan_has_tx_room` (gọi **sau** pick, trong `local_egress`):  
`ne_ring_count(mid_to_wan[dp][tx_slot_hiện_tại]) + 64 < 16384`.  
Hết chỗ → **drop cả datagram**, không đổi WAN. Per-packet **không** retry WAN kia khi ring đầy. Least-loaded chỉ khi pick trả WAN chết/invalid, không khi ring đầy.

### 7.4 `flow_table_pick_wan_per_packet` — thuật toán thật

File: `src/core/flow/flow_table.c`. State: `static _Atomic uint64_t g_pkt_wrr_seq` (một counter cả process).

```
nếu !wans || n<=0     → 0
nếu n==1              → wans[0]     // 1 WAN: KHÔNG tăng seq, không stripe
S = tổng weight > 0
k = atomic_fetch_add(g_pkt_wrr_seq, 1)   // mọi flow, mọi worker, TCP+UDP+bypass
nếu S>0:  return wrr_slot_to_wan(k % S)
else:     return wans[k % n]
```

`wrr_slot_to_wan(slot, wans, weights, n, S)`: `s = slot % S`; duyệt i, cộng `weights[i]` (bỏ ≤0), khi `s < acc` trả `wans[i]`.

Ví dụ 2 WAN weight 50/50, S=100: k%100 ∈ [0,50) → WAN0, [50,100) → WAN1. Gói k, k+1, k+2, … **luân phiên** nếu weight bằng nhau.

**Không có:** 5-tuple, seq per-flow, RTT, byte-count, “gói này của connect nào”, “frag0/frag1”, “TCP vs UDP”. `g_pkt_wrr_seq` tăng cả khi 6 worker encrypt 6 flow khác nhau — stripe là **thứ tự hoàn thành encrypt**, không phải thứ tự LAN RX của một flow.

1 flow UDP + 1 crypto core: gói 0,1,2,3 → WAN0, WAN1, WAN0, WAN1 (weight bằng).  
Nhiều flow / nhiều worker: xen kẽ không đoán được theo từng flow.

`n==1` (đúng 1 WAN live): return thẳng, seq không tăng. Topology 1 LAN + 1 WAN **không stripe**. Bài D: 8.38G, OOO 45/71.3M — split+crypto ×2 vẫn chạy nhưng một path nên thứ tự gần như tuyệt đối. OOO hàng loạt chỉ khi `n>=2`.

### 7.5 Sau pick — gói đi đâu (vì sao OOO)

```
LAN RX → crypto worker (sticky 5-tuple)
       → pick WAN   (KHÔNG sticky; global WRR)
       → encrypt / split
       → mid_to_wan[wan_dp][tx_slot]     tx_slot sticky theo flow
       → TX thread của slot đó, NIC wan_dp
```

**Tách độc lập (cố ý, và là mâu thuẫn OOO):**

| Trục | Sticky? | Hệ quả |
|------|---------|--------|
| Crypto worker | Có, per TCP/UDP flow | 1 connect 1 core mã hóa |
| TX slot | Có, per flow | 1 consumer, thứ tự trên **một** ring |
| WAN | **Không** — mỗi datagram WRR | Cùng flow, gói chẵn WAN0, lẻ WAN1 |

Cùng `tx_slot` nhưng **hai ring**: `mid_to_wan[0][slot]` và `mid_to_wan[1][slot]`. TX thread slot S drain **xen kề** mọi WAN:

```
for wi in wans:
    dp_burst_tx_wan(fwd, wi, tx_slot)
```

Thứ tự emit lên 2 NIC ≠ thứ tự datagram trong flow. WAN0 và WAN1 khác delay/jitter → phía nhận: gói k+1 (WAN1) tới trước gói k (WAN0) → iperf Out-of-order. Loss thấp vì cả hai vẫn tới.

UDP split: 2 mảnh **cùng** WAN (đúng). Datagram kế WRR sang WAN kia. Hold-gap reasm (A chờ frag1 trên WAN0, B đã xong trên WAN1) nhân OOO. §16.

**Nhân ×2 (lý do per-packet 2 WAN nổ, 1 WAN vẫn ổn):** iperf UDP `-l 1470` luôn `need_split` → **mỗi datagram gốc = 2 frame wire + 2 AES-GCM encrypt + 2 AES-GCM decrypt + 1 lần join bảng**. WRR chỉ chạy **một lần / datagram gốc**, nhưng trên wire và trên crypto core lưu lượng đã ×2. 1 WAN: hai mảnh đi **cùng** `mid_to_wan[0][slot]`, TX tuần tự frag0→frag1→datagram kế → OOO ~0 (bài D §7.7). 2 WAN: datagram N (2 frame) WAN0, N+1 (2 frame) WAN1 → 4 frame, 2 queue, 2 delay, hold-gap → OOO cực lớn. Chi tiết nhân và từng bước: **§18**.

Không stamp sequence bonding lên wire. Phía nhận **không** reorder buffer. Iperf đếm OOO trên payload UDP gốc.

### 7.6 Per-packet OFF = path cũ (window/sticky)

`flow_table_get_wan_profile`: khóa 5-tuple, `current_wan` giữ đến hết window byte / drain 1s (TCP Codex còn từng không bao giờ đổi). Cùng connect → cùng WAN lâu → OOO **cực giảm**. Aggregate = 1 đường / flow. Nhiều connect mới rải 2 WAN.

User: **tắt per-packet thì reorder cải thiện mạnh** — đúng, không phải ảo. Đó là mất bonding, không phải tối ưu bonding.

### 7.7 Bài đo thật (cập nhật theo test user)

**A — Per-packet ON, 2 WAN bonding, nhiều UDP stream, ~100s:**

| Stream | Bandwidth | Lost | OOO datagrams |
|--------|-----------|------|----------------|
| vài stream | ~399 Mb/s | 0.024–0.058% | 0.23M–0.31M / ~3.4M (~7–9%) |
| nhiều stream | ~1.19–1.20 Gb/s | 0.078–0.11% | 1.5M–1.9M / ~10.2M (~15–19%) |
| stream nặng hơn | ~1.19 Gb/s | 0.31–0.35% | 5.5M–5.7M / ~10.2M (**~54%**) |

Loss **ổn** (sub-percent). OOO **không chấp nhận**. Càng đầy tải / nhiều stream, tỉ lệ OOO càng lớn (stripe 2 path + reasm hold-gap + nhân ×2 split/crypto).

**B — 1 LAN + 1 WAN bão hòa / test cũ:** từng ghi “loss nhiều” khi dồn hết UDP (kể cả 2 wire/datagram sau split) vào một `mid_to_wan` và `fwd_wan_has_tx_room` drop. Đó là case **overrun một NIC**, không phải định nghĩa “1 WAN luôn kém”. Baseline vàng hiện tại là **D**.

**C — Tắt per-packet** (sticky/window, kể cả còn 2 WAN trong profile): OOO **cực cải thiện** vì từng flow dính 1 WAN. Loss/throughput phụ thuộc WAN đó. User xác nhận: tắt per-packet thì reorder tốt — đúng, đó là **mất gộp kênh**, không phải tối ưu bonding.

**D — Không gộp kênh: 1 LAN + 1 WAN duy nhất (n==1, WRR no-op) — 2026-08-27, cực ổn định.**  
Iperf UDP 10 stream, ~100s (log user, số copy nguyên):

| Stream | Transfer | Bandwidth | Jitter | Lost/Total | OOO |
|--------|----------|-----------|--------|------------|-----|
| 19 | 9.75 GB | 838 Mb/s | 0.024 ms | 8484/7133169 (0.12%) | — |
| 11 | 9.75 GB | 838 Mb/s | 0.013 ms | 10230/7133169 (0.14%) | 25 |
| 12 | 9.75 GB | 838 Mb/s | 0.018 ms | 11192/7133175 (0.16%) | 19 |
| 14 | 9.74 GB | 837 Mb/s | 0.025 ms | 17341/7133178 (0.24%) | — |
| 17 | 9.75 GB | 837 Mb/s | 0.018 ms | 13460/7133181 (0.19%) | — |
| 18 | 9.75 GB | 838 Mb/s | 0.010 ms | 8165/7133180 (0.11%) | — |
| 13 | 9.74 GB | 837 Mb/s | 0.021 ms | 15798/7133179 (0.22%) | 1 |
| 16 | 9.75 GB | 838 Mb/s | 0.016 ms | 9244/7133175 (0.13%) | — |
| 15 | 9.75 GB | 838 Mb/s | 0.013 ms | 9359/7133180 (0.13%) | — |
| 20 | 9.75 GB | 838 Mb/s | 0.024 ms | 10449/7133175 (0.15%) | — |
| **SUM** | **97.5 GB** | **8.38 Gbit/s** | — | **113722/71331761 (0.16%)** | **45** |

45 OOO / 71.3 triệu datagram ≈ **0.000063%**. Jitter 0.010–0.025 ms. Đây là bằng chứng:

- L2 PQC **vẫn cắt UDP ×2** và **vẫn mã hóa/giải mã ×2** trên 1 WAN (iperf `-l` lớn → `need_split`). Split+crypto **không** phá thứ tự khi hai mảnh cùng một path.
- Logic dataplane (RX LAN → crypto sticky → encrypt → TX → WAN RX → decrypt/join → TX LAN) **ổn** ở 8.38G.
- Chỗ kém là **gộp kênh per-packet 2 WAN**: WRR rải datagram liên tiếp sang 2 NIC trong khi mỗi datagram đã là 2 frame + 2 AES. Reorder nổ vì 2 queue × 2 mảnh × 2 delay, không vì “mã hóa hỏng”.

Ý nghĩa: cùng stack L2 PQC + split ×2, một path thì thứ tự gần tuyệt đối. OOO hàng loạt xuất hiện khi WRR 2 NIC kết hợp mỗi datagram đã là 2 frame + 2 AES. Sticky/window (bài C) giảm OOO vì hết stripe. Chi tiết nhân và từng bước: **§17, §18**.

### 7.8 ARP ≠ data WRR

`arp_bridge.c`: weight=0 / WRR / data-drain **không** chặn ARP — chỉ WAN down mới thôi ARP.

ARP chọn WAN theo bridge primary, backup WAN UP (kể cả weight=0). Ethertype `0x1048`, key tĩnh, luôn crypto worker.

---

## 8. LAN → WAN data — `dataplane_process_local`

```
parse 5-tuple → flow_ok
ARP? → arp_bridge_from_local; return
pick_profile_policy (profile 0, local_idx phải thuộc profile)
fwd_wan_pick_for_local → wan_dp     // PER PACKET
!fwd_wan_has_tx_room(wan_dp)? drop
BYPASS? stats; push_to_wan; return
!crypto_enabled? drop
TCP? crypto_tcp_clamp_mss(MTU 1500, L2 PQC overhead)
policy ctx ready? encrypt_to_wan(CRYPTO_OPT_L2_PQC)
  need_split UDP? split 2 frame, push_split_to_wan, return
  else encrypt in-place, push_to_wan
```

Dataplane **hardcode** `CRYPTO_OPT_L2_PQC`. Policy L3/L4 trong config/HS không đổi option encrypt live. Bypass là nhánh riêng, không gọi `crypto_option_encrypt`.

`fwd_wan_has_tx_room`: `ne_ring_count(mid_to_wan[dp][tx_slot]) + BATCH < cap`. Hết chỗ → drop (không xếp hàng vô hạn).

---

## 9. Mã hóa L2 PQC

### 9.1 Wire format

`eth_parse.h`:

- Data: EtherType `NE_L2_FAKE_ETHERTYPE = 0x104A`
- ARP enc: `NE_L2_FAKE_ETHERTYPE_ARP = 0x1048`

Sau L2 prefix (14B thường / +VLAN):

```
[policy_id: 1B][worker_idx: 1B][nonce: 12B][ciphertext + GCM tag]
```

`worker_idx` = `crypto_option_worker_idx()` TLS, bind lúc crypto thread start. WAN RX đọc field này để đẩy đúng core.

Overhead ~30B → TCP MSS clamp trước encrypt.

### 9.2 Key

`packet_crypto_ctx`: 3 slot PREV/CURRENT/NEXT. Data policy `pqc_from_handshake=true`. ARP key tĩnh, không HS-refresh.

Handshake (`pqc_handshake.c`): `KEY_ROTATION_INTERVAL_MS = 30 ngày`. Timeout rotate 15s rồi give up. L3 interval riêng `L3_KEY_ROTATION_INTERVAL_MS` (~50 phút) — dataplane live là L2.

Hot path: worker giữ snapshot ctx; `packet_crypto_update_keys` diversify qua `sig_pqc_diversify_key(profile_id, policy_id)`. Tránh `g_key_mutex` mỗi gói (crypto_runtime copy-on-generation).

Không key / HS chưa ready → drop (không encrypt bằng key rác).

### 9.3 Fragment UDP

TCP không cắt (MSS clamp). UDP sát MTU thì cắt 2 frame rồi ráp ở máy nhận. Offset, hàm, return code, hold-gap: **§16**.

### 9.4 WAN → LAN decrypt — `dataplane_process_wan`

```
ARP marker / ARP → arp_bridge_from_wan
encrypted?
  wan_try_l2_pqc_frag  (pending 1=đợi, 2=held UMEM)
  decrypt_l2 (CRYPTO_OPT_L2_PQC)
  bind TX: dp_flow_pick_tx_slot(pkt, worker_hint)
plain bypass IPv4 → policy match chiều ngược
mac_lookup → mid_to_local[li][tx_slot]
```

Decrypt xong mới pick TX slot (5-tuple plaintext). Worker hint = core đang chạy (đã khớp wire).

---

## 10. Bypass

Policy `POLICY_ACTION_BYPASS`:

- `needs_mid` = 0 → **RX thread** xử lý, core 3–8 không nhận gói.
- Không marker, không worker_idx, không overhead.
- Vẫn `fwd_wan_pick_for_local` (gộp kênh per-packet).
- TX slot = `dp_pick_tx_slot` (hash), không crypto route table.

`crypto_enabled=0`: tương tự, mọi IPv4 non-ARP đi RX→TX.

ARP **không** bypass dù policy bypass.

---

## 11. XDP filter

`bpf/lan.c`: ARP hoặc IPv4 → `xsks_map[rx_queue_index]`. Frame > 1514 (hoặc VLAN 1518) **DROP** — trần cứng PATH_MTU 1500, chặn jumbo trước AF_XDP. Khác PASS kernel.

`bpf/wan.c`: CFM `0x8902` **PASS** (AF_PACKET failover). ARP, `0x1048`, IPv4 ICMP/TCP/UDP/OSPF → XSK. EtherType fake data `0x104A` qua `wan_config_map`. WAN **không** drop theo độ dài.

Attach: `bpf_xdp_attach(..., XDP_FLAGS_DRV_MODE)` (`profile_xdp.c`). Load: `SEC("xdp")`, **không** `xdp.frags` / `BPF_F_XDP_HAS_FRAGS`.

Socket AF_XDP: `XDP_COPY | XDP_USE_NEED_WAKEUP`, **không** `XDP_USE_SG`. UMEM frame 2048B. Mục tiêu sau 6.8: **cùng** drv+COPY, **cả** 1500 lẫn 9000 — §20.0a. Chi tiết I/O: **§20**.

---

## 12. Ba trục độc lập (core / WAN / TX)

Hiện tại tách ba việc:

1. **Crypto worker** sticky theo TCP/UDP flow — một connect một core; bảng reasm theo worker.
2. **WAN** per packet — mỗi datagram WRR; không sticky 5-tuple.
3. **TX slot** sticky theo flow, độc lập WAN — một consumer trên một cột `mid_to_*[*][slot]`.

Bypass không vào `local_to_mid` / `wan_to_mid`. ARP luôn crypto worker; weight=0 không chặn ARP. WAN RX đọc `worker_idx` trên wire, không hash ciphertext. Route table không evict entry đang sống. Idle: eventfd, không spin 100% trừ `NE_DP_BUSY_POLL`.

### Vì sao bài test CPU lệch (lịch sử)

Test 1 connect 7G L2, 2 WAN, 4 TX core:

- Codex sticky TCP → 1 WAN → `mid_to_wan[một_dp][một_tx_slot]` nóng.
- TX cores khác drain WAN/slot trống → core 9 ~22%.
- Crypto: 1 core AES 100%; core khác `ne_dp_idle_arm` (idle), **không** phải mã hóa song song.

Sau khi per-packet: 1 connect phải thấy **cả 2 WAN TX**. Crypto vẫn 1 core — đúng. TX 4 core cân hơn vì 2 WAN × sticky tx_slot; nếu 1 flow 1 tx_slot thì vẫn 1 TX consumer chính + WAN kia cùng slot — 2 NIC cùng slot, 2 TX thread khác slot vẫn có việc nếu nhiều flow.

---

## 13. Hằng số cần nhớ

| Tên | Giá trị | Ý |
|-----|---------|---|
| `NE_CRYPTO_WORKERS` | 6 | CPU 3–8 |
| `NE_TX_SLOTS` | 4 | CPU 1,2,9,10 |
| `NE_RING` | 16384 | depth ring userspace |
| `NE_BATCH_SIZE` | 64 | RX batch |
| `NE_FRAME` | 2048 | UMEM chunk; trần `ne_packet.len` |
| `NE_N_FRAMES` | 1048576 | 1M × 2048 = 2 GiB mmap |
| `NE_FQ_PREFILL` | 16384 | FQ mỗi queue lúc open |
| `NE_XSK_COPY_TX_BATCH` | 32 | TX copy batch |
| `DP_ROUTE_SET_COUNT` | 8192 | route sets |
| `DP_ROUTE_WAYS` | 8 | associativity |
| `FLOW_TABLE_SIZE` | 16384 | bảng cũ, không pick live |
| `FLOW_WAN_SWITCH_DRAIN_MS` | 1000 | chỉ path window cũ |
| `WAN_REORDER_WINDOW_KB` | 10240 | quota cũ |
| `FORWARDER_WAN_DRAIN_SEC` | 5 | drain/join/blend |
| `CRYPTO_OPT_FRAG_MTU_DEFAULT` | 1500 | |
| `OPT_FRAG_TABLE_SIZE` | 4096 | |
| `OPT_FRAG_TIMEOUT_NS` | 200ms | |
| `KEY_ROTATION_INTERVAL_MS` | 30 ngày | L2 HS |
| `PACKET_CRYPTO_NONCE_BYTES` | 12 | |
| `NE_L2_FAKE_ETHERTYPE` | 0x104A | data |
| `NE_L2_FAKE_ETHERTYPE_ARP` | 0x1048 | ARP enc |
| `WAN_L2_FRAG_MAGIC` | 0x5B | UDP frag only |
| `NE_DP_IDLE_HOT_NS` | 5µs | |
| `NE_DP_IDLE_COLD_NS` | 25µs | |

---

## 14. Call chain nhanh

**LAN encrypt**

`local_rx_thread` → `dataplane_local_needs_mid` → `dp_crypto_pick_local_worker` → `local_to_mid[w]` → `crypto_worker_thread` → `dataplane_process_local` → `fwd_wan_pick_for_local` → `flow_table_pick_wan_per_packet` → `encrypt_to_wan` → `push_to_wan` → `tx_thread` → `ne_tx_drain_wan_all`

**LAN bypass**

`local_rx_thread` → `dp_pick_tx_slot` → `dataplane_process_local` (BYPASS) → `fwd_wan_pick_for_local` → `push_to_wan` → `tx_thread`

**WAN decrypt**

`wan_rx_thread` → `dataplane_wan_needs_mid` → `dp_crypto_pick_wan_worker` (wire) → `wan_to_mid[w]` → `dataplane_process_wan` → `decrypt_wan` / reasm → `dp_flow_pick_tx_slot` → `forward_wan_to_local` → `tx_thread` LAN

**LAN ARP**

`local_rx_thread` → mid → `arp_bridge_from_local` → `arp_select_egress_wan` → `mid_to_wan`

---

## 16. L2 PQC + UDP cắt/rã ráp

Bài iperf UDP ~100s:

- **1 LAN+1 WAN (không gộp kênh):** 8.38 Gbit/s, loss 0.16%, OOO 45/71.3M — split+crypto ×2 vẫn chạy, **cực ổn**. §7.7 D.
- **2 WAN per-packet:** loss 0.02–0.35% (ổn), OOO cực cao (15–54% @ 1.2G). Loss thấp + OOO cao = gói tới đủ, sai thứ tự.

Hai nguồn OOO khi bonding: (1) WRR per-packet 2 WAN lệch delay §7, (2) hold-gap rã ráp UDP **nhân** vì mỗi datagram đã là 2 mảnh. Luồng từng bước: §18.

---

### 16.0 Dispatch option — TCP không cắt, chỉ UDP cắt

Live encrypt luôn `CRYPTO_OPT_L2_PQC`. `crypto_proto_classify(ip_proto)`:

| ip_proto | class | ops | need_split | reasm |
|----------|-------|-----|------------|-------|
| 6 TCP | CRYPTO_PROTO_TCP | `l2_tcp_*` + `CRYPTO_OPS_PLAIN` (no-frag) | không | không |
| 17 UDP | CRYPTO_PROTO_UDP | `crypto_opt_l2_pqc_udp_ops` | `l2_udp_need_split` | `l2_udp_reasm` |
| 1 ICMP | CRYPTO_PROTO_ICMP | plain `l2_do_encrypt` | không | không |
| 89 OSPF | CRYPTO_PROTO_OSPF | plain | không | không |
| ARP | CRYPTO_PROTO_ARP | `l2_do_encrypt_arp` ethertype 0x1048 | không | không |

`encrypt_to_wan` (`local_egress.c`):

```
opt_id = CRYPTO_OPT_L2_PQC
pclass = crypto_proto_classify(proto)
if crypto_option_need_split(opt_id, pclass, job.len):   // chỉ UDP ops trả 1
    split_tail_take → crypto_option_split → push_split_to_wan
    return 1   // đã TX 2 frame, caller không push_to_wan nữa
crypto_option_encrypt(...)  // UDP vừa MTU, hoặc TCP/ICMP/OSPF
return 0                    // caller push_to_wan 1 frame
```

TCP: trước đó `crypto_tcp_clamp_mss(1500, 30)` nên plaintext + 30B PQC ≤ MTU → không bao giờ `need_split`.

Registry: `g_ops[CRYPTO_OPT_L2_PQC][CRYPTO_PROTO_UDP] = crypto_opt_l2_pqc_udp_ops()`.

Worker TLS: `crypto_option_bind_worker_idx(w)` lúc `crypto_worker_thread` start. Mọi `l2_write_wire_header` ghi byte `worker_idx` = giá trị này. WAN RX `dp_crypto_pick_wan_worker` đọc đúng byte đó.

---

### 16.1 Wire layout (không VLAN; et_off = 12, eth header 14B)

Offset từ đầu frame. `et_off = crypto_eth_l2_prefix_len` = 12 (thường) hoặc 16 (VLAN). Dưới đây **không VLAN**.

**A. Gói nguyên (TCP / UDP vừa / ICMP) — `l2_do_encrypt`**

```
 0..5    dst MAC
 6..11   src MAC
12..13   EtherType = 0x104A     (thay 0x0800)
14       policy_id  = ctx->wire_id
15       worker_idx = crypto_option_worker_idx()
16..27   nonce 12B
28..     ciphertext(IPv4 cả header+payload) || GCM tag 16B
```

`enc_start = 14+1+1+12 = 28`. Overhead 30B = 1+1+12+16 (`crypto_option_wire_overhead`).

Plaintext IPv4 (từ offset 14 gốc) được `memmove` tới 28 rồi AES-GCM. Decrypt `l2_do_decrypt`: đọc nonce, decrypt tại enc_start, `l2_restore_plain_packet` ghi lại 0x0800, trượt IPv4 về offset 14.

**B. Mảnh UDP — `l2_encrypt_fragment0_inplace` / `_single`**

```
 0..5    dst MAC (copy gói gốc)
 6..11   src MAC
12..13   0x104A
14       policy_id
15       worker_idx          ← CÙNG worker với mảnh kia
16..27   nonce 12B           ← KHÁC nhau từng mảnh (GCM riêng)
28       magic = 0x5B
29..30   pkt_id big-endian   ← CÙNG id hai mảnh
31       frag_index          0 = nửa đầu, 1 = nửa đuôi
32       reserved = 0
33..     ciphertext(plain mảnh) || GCM tag 16B
```

`enc_off = 14+1+1+12+1+4 = 33`. `OPT_FRAG_META_LEN = 35` ≈ 1+1+12+1+4+16 (magic+tag+GCM; dùng trong `need_split` so với MTU).

`l2_frag_magic_off` = `l2_enc_start_off` = offset 28 = chỗ 0x5B (cùng chỗ ciphertext bắt đầu ở gói **không** cắt). Vì vậy TCP/UDP vừa: byte 28 là CT; trùng 0x5B là false positive — RX restore scratch rồi `decrypt_l2`, **không drop**.

`opt_write_frag_tag(buf, pkt_id, frag_index)`: `buf[0]=id>>8, buf[1]=id&0xFF, buf[2]=frag_index, buf[3]=0`. Tag nằm ngay sau magic (offset 29).

**C. ARP** ethertype 0x1048, payload ARP 28B, không 0x5B, không split. Path `arp_bridge`, không `encrypt_to_wan`.

---

### 16.2 Vì sao UDP iperf luôn cắt

```
l2_udp_need_split(pkt_len):
    return (pkt_len + 35) > crypto_option_get_mtu();  // default 1500
```

`pkt_len` = độ dài **Ethernet plaintext LAN** (UMEM), không phải `-l` iperf.

Iperf `-u -l 1470`: `14+20+8+1470 = 1512`. `1512+35 = 1547 > 1500` → **mọi datagram lớn đều 2 wire frames**.

UDP nhỏ (`pkt_len+35 ≤ 1500`): `need_split=0` → `l2_udp_encrypt` = `l2_do_encrypt` (layout A, không 0x5B, không table reasm).

---

### 16.3 Thuật toán cắt — `l2_split` / `l2_udp_split`

Một datagram → **đúng 2** mảnh. Chỉ `ip_proto==17`. Cắt **app payload UDP**, không cắt IP/UDP header.

Ký hiệu (không VLAN): `l3_off=14`, `ip_hdr_len` = IHL*4 (thường 20), UDP header 8B, `app_len` = UDP payload.

```
frag_mtu       = crypto_option_get_mtu()          // 1500
frag_overhead  = l3_off + 35                      // 14+35=49
max_plain0     = frag_mtu - frag_overhead         // 1451
fixed_plain0   = ip_hdr_len + 8                   // 28
half1          = max_plain0 - fixed_plain0        // 1423 byte app trên frag0
nếu half1 >= app_len: half1 = app_len - 1         // luôn ≥1 byte cho frag1
half2          = app_len - half1
pkt_id         = crypto_option_next_pkt_id()      // u16, atomic GLOBAL mọi worker
frag0_plain    = IP || UDP-hdr || app[0..half1)
frag1_plain    = app[half1..end)                  // KHÔNG IP, KHÔNG UDP
```

Thứ tự encrypt trong `l2_split` (quan trọng: **frag1 trước**, rồi đè frag0 in-place lên buffer gốc):

1. `l2_encrypt_fragment_single(..., frag1_plain, half2, pkt_id, frag_index=1, out=tail_buf)`
2. `l2_encrypt_fragment0_inplace(..., frag0_plain_len, pkt_id, frag_index=0, in-place pkt_data)`

Hai nonce độc lập. Cùng `wire_id`, cùng `worker_idx`, cùng `pkt_id`.

Frag1 **không** tự thành IPv4. Phía nhận: frag0 cho IP+UDP+half1, frag1 chỉ half2; `opt_emit_join` ghép.

`pkt_id` wrap 65536. ~100k datagram split/s @ 1.2G → wrap ~0.65s. Table 4096+probe 8 phải chịu wrap (§16.7 bảng).

Ví dụ 1512B plaintext, half1=1423, app=1470 → half2=47B. Frag0 plaintext 20+8+1423=1451B; frag1 plaintext 47B.

---

### 16.4 TX hai mảnh — `encrypt_to_wan` + `push_split_to_wan`

`dataplane_process_local` (WAN **per-packet một lần / datagram gốc**, trước split):

```
wan_dp = fwd_wan_pick_for_local(...)     // §7 — không nhìn frag
if !fwd_wan_has_tx_room(wan_dp): drop cả job (chưa split)
...
enc = encrypt_to_wan(..., wan_dp, pclass)
```

`encrypt_to_wan` khi UDP cần cắt:

```
worker_idx = dp_crypto_current_worker_idx()
split_tail_take(fwd, worker_idx, &tail.addr)
    // cache UMEM per-worker 64 ô, refill batch 32; hết UMEM → return -1 → drop
crypto_option_split(L2_PQC, UDP, pctx, pkt, len, frame_size, &l1, tail_buf, frame_size, &l2)
push_split_to_wan(job, l1, &tail, l2, wan_dp)
return 1
```

`push_split_to_wan` — **cùng** `wan_dp`, **cùng** `dp_out_ring_idx()` (TX slot sticky của flow):

```
tx = &fwd->mid_to_wan[wan_dp][tx_slot]
cần 2 chỗ trống; không đủ → free tail, return -1 (frag0 chưa push)
job.len=l1; tail.len=l2; cả hai wan_idx=wan_dp, dir=WAN
ne_ring_try_push(tx, job)   // frag0
wake TX slot
ne_ring_try_push(tx, tail)  // frag1; fail → free chỉ tail, frag0 ĐÃ nằm ring
                            // nhận: frag0 treo table 200ms rồi GC = LOSS
```

Hai mảnh **không** pick WAN lần 2: lệch path thì không join được (timeout 200ms = loss). Datagram kế pick WAN mới — đó là stripe bonding, không phải lỗi split.

---

### 16.5 RX — nhận diện, decrypt mảnh, bảng, join, mã trả về

Chi tiết từng hàm / từng byte / chi phí copy để tối ưu ráp: **§16.8**. Tóm tắt dưới đây.

**Nhận diện mảnh** `wan_l2_is_udp_frag` / `l2_udp_is_fragment` (trước decrypt):

- Có marker 0x104A
- Byte magic-off == 0x5B
- `frag_index <= 1` (byte magic+3)
- reserved == 0 (byte magic+4)
- `l2_udp_is_fragment` thêm: `opt_policy_match` policy L2+PQC theo `policy_id` trên wire

False 0x5B trong CT gói nguyên: `wan_try_l2_pqc_frag` gọi `reassemble_l2` fail → restore `scratch` → return 0 → `decrypt_l2` thường.

**Worker:** `dp_crypto_pick_wan_worker` đọc byte 15. Đẩy `wan_to_mid[wi]`. Bảng `g_tables[profile_slot][wi]` — sai worker = hai nửa không gặp nhau → timeout 200ms = loss.

**`l2_udp_reasm`** (trong `crypto_option_reassemble(..., CRYPTO_PROTO_UDP, ...)`):

```
nd = l2_decrypt_fragment(ctx, pkt, *len, &pkt_id, &frag_index)
     // AES-GCM; memmove plaintext về l3_off (14)
     // frag0: inner = IP||UDP||half1
     // frag1: inner = half2 thuần
*len = nd
rr = l2_reassemble(opt_table(slot, worker), pkt, *len, pkt_id, frag_index, out, out_len)
return rr
```

`l2_reassemble`:

- `inner = pkt + wire_eth` (`wire_eth` = et_off+2 = 14), `inner_len = len - 14`
- `idx = opt_pick_slot(ft, pkt_id, now)`
- `frag_index==0`: inner phải IPv4 hợp lệ; `opt_store_first` copy **eth 14B** + inner vào `entry->first`
- `frag_index==1`: `opt_store_second` copy inner vào `entry->second` (không eth)
- `opt_emit_join` nếu `got_first && got_second`

`opt_emit_join`:

```
out = eth_hdr || first || second
crypto_eth_set_ipv4_et(out)     // 0x0800
clear entry
return 1  // *out_len = độ dài datagram plaintext gốc
return 0 nếu còn thiếu một nửa
```

Không sửa IP tot_len / UDP length / checksum lúc join — ghép byte đúng như lúc cắt thì độ dài tự khớp frame gốc.

**`reassemble_l2` trong wan_ingress** map mã:

| `crypto_option_reassemble` rr | ý | `pending` | `reassemble_l2` |
|-------------------------------|---|-----------|-----------------|
| 1 | join xong, pkt = datagram đầy | 0 | 0, `*len=blen` |
| 0 | đang đợi mảnh kia | held()? 2: **1** | 0 |
| khác | lỗi | — | -1 |

`crypto_l2_pqc_reasm_held()` **luôn 0** (copy vào `first[1600]/second[1600]`, không giữ UMEM). `pending==2` chết. `pending==1` = đợi.

**`wan_try_l2_pqc_frag`:** không phải frag → 0. Là frag + reasm ok → **1**. Reasm fail → restore scratch, return **0** (cho `decrypt_l2`).

**`decrypt_wan` rồi `dataplane_process_wan`:**

```
l2_fast = wan_try_l2_pqc_frag(...)
l2_fast==1 && pending==1 → decrypt_wan return 1 → ne_frame_free(job); return
                          // KHÔNG forward_wan_to_local — hold-gap
l2_fast==1 && pending==0 → job.len = datagram đã join; return 0 → TX LAN
l2_fast==0               → decrypt_l2 (gói nguyên)
```

Hold-gap (cơ chế OOO **không** cần 2 WAN, nhưng bài D cho thấy trên 1 WAN gần như không xảy ra — 45/71.3M):

```
t0  A-frag0  store, free frame, không TX LAN
t1  B nguyên (hoặc B đã join)  TX LAN ngay
t2  A-frag1  join A, TX LAN sau B
→ iperf: B trước A = out-of-order; A không lost
```

Trên 1 WAN, A.frag0 và A.frag1 kề nhau trên cùng NIC/TX ring → t1 hiếm khi cắt giữa hai mảnh của A. Trên 2 WAN, B đi WAN kia, join xong trong lúc A còn pending → t1 thường xuyên. Nhân ×2 split là hệ số; WRR 2 path là điều kiện.

---

### 16.5b Bảng reasm (chi tiết struct + slot)

```
g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS]   // calloc lần đầu opt_table()
struct opt_entry {
    uint16_t pkt_id;
    uint8_t  first[1600], second[1600];
    uint32_t first_len, second_len;
    uint8_t  eth_hdr[18], eth_len;
    uint64_t timestamp_ns;
    uint8_t  got_first, got_second;
};
struct opt_table { entries[4096]; }   // OPT_FRAG_TABLE_SIZE
```

`opt_pick_slot(pkt_id)`: `base = pkt_id % 4096`, probe **8** ô. Thứ tự: ô cùng `pkt_id` còn sống → ô trống (GC tại chỗ nếu age > 200ms) → occupied **già nhất** trong 8 (**evict**). Evict nửa đang chờ = mảnh kia timeout = **loss**.

`opt_prepare_entry`: nếu `pkt_id` khác hoặc entry cũ quá 200ms → `memset` entry.

`OPT_FRAG_TIMEOUT_NS = 200ms`. GC full table: `l2_udp_frag_gc` mỗi 2048 vòng `crypto_worker_thread` (`fwd_crypto_frag_gc_worker_tick`).

1600B đủ nửa MTU; `first_len+second_len+eth > NE_FRAME(2048)` → join fail, clear, -1.

---

### 16.5c Mã trả về tóm tắt (để debug)

| Hàm | 0 | 1 | -1 |
|-----|---|---|-----|
| `l2_udp_need_split` | không cắt | cắt | (không) |
| `encrypt_to_wan` | 1 frame, caller push | đã push 2 mảnh | drop |
| `l2_udp_reasm` / `l2_reassemble` | đợi mảnh kia | đã join | lỗi decrypt/store |
| `wan_try_l2_pqc_frag` | không frag / fail→thử decrypt_l2 | đã xử lý frag | (hiếm, decrypt_wan -1) |
| `decrypt_wan` | xong, forward | pending, free frame | drop |
| `dataplane_process_wan` dec==1 | — | free, không TX LAN | — |

### 16.6 Hai nguồn OOO

| Nguồn | Cơ chế | Iperf |
|-------|--------|--------|
| Per-packet 2 WAN (§7) | Datagram N → WAN0, N+1 → WAN1, delay khác; không có reorder buffer | OOO 15–54% @ 1.2G, loss vẫn ~0.1% |
| UDP split ×2 + crypto ×2 | 1 datagram = 2 frame + 2 AES TX + 2 AES RX | 1 WAN gần vô hại (bài D). 2 WAN nhân hold-gap và 2 queue |
| UDP reasm hold-gap | Frag0 giữ A, B đi trước, frag1 mới ra A | Nổ khi A và B khác WAN; 1 WAN gần 0 |
| 1 LAN+1 WAN đúng tải (bài D) | `n==1`, cùng ring, TX tuần tự | **8.38G, loss 0.16%, OOO 45/71.3M** |
| 1 LAN+1 WAN overrun (bài B cũ) | `fwd_wan_has_tx_room` drop | Loss cao — bão hòa NIC |
| Tắt per-packet | Sticky/window 1 WAN/flow | OOO giảm vì hết stripe |
| TX slot sticky | 1 flow 1 TX consumer trên **một** ring | Không giữ thứ tự giữa 2 ring 2 NIC |
| 2 mảnh cùng WAN+slot | push 0 rồi 1 | Code hiện tại làm vậy |

Bài D: OOO ~0 trong khi split vẫn bật → join không phải nguồn OOO hàng loạt; nguồn chính là 2 path × 2 mảnh.

### 16.7 Cách hai mảnh đang gắn với nhau

Hành vi hiện tại:

1. Hai mảnh cùng `pkt_id` cùng `worker_idx` trên wire → cùng crypto core RX.
2. Hai mảnh cùng `wan_dp` và cùng `tx_slot` lúc TX.
3. TCP MSS clamp, không split.
4. Reasm table per `(profile_slot, worker)`.
5. Frag1 không có IP/UDP header — join lấy L3 từ frag0.

Hệ quả: WRR từng *mảnh* sẽ làm hai nửa không gặp nhau. Timeout 200ms GC mảnh mồ côi; tăng timeout không sắp lại thứ tự vì B đã emit. Jumbo / payload nhỏ hơn ngưỡng `1500-35` thì `need_split=0`, hết hold-gap. UDP không có seq IP; phía nhận hiện emit ngay khi join, không buffer theo thứ tự datagram gốc.

---

## 16.8 Rã ráp UDP — chi tiết để tối ưu

Đây là ráp **datagram UDP đã cắt trên dataplane**, không phải ráp handshake PQC.

| Đây | Không phải đây |
|-----|----------------|
| `src/crypto/pqc/pqc_l2_option.c` — `l2_udp_reasm` / `l2_reassemble` / `opt_*` | `pqc_l2_handshake.c` `g_reassemble_list` (keying, list, không nằm hot path gói) |
| Gọi từ `wan_ingress.c`: `wan_try_l2_pqc_frag` → `reassemble_l2` → `decrypt_wan` → `dataplane_process_wan` | TCP / ICMP / OSPF / ARP — `need_split=0`, `reasm` TCP không cắt |
| TX cắt: `local_egress.c` `encrypt_to_wan` / `push_split_to_wan` / `l2_split` | `l2_do_encrypt` gói nguyên (UDP nhỏ hoặc TCP) |

Hằng số live:

| Tên | Giá trị | Ý |
|-----|---------|---|
| `OPT_FRAG_TABLE_SIZE` | 4096 | số ô / bảng |
| probe | 8 (hardcode trong `opt_pick_slot`) | cửa sổ linear từ `pkt_id % 4096` |
| `OPT_FRAG_TIMEOUT_NS` | 200 ms | GC mảnh mồ côi; không phải reorder window |
| `OPT_FRAG_META_LEN` | 35 | overhead **mảnh** trên dây (so MTU) |
| `crypto_option_wire_overhead(L2_PQC)` | 30 | overhead **gói nguyên** (không magic/tag) |
| MTU | 1500 (`CRYPTO_OPT_FRAG_MTU_DEFAULT`) | `crypto_option_get_mtu()` |
| `NE_FRAME` | 2048 | trần join / UMEM frame |
| `first[]`/`second[]` | 1600 | trần inner mỗi nửa |
| `ETH_L2_HDR_MAX` | 18 | 14 thường, 18 VLAN |
| `AES_GCM_TAG_SIZE` | 16 | đuôi mỗi mảnh |
| `PACKET_CRYPTO_NONCE_BYTES` | 12 | nonce trên header, ngoài GCM |
| `NE_CRYPTO_WORKERS` | 6 (CPU 3–8) | một bảng / worker |
| `MAX_PROFILES` | 32 mảng; live slot 0 | `g_tables[slot][W]` |
| GC tick | 2048 vòng `crypto_worker_thread` | full scan 4096 ô |

Một connect TCP/UDP = một crypto worker (sticky). WAN **không** sticky. Hai mảnh một datagram cùng worker, cùng WAN, cùng TX slot.

---

### 16.8.1 Cặp mảnh trên dây (đầu vào của ráp)

`l2_udp_need_split`: `(pkt_len + 35) > mtu`. `pkt_len` = **cả frame Ethernet** (14B + IP + UDP + app). Đúng **2** mảnh, không 3+. Cắt **app UDP**; IP header và UDP header nguyên trên frag0.

So sánh 35 vs 30: gói nguyên (`l2_do_encrypt`) phình `+30` (policy+core+nonce 14B thay ethertype area, + tag 16). Mảnh phình `+35` vì thêm magic 1 + tag 4. `need_split` dùng 35 → một số frame mà encrypt nguyên vẫn ≤1500 vẫn bị cắt. iperf `-l 1470` thì frame LAN 1512, cắt chắc.

Công thức `l2_split` (không VLAN, `l3_off=14`, IHL=20, UDP hdr=8):

```
frag_overhead = l3_off + 35 = 49
max_plain0    = 1500 - 49 = 1451     // trần inner frag0
fixed_plain0  = 20 + 8 = 28          // IP + UDP hdr, không cắt
half1         = 1451 - 28 = 1423     // app trên frag0
nếu half1 >= app_len: half1 = app_len - 1   // luôn để ≥1 byte cho frag1
half2         = app_len - half1
```

iperf `-l 1470`: `half1=1423`, `half2=47`.

```
frag0 plaintext = IPv4 (20) || UDP hdr (8) || app[0 .. 1423)     // 1451 B
frag1 plaintext = app[1423 .. 1470)                              // 47 B, không IP, không UDP
```

IP `tot_len` và UDP `length` trên frag0 **vẫn là giá trị gốc** (app 1470B). Join ghép `first||second` thì độ dài khớp datagram cũ; **không** tính lại checksum. Checksum UDP/IP gốc vẫn đúng vì payload sau join = payload lúc cắt.

`pkt_id` = `crypto_option_next_pkt_id()`: `atomic_fetch_add(&g_opt_pkt_id, 1) & 0xFFFF` trong `crypto_option_router.c`. **Một counter cả process**, mọi worker, mọi flow, LAN và (nếu có) chiều kia. Wrap 65536. Không gắn 5-tuple.

#### Layout mảnh trên dây (không VLAN)

`et_off = 12`. Byte:

```
 0–5    dst MAC
 6–11   src MAC
12–13   EtherType = 0x104A
14      policy_id          (plaintext)
15      worker_idx         (plaintext)  ← WAN RX hash vào wan_to_mid[W]
16–27   nonce 12B          (plaintext, input GCM)
28      magic 0x5B         (plaintext)
29–30   pkt_id big-endian  (plaintext)
31      frag_index 0|1     (plaintext)   opt_write_frag_tag buf[2]
32      reserved 0         (plaintext)   buf[3]
33…     ciphertext inner || GCM tag 16B
```

`enc_off = 33`. GCM phủ từ 33 đến hết frame. Tag, magic, `pkt_id` **không** nằm trong CT.

VLAN 802.1Q: `et_off=16`, mọi offset +4. Magic 32, `enc_off=37`. `ETH_L2_HDR_MAX=18` đủ copy eth (MAC+VLAN+et). Live iperf thường không VLAN.

Độ dài wire gần đúng (không VLAN):

| Mảnh | công thức | iperf 1470 |
|------|-----------|------------|
| frag0 | 33 + 1451 + 16 = 1500 | đúng MTU |
| frag1 | 33 + 47 + 16 = 96 | nhỏ |

#### Thứ tự encrypt / TX / mất mảnh

`l2_split`: encrypt **frag1 trước** vào buffer `tail` UMEM (`l2_encrypt_fragment_single`), rồi frag0 **in-place** lên frame gốc (`l2_encrypt_fragment0_inplace`). Hai nonce độc lập. Cùng `policy_id`, `worker_idx`, `pkt_id`.

`encrypt_to_wan`: `need_split` → `split_tail_take` (cache 32 frame/worker) → `crypto_option_split` → `push_split_to_wan`.

`push_split_to_wan` (`local_egress.c`):

1. Nếu `ne_ring_count(tx)+2 > cap` → free tail, return -1 (caller drop **cả** job gốc — chưa push mảnh nào).
2. `ne_ring_try_push(tx, job)` frag0. Fail → free tail, return -1.
3. `ne_ring_try_push(tx, tail)` frag1. Fail → **free chỉ tail**, return **0** (thành công phía caller). Frag0 đã nằm ring. Máy nhận treo frag0 ≤200ms rồi GC = **loss**. Không rollback frag0.

Hai mảnh cùng `wan_dp`, cùng TX slot (`dp_out_ring_idx()`). Không WRR từng mảnh.

---

### 16.8.2 Gói đi vào worker nào

WAN RX: `crypto_eth_l2_read_worker_idx` = byte 15 → `wan_to_mid[W]`. Crypto thread W gọi `reassemble_l2` với `dp_crypto_current_worker_idx()` = W. Bảng `g_tables[profile_slot][W]`. Chỉ thread đó đọc/ghi — **không lock**.

Sai worker (byte 15 ≠ thread đang chạy): hai nửa không chung bảng, 200ms GC = loss. Sticky crypto lúc LAN RX (`crypto_route.c`) ghi `worker_idx` lên header lúc encrypt, nên hai mảnh cùng W nếu cùng datagram.

`profile_slot` = `fwd_crypto_profile_slot_for_id(fwd_crypto_profile_id_for_wire_id(policy_id))`. Live một profile → slot 0. `opt_table` clamp slot/worker về 0 nếu out of range.

`opt_table` lần đầu `calloc(1, sizeof(opt_table))` (~13 MB). **Cả `l2_udp_frag_gc` cũng gọi `opt_table`**, nên tick GC 2048 vòng cấp bảng ngay cả khi worker chưa từng nhận UDP cắt. 6 worker × slot 0 ≈ **80 MB** sau vài giây chạy, không cần có split.

---

### 16.8.3 Nhận diện mảnh — trước AES

`wan_l2_is_udp_frag` (`wan_ingress.c`), **không decrypt**:

1. EtherType 0x104A (`crypto_eth_l2_has_marker`)
2. `mark_off = crypto_eth_l2_frag_magic_off(..., 12)` = core_id_off + 1 + 12 = **28** không VLAN, **32** VLAN
3. `pkt[mark_off] == 0x5B`
4. `frag_index = pkt[mark_off+3] <= 1`  (byte 31: `frag_index` trong tag)
5. `reserved = pkt[mark_off+4] == 0`    (byte 32)

Tag sau magic: `[id_hi][id_lo][frag_index][reserved]` = `opt_write_frag_tag`.

`l2_udp_is_fragment` thêm: đọc `policy_id`, `opt_policy_match(ENCRYPT_L2 + MODE_PQC + wire_id)`. Nhánh nhanh `wan_try_l2_pqc_frag` **không** gọi cái này — chỉ `wan_l2_is_udp_frag` rồi `fwd_policy_by_wire_id` / `fwd_crypto_ctx_for_wire_id`. `l2_udp_is_fragment` dùng ở fallback `decrypt_wan` (`crypto_option_is_fragment`).

Gói **không cắt**: offset 28 là ciphertext. Trùng 0x5B + reserved 0 + frag_index≤1 → false positive. `wan_try_l2_pqc_frag` đã `memcpy` scratch cả frame; `reassemble_l2` decrypt/store fail → restore scratch → return 0 → `decrypt_l2` (GCM gói nguyên, ops TCP).

---

### 16.8.4 Decrypt một mảnh — `l2_decrypt_fragment`

In-place trên UMEM frame hiện tại:

1. `l2_frag_magic_off`; fail nếu không 0x5B.
2. `opt_read_frag_tag` tại magic+1 → `pkt_id`, `frag_index` (còn plaintext).
3. `enc_off = magic+1+4` (=33 không VLAN). `crypto_pqc_decrypt_payload` từ `enc_off` đến hết (CT + tag 16).
4. `memmove(packet + l3_off, packet + enc_off, dec_len)` với `l3_off = prefix_len+2` (=14).
5. Return `l3_off + dec_len`. EtherType **vẫn 0x104A**.

Sau bước này:

| Mảnh | Buffer từ offset 14 |
|------|---------------------|
| 0 | IPv4 \|\| UDP \|\| half1 |
| 1 | half2 thuần (byte đầu **không** phải 0x45 trừ trùng ngẫu nhiên) |

Key `KEY_SLOT_CURRENT`. Nonce copy từ offset 16. AAD `HARDCODED_AAD` 8 byte `"TEST_AAD"` nhưng `aad_len=12` trong `crypto_pqc_sess_load`. `CipherInit` mỗi gói (`crypto_pqc_tls_cipher` giữ `SCryptCipherCtx` per-thread).

Decrypt fail (tag sai, key 0, len ngắn) → `l2_udp_reasm` -1 → `reassemble_l2` -1 → restore scratch.

---

### 16.8.5 Bảng — struct, RAM, layout cache

```
g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS]   // con trỏ; calloc trong opt_table()

struct opt_entry {                 // sizeof = 3248 (x86_64)
    uint16_t pkt_id;               // off 0
    uint8_t  first[1600];          // off 2     inner frag0
    uint32_t first_len;            // off 1604
    uint8_t  second[1600];         // off 1608  inner frag1
    uint32_t second_len;           // off 3208
    uint8_t  eth_hdr[18];          // off 3212  MAC + 0x104A (+VLAN)
    uint8_t  eth_len;              // off 3230
    uint64_t timestamp_ns;         // off 3232  CLOCK_MONOTONIC lúc store
    uint8_t  got_first;            // off 3240
    uint8_t  got_second;           // off 3241
    /* pad 6 → 3248 */
};

struct opt_table { entries[4096]; }   // 4096 × 3248 = 13 303 808 B ≈ 12.7 MiB
```

`opt_pick_slot` đọc `got_first`/`got_second`/`timestamp_ns`/`pkt_id` — ba field này nằm **hai đầu** struct (0 và 3232–3241). Probe 8 ô occupied = 8 lần nhảy ~3.2 KB. `opt_clear_entry` = `memset` **cả 3248 B**, kể cả khi chỉ cần hạ flag.

**Copy-based:** không giữ frame UMEM. `crypto_l2_pqc_bind_pair` / `reasm_set_addr` no-op. `crypto_l2_pqc_reasm_held()` **luôn 0**. `crypto_l2_pqc_reasm_out_addr()` **luôn 0**. `reassemble_l2` gọi `crypto_l2_pqc_reasm_set_addr(addr)` rồi bỏ qua. Join ghi đè `out_buf = pkt` (cùng UMEM mảnh vừa decrypt).

Pending: `dataplane_process_wan` `dec==1` → `ne_frame_free(job.addr)`. Dữ liệu mảnh chỉ còn trong `opt_entry`. Mảnh kia tới: decrypt vào frame mới, join vào frame đó, TX LAN. FQ UMEM không bị giữ.

`decrypt_wan` có nhánh `if (out_addr && out_addr != job->addr)` đổi frame — **chết** vì `out_addr` luôn 0.

---

### 16.8.6 Chọn ô — `opt_pick_slot` rồi `opt_prepare_entry`

Mỗi `l2_reassemble`: `now = opt_time_ns()` = `clock_gettime(CLOCK_MONOTONIC)` (mỗi mảnh, kể cả khi đôi đã đủ).

```
base = pkt_id % 4096          // uint16 % 4096 = 12 bit thấp
probe 8: idx = (base + i) % 4096, i = 0..7

với mỗi ô:
  occupied = got_first || got_second     // pkt_id bẩn sau memset? got=0 → trống
  nếu occupied && (now - ts) > 200ms → memset 3248B, occupied=0
  trống → nhớ empty_idx đầu tiên, continue
  occupied && e->pkt_id == pkt_id → return idx   // ưu tiên đôi đang chờ
  occupied khác id → theo dõi ô già nhất trong 8

return empty_idx, else oldest (EVICT), else base
```

Cùng `pkt_id` luôn cùng cửa sổ 8 (hash = id % 4096). Không chain, không tombstone.

Evict: `pick_slot` trả ô occupied **id khác**, chưa xóa. `opt_store_*` → `opt_prepare_entry`:

```
nếu entry->pkt_id != pkt_id
   hoặc (đã có dữ liệu và age > 200ms)
   → memset cả entry
gán pkt_id, timestamp_ns = now     // timestamp luôn refresh, kể cả khi thêm nửa thứ hai
```

Evict = mất nửa cũ. Mảnh kia của nửa cũ tới sau: `pick_slot` có thể cho ô mới, vẫn thiếu đôi → 200ms GC = loss.

Frag1 có thêm check trước `opt_store_second`: nếu cùng `pkt_id` và age > 200ms thì clear. `pick_slot` đã GC ô quá hạn trong cửa sổ 8, nên nhánh này gần như chết với cùng id trong cùng cửa sổ.

Không lock. Hai thread không đụng một `g_tables[][W]`.

---

### 16.8.7 Ghi mảnh — `opt_store_first` / `_second`

`l2_reassemble` sau pick:

**frag_index == 0**

- `inner = pkt + wire_eth` (`wire_eth = prefix_len+2` = 14), `inner_len = pkt_len - 14` (đã decrypt, không còn CT/tag).
- `inner_len < 20` hoặc nibble version ≠ 4 → -1 (frag1 nhầm 0, hoặc decrypt rác).
- IHL ≥ 20 và `inner_len ≥ IHL`.
- `opt_store_first`: copy `eth` `wire_eth` byte (còn 0x104A) + copy inner → `first`. `got_first=1`.
- `opt_emit_join`.

**frag_index == 1**

- Không kiểm tra IPv4.
- `opt_store_second`: copy inner → `second`. `got_second=1`.
- `opt_emit_join`.

`inner_len > 1600` → -1, drop mảnh đó (entry có thể đã prepare). iperf: first 1451, second 47.

Thứ tự tới: frag1 trước frag0 được. Frag1 store, join return 0. Frag0 store, join 1.

Trùng mảnh cùng phía: store đè, timestamp mới. Trùng frag0 khi đã có second: prepare giữ (cùng id), đè first, join ngay.

`frag_index` khác 0 và 1 → `l2_reassemble` -1. `wan_l2_is_udp_frag` đã lọc `<=1` nên nhánh này chỉ khi tag đổi giữa nhận diện và decrypt (không đổi — tag ngoài GCM).

---

### 16.8.8 Join — `opt_emit_join`

Chỉ khi `got_first && got_second`. Thiếu một nửa → return 0, entry giữ nguyên.

```
nếu first_len + second_len + eth_len > 2048 → memset entry, -1
memcpy out, eth_hdr, eth_len          // 14B, nguồn = bảng không phải pkt
memcpy out+14, first, first_len
memcpy out+14+first, second, second_len
crypto_eth_set_ipv4_et(out, eth_len-2)   // ghi 0x0800 tại offset 12
memset entry (3248 B)
return 1, *out_len = 14+first+second
```

`out_buf` = UMEM frame mảnh **vừa** decrypt (`reassemble_l2(..., pkt, ..., pkt, &blen)`). Overwrite an toàn vì nguồn là `entry->first/second` đã copy trước.

Không sửa IP tot_len, UDP length, checksum. Datagram ra LAN = Ethernet IPv4 UDP lúc vào encryptor.

`l2_udp_reasm` khi rr==1: `*pkt_len = *out_len` (trùng `blen` mà `reassemble_l2` gán `*len`).

---

### 16.8.9 Walk một datagram — RX từng bước

Ký hiệu: A cắt thành A0, A1. Crypto worker W. Không VLAN.

**A0 tới trước (thường, vì TX push 0 rồi 1)**

1. WAN RX → `wan_to_mid[W]` (byte 15).
2. `dataplane_process_wan`: `wan_l2_is_frag` → snapshot `wire_buf` **64B** (policy_id). Frame đầy đủ vẫn trong UMEM.
3. `decrypt_wan` → `wan_try_l2_pqc_frag`:
   - `memcpy(scratch, pkt, orig_len)` cả frame wire (~1500B) — **mọi** mảnh, kể cả ráp thành công.
   - `reassemble_l2`: `crypto_option_reassemble(L2_PQC, UDP, slot, W, ctx, pkt, len, pkt, &blen)`.
4. `l2_udp_reasm`: AES-GCM A0 → memmove inner về 14 → `l2_reassemble`.
5. `opt_pick_slot` ô trống, `opt_store_first` memcpy 14+1451, `opt_emit_join` return 0.
6. `reassemble_l2`: `pending = held()?2:1` → **1**. return 0.
7. `wan_try_l2_pqc_frag` return 1. `decrypt_wan` return 1.
8. `ne_frame_free(A0)`. Không FDB, không TX LAN. A nằm bảng.

**A1 tới**

1–4 như trên, decrypt inner 47B.
5. `opt_pick_slot` tìm cùng `pkt_id`, `opt_store_second` memcpy 47, `opt_emit_join` memcpy 14+1451+47 ra UMEM A1, memset entry, return 1.
6. `pending=0`, `job.len=1512`, `decrypt_wan` return 0.
7. `out_addr` 0, không đổi frame. FDB, `forward_wan_to_local` datagram A.

Giữa bước 8 của A0 và bước 7 của A1, worker có thể ráp xong B và TX LAN B → hold-gap OOO.

**A1 tới trước A0:** store second, pending free A1; A0 tới join trên frame A0. Cùng đúng.

---

### 16.8.10 Chuỗi mã trả về

`l2_udp_reasm` / `l2_reassemble`: 0 đợi / 1 xong / -1 lỗi.

`reassemble_l2`: rr=1 → `*len=blen`, pending không set (0). rr=0 → pending 1. rr khác → -1.

`wan_try_l2_pqc_frag`: không phải frag → 0. reasm ok → **1**. reasm -1 → restore scratch, pending=0, return **0**.

`decrypt_wan` khi `l2_fast==1`:

| pending | return | `dataplane_process_wan` |
|---------|--------|-------------------------|
| 2 | 2 | không xảy ra (`held=0`); comment cũ “giữ UMEM” |
| 1 | 1 | `ne_frame_free`; **không** TX LAN |
| 0 | 0 | join xong; policy_in; TX LAN |

Nhánh chậm `l2_fast==0`: `decrypt_l2` dùng ops **TCP** (`l2_do_decrypt` gói nguyên, không đọc 0x5B). Fail + `is_fragment` → `reassemble_l2` lần nữa (AES lần hai nếu lần một đã fail — thường drop). False 0x5B: lần reasm đã fail, restore, `decrypt_l2` thành công.

`dec==2`: `dataplane_process_wan` `return` **không** free — nhánh chết. Nếu `held` bao giờ trả 1, frame leak.

---

### 16.8.11 Hold-gap (OOO do ráp, không do loss)

Mảnh thứ nhất: store, free UMEM, không TX LAN. Mảnh thứ hai: join, TX LAN ngay. **Không** so sánh seq với datagram khác cùng 5-tuple. UDP không có IP ID dùng cho thứ tự.

```
t0  A0  store A, free frame
t1  B đủ 2 mảnh (hoặc B không cắt)  TX LAN B
t2  A1  join A, TX LAN A
→ iperf: B trước A = OOO; A không lost
```

1 WAN bài D: A0 và A1 kề trên một NIC/TX ring → t1 hiếm (45 OOO / 71.3M). 2 WAN: B trên path nhanh join trong lúc A pending mảnh path chậm → t1 thường xuyên. Tăng `OPT_FRAG_TIMEOUT_NS` không sắp lại thứ tự: B đã emit ở t1.

Ráp **không** tạo OOO giữa hai mảnh của A (chúng không TX riêng). OOO là giữa datagram A và B.

---

### 16.8.12 `pkt_id` wrap, occupancy, evict

Wrap 16-bit, global mọi worker:

| Tốc độ datagram cắt | Wrap | vs timeout 200ms |
|---------------------|------|------------------|
| 100k/s (~1.2G `-l 1470`) | ~0.65 s | 200ms ≪ wrap, ít trùng id còn sống |
| 1M/s | ~65 ms | wrap < timeout → id mới đụng entry cũ cùng id |

Hai worker cắt độc lập vẫn `fetch_add` chung → wrap nhanh hơn tổng PPS cắt.

Pending đồng thời ≈ (thời gian A0→A1) × datagram/s trên **một worker**. 1 WAN: A0/A1 kề, pending ~1–vài ô. 2 WAN skew 2ms × 100k dps / 6 worker ≈ ~33 ô/worker nếu tải đều — probe 8 **không** phải 4096; 8 ô cửa sổ mới là trần va chạm. Hash 12 bit; 33 pending rải 4096, P(cùng cửa sổ 8) thấp. Skew lớn + nhiều flow dồn một worker (sticky) → đầy 8 → evict = loss.

`pkt_id % 4096` bỏ 4 bit cao. Id cách 4096 map cùng base.

---

### 16.8.13 GC định kỳ

`crypto_worker_thread`: `++gc_tick >= 2048` kể cả vòng idle → `fwd_crypto_frag_gc_worker_tick(w)`:

1. `clock_gettime` lần nữa.
2. Worker 0: `flow_table_gc_slice` (bảng WAN/flow cũ, **không** phải reasm).
3. Mọi worker: `crypto_option_frag_gc_all(0, w)` → `l2_udp_frag_gc` → `opt_table` (calloc nếu null) → `opt_frag_gc_table`: for i in 0..4095, nếu occupied && age>200ms → `memset` 3248B.

GC trong `opt_pick_slot` chỉ 8 ô đang probe. Full scan bắt ô không ai đụng (mảnh mồ côi đứng yên). 2048 vòng idle trên crypto core vẫn scan 13 MB.

---

### 16.8.14 Chi phí byte trên hot path

Một datagram cắt = 2 mảnh RX. iperf 1470, không VLAN, ráp thành công, A0 trước A1:

| Bước | A0 | A1 (join) |
|------|----|-----------|
| scratch copy wire | ~1500 | ~96 |
| AES-GCM decrypt | 1451+16 | 47+16 |
| memmove inner về 14 | 1451 | 47 |
| clock_gettime | 1 | 1 |
| probe 8 × đọc flag cuối struct | 8 | 8 |
| memcpy vào bảng | 14+1451 | 47 |
| memcpy join ra UMEM | — | 14+1451+47 |
| memset entry 3248 | — (pending) | 3248 |
| ne_frame_free | có | không |
| snapshot wire_buf | 64 | 64 |

TX (chiều gửi, không phải ráp nhưng tạo input ráp): 2 AES encrypt, 1 `split_tail_take`, 2 `ne_ring_try_push`, alloc batch 32 khi cache cạn.

False 0x5B: scratch copy + decrypt frag fail + restore + `decrypt_l2` (scratch lần nữa trong `decrypt_l2`).

---

### 16.8.15 Việc ráp **không** làm

- Không reorder datagram theo 5-tuple / UDP seq / IP ID.
- Không giữ UMEM (`held=0`).
- Không sửa L3/L4 lúc join.
- Không lock, không atomic trên `opt_entry`.
- Không WRR lại hai mảnh; không đổi WAN lúc TX.
- Không ráp TCP (MSS clamp 1500/30 → không `need_split`).
- Không dùng `pqc_l2_handshake.c` list.
- Timeout 200ms = GC orphan, không phải buffer sắp thứ tự.

---

### 16.8.16 Chỗ logic chạm khi tối ưu ráp

Hành vi hiện tại, từng khâu — đổi khâu nào thì hệ quả đi theo:

| Khâu | Việc đang làm | Hệ quả gắn với ráp |
|------|----------------|-------------------|
| Copy `first[1600]`/`second[1600]` | Không giữ UMEM | 2 memcpy/mảnh + join; pending không chiếm FQ; `memset` 3248B/join |
| Flag/timestamp ở cuối struct 3248B | Probe đọc cuối ô | 8 cache miss / pick |
| `held`/`out_addr` = 0 | API giữ frame không gắn | Join in-place frame mảnh sau; nhánh `dec==2` chết |
| Scratch full frame trước mọi reasm | Rollback false 0x5B | Copy ~1500B cả khi ráp đúng |
| `pkt_id` u16 global `fetch_add` | Không per-flow, không per-worker | Wrap theo tổng PPS cắt |
| Probe 8 + evict oldest + `prepare_entry` clear | Không chain | Đầy cửa sổ 8 → loss nửa |
| Timeout 200ms | GC orphan | Không phải reorder; tăng timeout không giảm OOO hold-gap |
| Emit ngay khi `got_first && got_second` | Không seq datagram | Hold-gap với datagram khác |
| `clock_gettime` / mảnh | ts từng store | |
| GC `opt_table()` | calloc bảng trên tick | 13 MB/worker dù chưa có UDP cắt |
| Full scan 4096 / 2048 vòng | kể cả idle | |
| 2 mảnh cùng WAN+slot, TX 0 rồi 1 | | Ráp đúng; OOO 2 WAN do datagram khác path |
| `need_split` +35 vs encrypt nguyên +30 | Cắt sớm hơn | Nhiều datagram vào bảng hơn mức “vượt MTU sau encrypt nguyên” |
| `push_split` fail mảnh 1 sau mảnh 0 queued | không rollback | orphan 200ms = loss |
| Jumbo / `pkt_len+35 ≤ 1500` | không vào bảng | hết ráp; một GCM |

Bài D (1 WAN, 8.38G, OOO 45/71.3M): bảng + join không phải nguồn OOO hàng loạt. 2 WAN: hold-gap × WRR per-packet mới nổ. Tối ưu copy/probe/GC là CPU/latency; tối ưu OOO bonding là emit-policy hoặc hết cắt, không phải tăng timeout.

---

## 17. Phân tích: vì sao 2 WAN OOO, 1 WAN thì không

Luồng từng bước: **§18**. Dưới đây là hệ số trên đường đi hiện tại — chưa có reorder buffer, chưa jumbo.

### 17.1 Đối chứng bài D

Bài D: **cùng** L2 PQC, **cùng** `need_split`, **cùng** 2 AES encrypt + 2 AES decrypt / datagram, **cùng** bảng reasm 200ms — chỉ khác `pool_n==1`. Kết quả 8.38G / 0.16% loss / 45 OOO.

Không phải AES làm hỏng thứ tự, không phải bảng reasm hỏng, không phải TX slot sticky hỏng, không phải “1 connect 1 crypto core” hỏng.

Là `g_pkt_wrr_seq` rải datagram liên tiếp sang 2 NIC trong khi mỗi datagram đã nhân ×2 frame + ×2 crypto. Hai queue độc lập + hold-gap (A chờ frag1 WAN0, B đã join trên WAN1) + TX drain xen kẽ 2 WAN + không reorder buffer → iperf OOO.

Công thức nhân (iperf `-l 1470`, MTU 1500):

```
1 datagram UDP gốc
  → 2 wire frames (frag0 + frag1)
  → 2 AES-GCM encrypt (LAN crypto)
  → 2 lần TX WAN  (cùng wan_dp, cùng tx_slot)
  → 2 lần RX WAN  (lệch delay nếu 2 datagram khác WAN)
  → 2 AES-GCM decrypt
  → 1 join (hoặc hold-gap 200ms nếu thiếu mảnh)
  → 1 datagram ra LAN

71.3M datagram bài D  →  ~142.6M frame wire  →  ~142.6M enc + ~142.6M dec
```

1 WAN: 142.6M frame một `mid_to_wan[0][slot]`, TX tuần tự `N.f0, N.f1, N+1.f0, N+1.f1` → join gần như in-order.

2 WAN weight 50/50: datagram chẵn WAN0 (2 frame), lẻ WAN1 (2 frame). Cùng stream, cùng crypto worker, cùng TX **slot** nhưng **hai ring**. Bốn frame của hai datagram cạnh nhau không còn thứ tự trên một NIC.

### 17.2 Các khâu trên đường đi (code hiện tại)

`g_pkt_wrr_seq` một counter toàn cục:

- Không gắn flow — stripe theo nhịp **xong encrypt**, không theo seq UDP.
- Không gắn delay WAN — weight 50/50 kể cả khi một đường chậm hơn.
- Header 0x104A không có seq bonding — máy nhận emit ngay khi join.
- `fwd_wan_has_tx_room` fail thì drop, không thử WAN kia.
- `tx_thread` drain `for wi in wans` — burst WAN0 rồi WAN1.
- Split: pick một lần / datagram (hai mảnh cùng WAN); datagram k và k+1 có thể khác WAN → hold-gap.
- Crypto worker pop `wan_to_mid` trước `local_to_mid` — chiều về xen chiều đi trên cùng core.

Chỗ hệ số nằm:

- **Split ×2** (`need_split` khi `pkt_len+35 > 1500`): mỗi datagram 2 AES + 2 frame + 1 join. Jumbo / payload nhỏ thì hết hold-gap; OOO còn lại chỉ lệch delay 2 WAN.
- **Không reorder sau join:** UDP không có seq trên wire sau khi ráp; B ra LAN trước A nếu A còn pending mảnh.
- **Counter global:** 6 worker + nhiều stream cùng `fetch_add` làm lịch stripe một flow không đều.
- **Ring đầy:** drop; 2 WAN chia hàng nên loss thấp hơn 1 WAN overrun, đổi lại OOO.
- **TX xen 2 NIC:** thứ tự emit ≠ thứ tự datagram.

Sticky WAN / window 10MB / “một connect một WAN” cũng làm OOO giảm — vì hết stripe, không còn gộp kênh. WRR từng mảnh (frag0 WAN0, frag1 WAN1) thì hai nửa không gặp nhau → loss 200ms.

---

## 18. Luồng per-packet — từng bước

File: `local_egress.c`, `wan_scheduler.c`, `flow_table.c` (`flow_table_pick_wan_per_packet`), `crypto_route.c`, `forwarder.c`, `pqc_l2_option.c`, `wan_ingress.c`.

Per-packet **chỉ chọn WAN**. Crypto worker và TX slot **sticky theo 5-tuple**. ARP không đi WRR này.

### 18.1 Một datagram UDP iperf đi hết hệ thống

Giả sử: profile 2 WAN weight 50/50, MTU 1500, Ethernet+IPv4+UDP+1470 ≈ 1512B, `need_split=1`. Flow đã gán `worker_idx=W`, `tx_slot=S`.

```
[LAN client]  UDP datagram N
     │
     ▼
CPU 0  local_rx_thread
     ne_recv_local_slot (batch ≤ 64)
     dataplane_local_needs_mid?  policy ≠ BYPASS → YES
     dp_crypto_pick_local_worker()  → (W, S) sticky 5-tuple
     job.tx_slot = S
     push local_to_mid[W]
     wake CRYPTO(W)
     │
     ▼
CPU 3–8  crypto_worker_thread[W]
     pop wan_to_mid[W] trước (decrypt chiều về), rồi pop local_to_mid[W]
     dp_out_ring_bind(job.tx_slot)   // TLS tx_slot = S
     dataplane_process_local:
       parse 5-tuple
       pick_profile_policy → profile_idx, cp
       ╔══════════════════════════════════════════════════════╗
       ║  wan_dp = fwd_wan_pick_for_local(...)                ║
       ║  ← ĐÂY LÀ PER-PACKET. 1 lần / datagram gốc.          ║
       ╚══════════════════════════════════════════════════════╝
       !fwd_wan_has_tx_room(wan_dp)?  DROP cả job (chưa encrypt)
       TCP? clamp MSS (UDP bỏ qua)
       encrypt_to_wan(..., wan_dp):
         need_split?  YES
         split_tail_take → frame UMEM thứ 2
         crypto_option_split → AES frag1 rồi AES frag0 in-place
         push_split_to_wan(frag0, frag1, wan_dp)  // CÙNG wan_dp, CÙNG S
         return 1  → caller KHÔNG push_to_wan lần nữa
     │
     ▼
  mid_to_wan[wan_dp][S]   chứa 2 ne_packet: frag0 rồi frag1
     │
     ▼
CPU 1/2/9/10  tx_thread[S]
     drain CQ
     for li: dp_burst_tx_local
     for wi in 0..wan_count-1:          // XEN KẼ MỌI WAN
         dp_burst_tx_wan(fwd, wi, S)
     → sendto / XDP TX lên NIC wan_dp
     │
     ▼
[dây WAN 0 hoặc WAN 1]  2 frame 0x104A + magic 0x5B, cùng pkt_id, frag 0 rồi 1
     │
     ▼
Máy nhận  CPU 11  wan_rx_thread
     đọc worker_idx byte 15 → push wan_to_mid[W]   (cùng W vì TX ghi W)
     │
     ▼
crypto_worker_thread[W]  (máy nhận)
     dataplane_process_wan
     decrypt_wan → wan_try_l2_pqc_frag
       AES decrypt mảnh
       l2_reassemble bảng g_tables[profile][W]
       mảnh 1/2: pending → free frame, KHÔNG TX LAN   (hold-gap)
       đủ 2 mảnh: join → 1 Ethernet IPv4 UDP gốc
     forward_wan_to_local → mid_to_local[li][S']
     │
     ▼
tx_thread  TX LAN → client iperf
```

Pick WAN **không** chạy chiều WAN→LAN. Gói mã hóa đã “dính” NIC lúc TX.

### 18.2 `fwd_wan_pick_for_local` — từng lệnh

File `wan_scheduler.c`. Mọi 5-tuple / `flow_ok` / `window_bytes` là `(void)` — **cố ý**.

1. `profile_idx` hợp lệ? Không → `pick_least_loaded_wan` (độ sâu ring), **không** WRR.
2. `fwd_wan_build_profile_pool(p)`:
   - Duyệt `p->wan_indices[]`. `weight<=0` bỏ (ARP-only).
   - WAN chết / ramp=0: cộng `dead_weight` rồi chia đều cho WAN sống.
   - Join ramp 0–100% scale weight.
   - Drain taper: WAN đang rút vẫn vào pool, weight giảm theo thời gian.
   - Output: `allowed_wans[]` = **index config**, `allowed_weights[]`, `pool_n`.
3. `pool_n<=0` → least-loaded.
4. `flow_table_pick_wan_per_packet(allowed_wans, allowed_weights, pool_n)` → `wan_cfg`.
5. `fwd_wan_live_dp_for_cfg(wan_cfg)` → dataplane slot `dp`. Fail → `fwd_wan_dp_for_legacy_cfg` (drain).
6. `!fwd_wan_dp_ok_for_new_traffic(dp)` (stopped / admin-hold / draining / failover-exclude) → least-loaded.

**Không** gọi `fwd_wan_has_tx_room` trong hàm pick. Room check nằm **sau**, ở `dataplane_process_local`: fail → drop, **không** thử WAN kia.

`pick_least_loaded_wan` (chỉ invalid/dead, không phải ring đầy): nếu `selected` còn room thì giữ; không thì WAN cùng profile còn room, depth `mid_to_wan` nhỏ nhất. Weight=0 không vào fallback data.

### 18.3 `flow_table_pick_wan_per_packet` — từng lệnh

File `flow_table.c`. State duy nhất: `static _Atomic uint64_t g_pkt_wrr_seq` (cả process, **mọi** flow, **mọi** worker, TCP+UDP+bypass).

```
if (!wans || allowed_count <= 0)  return 0
if (allowed_count == 1)           return wans[0]   // KHÔNG fetch_add — bài D đi đây
S = tổng weight > 0
k = atomic_fetch_add(&g_pkt_wrr_seq, 1)            // tăng TRƯỚC khi chọn
if S > 0: return wrr_slot_to_wan(k % S, ...)
else:     return wans[k % allowed_count]
```

`wrr_slot_to_wan(slot, wans, weights, n, S)`:

```
s = ((slot % S) + S) % S
acc = 0
for i in 0..n-1:
    if weights[i] <= 0: continue
    acc += weights[i]
    if s < acc: return wans[i]
return wans[n-1]
```

2 WAN weight 50/50, S=100: `k%100 < 50` → WAN config 0, else WAN 1. Gói k, k+1, k+2 **luân phiên** *nếu không có flow khác xen*. Thực tế 6 worker + 10 stream cùng `fetch_add` → thứ tự stripe của **một** iperf stream = thứ tự các datagram **xong encrypt trên core W**, xen với mọi flow khác trên mọi core.

`flow_table_init` `atomic_store(&g_pkt_wrr_seq, 0)`. Dataplane **không** gọi `flow_table_get_wan` / `flow_table_get_wan_profile`.

### 18.4 Sau pick — encrypt ×2 rồi hai frame vào **một** ring

`fwd_wan_has_tx_room`: `ne_ring_count(mid_to_wan[dp][tls_tx_slot]) + 64 < 16384`. Slot là TLS `dp_out_ring_idx()` = S của flow, **không** phải “cả WAN”. Hết chỗ cột S của WAN đã pick → drop cả datagram (kể cả WAN kia trống).

`encrypt_to_wan` (`local_egress.c`):

| Điều kiện | Việc | Số AES | Số frame TX |
|-----------|------|--------|-------------|
| UDP `need_split` | split + `push_split_to_wan` | **2** | **2** cùng `wan_dp`, cùng S |
| UDP vừa / TCP / ICMP | `crypto_option_encrypt` + caller `push_to_wan` | 1 | 1 |

`push_split_to_wan`: cần 2 slot trống trên `mid_to_wan[wan_dp][S]`. Push frag0, wake TX, push frag1. Frag1 fail → mất đuôi, frag0 đã trên ring → máy nhận treo table 200ms = **loss** (không phải OOO).

Hai mảnh **không** pick WAN lần 2. Datagram **kế** mới `fetch_add` → có thể WAN kia.

### 18.5 TX thread — vì sao 2 WAN đảo thứ tự ngay lúc gửi

`tx_thread(S)` mỗi vòng:

```
ne_drain_cq_local; ne_drain_cq_wan
for li: dp_burst_tx_local(li, S)
for wi = 0 .. wan_count-1:
    if !stopped: dp_burst_tx_wan(wi, S)
```

`dp_burst_tx_wan` drain `mid_to_wan[wi][S]` tối đa `DP_TX_BURST_MAX` burst. Hệ quả:

- Cùng S, WAN0 và WAN1 là **hai consumer ring độc lập**.
- Datagram N (WAN0, 2 frame) và N+1 (WAN1, 2 frame) không có thứ tự toàn cục lúc emit.
- Burst WAN0 có thể phun nhiều datagram chẵn trước khi WAN1 được drain → phía dây: chùm WAN0 rồi chùm WAN1, hoặc ngược lại tùy độ đầy ring.
- 1 WAN (`wan_count==1`): vòng `for wi` chỉ một NIC → thứ tự ring = thứ tự encrypt = thứ tự datagram (frag0 rồi frag1 từng cặp) → bài D OOO ~0.

### 18.6 Máy nhận — decrypt ×2, hold-gap, không reorder

WAN RX **không** pick WAN. `dp_crypto_pick_wan_worker` đọc byte 15 → đúng core W (bảng reasm per worker).

`decrypt_wan`:

- `wan_try_l2_pqc_frag` nếu magic 0x5B: AES mảnh + `l2_reassemble`.
- `pending==1` (dec return 1): free frame ingress, **không** `forward_wan_to_local` — datagram chưa ra LAN.
- `pending==2` (held): tương tự, frame giữ trong table (hiện copy-based, `reasm_held` thường 0 — xem §16).
- Join xong (dec 0): một IPv4 UDP → `forward_wan_to_local` ngay. **Không** so sánh seq với datagram trước.

Hold-gap 2 WAN:

```
t0  WAN0 RX  N.frag0   → store first, pending, không TX LAN
t1  WAN1 RX  N+1.frag0 → store
t2  WAN1 RX  N+1.frag1 → join N+1 → TX LAN   // iperf thấy N+1 trước
t3  WAN0 RX  N.frag1   → join N → TX LAN     // OOO
```

1 WAN bài D: N.frag0, N.frag1 thường kề nhau trên cùng NIC → join N trước N+1 → 45 OOO / 71.3M.

`crypto_worker` pop `wan_to_mid` **trước** `local_to_mid`: chiều về được ưu tiên decrypt. Không khôi phục thứ tự cross-WAN.

### 18.7 Bypass và TCP trên cùng per-packet

Bypass: RX LAN **không** vào crypto 3–8. `dataplane_process_local` trên CPU 0 vẫn `fwd_wan_pick_for_local` + `push_to_wan` — **cùng** `g_pkt_wrr_seq`. 1 datagram = 1 frame, không ×2. OOO 2 WAN lúc đó chỉ lệch path, không hold-gap.

TCP: MSS clamp 1500/30 → không split. Vẫn per-packet WRR mỗi segment. TCP stack tự SACK/reorder; iperf TCP không in “datagrams out-of-order”. Một thời kỳ sticky WAN từng đưa cả TCP lên một NIC.

### 18.8 Tóm tắt hành vi pick + split

1. Pick WAN một lần / datagram gốc, trước split. Hai mảnh cùng `wan_dp` + cùng `tx_slot`.
2. Đúng 1 WAN live (`allowed_count==1`): không `fetch_add`, không stripe.
3. Hàm pick live không đọc 5-tuple (tham số `(void)`).
4. `g_pkt_wrr_seq` tăng mỗi datagram khi `n>=2`, mọi flow/worker dùng chung.
5. Crypto worker + TX slot sticky theo flow — không phải gộp kênh.
6. Không có seq bonding trên 0x104A — máy nhận không sắp lại sau 2 path.
7. TCP clamp / ARP 0x1048 / `worker_idx` byte 15 độc lập với WRR WAN.

---

## 19. Lớp mã hóa đang chạy và code còn sót

Dataplane encrypt hiện tại: **L2 PQC** (`CRYPTO_OPT_L2_PQC`) và **bypass** (không mã hóa). Không còn file option L3/L4/CTR. AES-GCM là primitive bên trong L2 PQC (`trf_encrypt_payload_gcm`), không phải policy mode `CRYPTO_MODE_GCM` cũ.

Lớp DB (`src/db/*`, `schema.sql`) vẫn parse action L3/L4 và method `aes-ctr` / `aes-gcm`, rồi **ghi đè** thành L2 + PQC lúc load. Parser/schema nằm ngoài dataplane; tài liệu này không mô tả chúng. Enum trên `config.h` (`ENCRYPT_L3/L4`, `CRYPTO_MODE_CTR/GCM`, `cp->key[]`) vẫn có vì load DB ghi vào struct — core encrypt không đọc mode/key đó.

### 19.0 Bốn lớp trong tree

| Lớp | Là gì | Trên dataplane |
|-----|--------|----------------|
| **A. Encrypt option** | `CRYPTO_OPT_L2_PQC` / `CRYPTO_OPT_BYPASS` | `encrypt_to_wan` hardcode L2 PQC. Bypass = không gọi option encrypt. Không có `options/l3*.c` / `l4*.c` |
| **B. AES-GCM primitive** | `trf_encrypt_payload_gcm` / decrypt trong `traffic_crypto.c` | Live. Mọi payload L2 PQC (TCP/UDP/ICMP/OSPF/ARP) GCM 256 + tag 16B + nonce 12B. Khác `CRYPTO_MODE_GCM` trên policy |
| **C. Policy struct + DB** | `ENCRYPT_L3/L4`, `CRYPTO_MODE_CTR/GCM`, `ne_parse_method`, `cp->aes_bits`, `cp->key[]` | Load DB parse rồi coerce L2+PQC. Core encrypt không đọc mode/key. Parser/schema không thuộc dataplane |
| **D. Handshake L2 vs L3** | `pqc_handshake.c`: `is_bridge_mode` → Ethernet 0x88B5/0x88B6; `is_tunnel` → UDP `:7090` `[PQC-HS-L3]` | Bridge = HS L2. HS L3 là trao key kiểu tunnel, không mã hóa payload L3 |

Tóm tắt live encrypt LAN→WAN:

```
cp->action == BYPASS  → CPU 0 push_to_wan, không AES, không option ops
cp->action != BYPASS  → luôn CRYPTO_OPT_L2_PQC (kể cả DB ghi L3/L4)
                          AES-GCM qua crypto_pqc_encrypt_payload
                          key = sig_pqc_diversify_key (handshake), không phải cp->key
```

---

### 19.1 Struct — dataplane crypto

#### `struct crypto_option_ops` (`inc/crypto/crypto_option.h`)

Bảng hàm per `(option_id, proto)`. Live chỉ 2 option × vài proto.

| Field | Việc | L2 PQC UDP | L2 PQC TCP/ICMP/OSPF/ARP | Bypass |
|-------|------|------------|--------------------------|--------|
| `need_split` | 1 nếu cắt | `l2_udp_need_split` | `opt_no_frag_need_split` → 0 | 0 |
| `split` | cắt + encrypt 2 mảnh | `l2_udp_split` | return -1 | -1 |
| `encrypt` | 1 frame | `l2_udp_encrypt` (= `l2_do_encrypt` nếu không cắt) | `l2_tcp/icmp/ospf/arp_encrypt` | no-op 0 |
| `decrypt` | 1 frame nguyên | `l2_udp_decrypt` | tương ứng | no-op 0 |
| `is_fragment` | nhận 0x5B | `l2_udp_is_fragment` | 0 | 0 |
| `reasm` | join 2 mảnh | `l2_udp_reasm` | -1 | -1 |
| `frag_gc` | timeout 200ms | `l2_udp_frag_gc` | no-op | no-op |

`g_ops[CRYPTO_OPT_COUNT][CRYPTO_PROTO_COUNT]` trong `crypto_option_registry.c`. `CRYPTO_OPT_COUNT=2`. **Không** có slot L3/L4.

`crypto_option_ops(id, proto)`: id lệch → BYPASS; ops NULL → BYPASS. Dataplane **không** gọi `CRYPTO_OPT_BYPASS` trực tiếp — bypass không vào `encrypt_to_wan`. Registry bypass chỉ fallback.

#### `struct packet_crypto_ctx` (`inc/crypto/packet_crypto.h`)

Ctx AES/PQC per policy (và ARP static).

| Field | Ý nghĩa trên dataplane |
|-------|------------------------|
| `master_key[32]` | ARP: HMAC-SHA256 epoch 0 → 3 slot giống nhau. Encrypt policy không dùng master DB. `packet_crypto_init` chỉ ARP |
| `keys[3][32]` | PREV/CURRENT/NEXT. PQC: 3 slot cùng traffic key diversify |
| `initialized` | 1 sau init/rebuild |
| `crypto_mode` | Live ctx gán `CRYPTO_MODE_PQC`. Core không đọc CTR/GCM |
| `policy_id` | `cp->db_id` cho `sig_pqc_diversify_key` |
| `wire_id` | `cp->id` 1..255 ghi byte 14 trên 0x104A |
| `profile_id` | profile id |
| `aes_bits` | ARP 256; policy ctx thường 0 vì không `packet_crypto_init` |
| `pqc_from_handshake` | 1 = refresh từ HS; 0 = ARP static |

Hàm:

- `packet_crypto_init(ctx, master, aes_bits)` — **chỉ ARP** (`arp_bridge.c`). Set mode PQC, `fill_static_slots` HMAC-SHA256(master, epoch=0).
- `packet_crypto_get_key(ctx, slot)` — encrypt/decrypt đọc `KEY_SLOT_CURRENT`.
- `packet_crypto_update_keys` / `packet_crypto_refresh_pqc_keys` — `sig_pqc_diversify_key(profile_id, policy_id, out)`. Fail + key zero → `pqc_clear_ctx_keys`. Chỉ khi `crypto_mode==PQC && pqc_from_handshake`.

#### `crypto_pqc_sess_t` (`src/crypto/pqc/include/crypto_pqc_layer.h`)

`key`, `aad`, `aad_len`. AAD hardcode 12B `"TEST_AAD..."`. `crypto_pqc_sess_load` lấy CURRENT, chặn all-zero. `crypto_pqc_tls_cipher(enc)` — `__thread` `SCryptCipherCtx*` enc/dec, `CipherInit` mỗi gói. Đây là AEAD GCM của L2 PQC.

#### `struct crypto_policy` (`inc/core/util/config.h`)

Match 5-tuple + action. Live action sau load: **chỉ** `BYPASS=0` hoặc `ENCRYPT_L2=2`.

| Field | Trên dataplane |
|-------|----------------|
| `id` | wire id 0=bypass, 1–255 encrypt |
| `db_id` | id policy (HS bind) |
| `priority`, `protocol`, port/CIDR/any/negate | match 5-tuple |
| `action` | Sau load: 0 hoặc 2 (DB có thể parse 3/4 rồi coerce) |
| `crypto_mode` | bị ghi đè PQC; core encrypt không đọc |
| `aes_bits` | bị ghi đè 256 |
| `key[32]` | memset 0; traffic key từ handshake |

`config_select_crypto_policy` — match, **không** nhìn mode. `local_egress`: `action==BYPASS` vs else encrypt L2.

#### `struct app_config`

`crypto_enabled`, `crypto_key[32]`, `fake_ethertype_ipv4` (0x104A), `crypto_mode`/`aes_bits` global (load gán PQC/256, dataplane encrypt **không** đọc). `policies[]`.

#### Reasm UDP — `opt_entry` / `opt_table` (`pqc_l2_option.c`)

`g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS]`. 4096 entry, probe 8, timeout 200ms. Chi tiết §16. TLS: `crypto_l2_pqc_reasm_*` cho `wan_ingress` đổi frame sau join.

#### Runtime policy ctx (`crypto_runtime.c`) — biến static

| Biến | Việc |
|------|------|
| `policy_crypto_ctx[MAX_CRYPTO_POLICIES]` | master copy, lock khi HS/reload |
| `worker_policy_crypto_ctx[6][128]` | copy immutable per crypto worker |
| `policy_crypto_ready[]` | 1 = encrypt policy có ctx |
| `worker_prev_*` + `prev_policy_*` | grace 3s reload, decrypt gói wire_id cũ |
| `policy_crypto_generation` + TLS generation | worker memcpy khi gen đổi — tránh `g_key_mutex` trên packet path |
| `policy_index_by_wire_id[256]` | byte 14 → index ctx |
| `policy_profile_id_by_wire_id[256]` | wire → profile (reasm slot) |
| `active_policies[]` | snapshot policy |
| `profile_flow_tables[MAX_PROFILES]` | **chỉ slot 0 dùng.** Live WAN pick **không** đọc table này. GC vẫn chạy `flow_table_gc_slice` trên worker 0 |

`fwd_crypto_rebuild`: encrypt → ctx PQC + `pqc_from_handshake=1` + refresh key. Không `packet_crypto_init` cho policy.

`crypto_policy_is_encrypt` = `action != BYPASS` (L3/L4 lọt qua vẫn coi encrypt).

---

### 19.2 Call chain encrypt/decrypt

**LAN encrypt** `dataplane_process_local` → `encrypt_to_wan`:

```
opt_id = CRYPTO_OPT_L2_PQC                    // hardcode, không đọc cp->action L3/L4
pclass = crypto_proto_classify(proto)
need_split? split_tail_take + crypto_option_split + push_split_to_wan → return 1
else crypto_option_encrypt → return 0 → push_to_wan
```

Router `CALL_OPS` → `pqc_l2_option.c`:

- TCP/ICMP/OSPF: `l2_*_encrypt` → `l2_do_encrypt` (layout A 0x104A, GCM IPv4 từ offset 14).
- UDP: `l2_udp_need_split` / `l2_split` / `l2_udp_encrypt`.
- ARP: `arp_bridge` gọi `crypto_option_encrypt(L2_PQC, ARP)` → `l2_do_encrypt_arp` ethertype **0x1048**, payload ARP 28B.

**WAN decrypt** `decrypt_wan` → `wan_try_l2_pqc_frag` (UDP 0x5B) hoặc `decrypt_l2` → `crypto_option_decrypt(L2_PQC, TCP)` (gói nguyên dùng ops TCP; UDP nguyên `l2_udp_decrypt` = `l2_do_decrypt`).

**Bypass live:** `dataplane_local_needs_mid` false → RX CPU 0 `dataplane_process_local` → `push_to_wan`. **Không** `crypto_opt_bypass_encrypt`. File `bypass.c` chỉ no-op ops cho registry.

TLS option: `crypto_option_bind_worker_idx` / `g_worker_idx` — ghi byte 15. `g_opt_pkt_id` atomic — `pkt_id` fragment. `g_opt_frag_mtu` — `need_split`.

`crypto_option_wire_overhead(L2_PQC)=30` (1+1+12+16). MSS clamp TCP dùng số này.

---

### 19.3 Handshake — key cho L2 PQC (khác encrypt L3)

Key dataplane **không** nằm `cp->key`. Nằm `policy_key_binding_t` (`pqc_handshake.h`).

| Field chính | Việc |
|-------------|------|
| `encrypt_key` / `decrypt_key` / `keys[3]` | master sau ML-KEM; diversify per policy |
| `key_ready` | 0 → ctx all-zero → L2 encrypt **fail** (đúng) |
| `is_tunnel` | 1 → nhánh UDP 7090 `[PQC-HS-L3]` |
| `wan_ifname`, `peer_ip` | L2 bridge: ifname set, peer 0.0.0.0 → `is_bridge_mode` |
| `role_mode` | DYNAMIC so MAC (L2) hoặc IP (L3 tunnel) |
| `hs_cache[]` | **chỉ L3 tunnel** idempotent HELLO |

`struct pqc_hs_msg`: magic `PQCH`, HELLO/RESP/KEEPALIVE/POKE. Payload KEM + ML-DSA. **Cùng format** trên L2 frame (sau `pqc_l2_hdr`+frag) và trên UDP 7090.

`struct pqc_l2_hdr` / `pqc_frag_hdr` / `pqc_l2_peer` / `pqc_l2_reassemble` — **transport** handshake, ethertype **0x88B5/0x88B6**, không phải 0x104A traffic.

Hàm bind: `sig_pqc_bind_policy`, `sig_pqc_diversify_key`, `sig_pqc_load_and_bind_policy` (DB). Worker: `is_bridge_mode` → `pqc_l2_*`; else `pqc_hs_send_l3_*`, `L3_KEY_ROTATION_INTERVAL_MS` (~50 phút). L2 rotate: `KEY_ROTATION_INTERVAL_MS` = 30 ngày.

`trf_kem_*`, `trf_dsa_*`, `trf_derive_session_keys`, `trf_calculate_hmac` — KEM/DSA/HMAC của handshake, không phải AES-CTR dataplane.

`is_tunnel` bật nhánh UDP 7090, cache HELLO, `L3_KEY_ROTATION_INTERVAL_MS` ~50 phút. Bridge (`is_bridge_mode`) dùng raw Ethernet 0x88B5/0x88B6 và `KEY_ROTATION_INTERVAL_MS` = 30 ngày.

---

### 19.4 Symbol không có caller dataplane

Dataplane encrypt không có nhánh CTR/GCM/L3/L4. Enum dưới vẫn nằm `config.h` vì load DB ghi vào struct:

```
CRYPTO_MODE_CTR / GCM / PQC     // sau coerce: core encrypt luôn PQC
POLICY_ACTION_ENCRYPT_L3 / L4   // sau coerce: action!=BYPASS → L2 PQC
```

`src/db/*` và `schema.sql` là lớp load config (parse L3/L4/CTR/GCM rồi coerce). Không thuộc luồng gói.

`traffic_crypto.c`:

| Symbol | Caller dataplane |
|--------|------------------|
| `trf_encrypt_payload_gcm` / decrypt | Có — `crypto_pqc_layer.h` |
| `trf_encrypt_payload_cbc` / decrypt | Không |
| `trf_encrypt_cbc_hmac` / decrypt | Khai báo header, không body, không caller |
| `TrfPqcContext` `{l2_ctx,l3_ctx,l4_ctx}` | Không có instance |
| `trf_pqc_setup_session` | Có body, không caller ngoài file |
| `trf_pqc_init_global`, nonce, random, base64, kem, dsa, hmac, digest, HKDF | Handshake hoặc GCM |

`CIPHER_TYPE_AES_256_GCM` dùng. CBC/XTS trong `types.h` không đi dataplane. OpenSSL HMAC trong `packet_crypto.c` `fill_static_slots` là derive key ARP.

WAN pick live: `flow_table_pick_wan_per_packet` + `g_pkt_wrr_seq`. `flow_table_get_wan` / `get_wan_profile` / window/drain không có caller dataplane; `fwd_crypto_flow_table*` vẫn alloc table và GC.

File `*.orig` (`forwarder.c`, `crypto_route`, `flow_table`) không compile. `inc/crypto/pqc_*.h` phần lớn là stub `#include` bản `src/crypto/pqc/include/`. Comment `eth_parse.h` ghi 0x88B5 là marker IP — thực tế 0x88B5 là HS discovery; traffic là 0x104A.

`bypass.c`: năm export (`tcp/udp/icmp/ospf/other`) trỏ cùng `bypass_ops`. Dataplane bypass không gọi các hàm này — policy BYPASS đi RX thread.

`OPT_AES_BITS` trong `pqc_l2_option.c`: GCM dùng key 32B.

---

### 19.5 File crypto dataplane

Mã hóa traffic: `pqc_l2_option.c`. Dispatch: `crypto_option_router.c`, `crypto_option_registry.c`. Wire: `eth_parse.c`. Key slot: `packet_crypto.c`. AEAD: `crypto_pqc_layer.h` → `trf_*_gcm`. Handshake: `pqc_handshake.c`, `pqc_l2_handshake.c`. Dataplane: `local_egress.c`, `wan_ingress.c`, `arp_bridge.c`, `crypto_runtime.c`. Bypass registry: `bypass.c` + `opt_no_frag_ops.c`.

Không có `src/crypto/options/l3*.c`, `l4*.c`, `ctr*.c`.

---

## 20. AF_XDP / UMEM — `xdp_interface.c` (1500 + 9000 song song, drv + `XDP_COPY`)

File này là I/O NIC: một UMEM dùng chung mọi LAN/WAN, socket AF_XDP per queue, pool địa chỉ frame, RX peek / TX submit / FQ refill / CQ reclaim. Dataplane phía trên chỉ thấy `struct ne_packet { addr, len }` — **một địa chỉ, một độ dài, buffer tuyến tính**.

**Mục tiêu I/O:** cùng một source, cùng **`XDP_FLAGS_DRV_MODE` + `XDP_COPY`** (không SKB, không đổi sang ZC), nhận/gửi **cả** frame ~1514 (MTU 1500) **và** frame ~9014 (MTU 9000). Không phải build “chỉ 1500” hoặc “chỉ 9000”. `xdp.frags` / `XDP_USE_SG` là **mở thêm** đường jumbo trên cùng socket/prog; gói nhỏ vẫn một desc, `options=0`, như hiện tại.

Gắn BPF / `xsks_map` không nằm đây: `profile_xdp.c`. Hằng số: `inc/core/iface/interface.h`. Chi tiết song song 1500/9000: **§20.0a**.

### 20.0 Phần cứng i40e + kernel 5.15.0 → 6.8 (vì sao `xdp.frags` chưa chạy)

NIC trên server: driver **i40e** (Intel Ethernet 700 Series — X710 / XXV710 / XL710). Đó là driver dataplane này viết theo. Bind AF_XDP: **`XDP_COPY` + `XDP_USE_NEED_WAKEUP`**, attach **drv**. i40e có zero-copy; code **không** bật. COPY: kernel memcpy vào UMEM — đủ 1500 hiện tại và jumbo sau 6.8 (`XDP_USE_SG` thêm, vẫn COPY).

Kernel đang chạy: **5.15.0**. Kế hoạch: **6.8** (Ubuntu 24.04 GA cùng dòng). 5.15 thiếu cả tầng BPF `xdp.frags` lẫn driver i40e ráp nhiều RX buffer cho XDP — nâng kernel là điều kiện, không phải tùy chọn.

#### Card i40e cấp buffer thế nào

HW RX: mỗi descriptor trỏ **một** buffer trong host. Gói lớn hơn một buffer = nhiều descriptor, bit EOP trên desc cuối.

Kích thước buffer i40e (x86_64, `PAGE_SIZE=4096`, **không** `legacy-rx`):

```
i40e_calculate_vsi_rx_buf_len():
  PAGE_SIZE < 8192  →  I40E_RXBUFFER_3072   // 3072 B / desc
  else              →  I40E_RXBUFFER_2048
```

Trần một desc (không XDP): `I40E_MAX_RXBUFFER = 9728`. Jumbo 9000 **không XDP** driver xâu chuỗi desc bình thường.

**Có XDP native trên 5.15:** driver **không** ráp multi-buffer vào `xdp_buff`. `i40e_xdp_setup()`:

```
/* Don't allow frames that span over multiple buffers */
nếu netdev->mtu > frame_size - I40E_PACKET_HDR_PAD
    → -EINVAL  "MTU too large to enable XDP"
```

`I40E_PACKET_HDR_PAD` ≈ Ethernet + FCS + 2 VLAN (~26B). Với RX 3072: MTU tối đa quanh **~3000**. MTU 1500 attach XDP được. **MTU 9000 + XDP trên 5.15: kernel từ chối attach** — gói chưa tới `bpf/lan.c`, chưa tới AF_XDP.

`legacy-rx` (priv-flag i40e): buffer 2K, sau 6.4 còn hạ 1664 để chừa `skb_shared_info`; xâu tối đa 5 buffer → MTU ~8320, **thiếu 9000**. Jumbo 9K + XDP cần path mặc định 3072 + frags, không bật legacy-rx.

#### Tầng Linux — cái gì có ở kernel nào

| Tầng | Việc | Có từ | 5.15.0 | 6.8 |
|------|------|--------|--------|-----|
| BPF `BPF_F_XDP_HAS_FRAGS` / `SEC("xdp.frags")` | Prog khai báo hiểu multi-buffer | **5.18** | Không (UAPI/kernel không có cờ) | Có |
| Core XDP frags (`xdp_buff` + `skb_shared_info`) | Driver nhét thêm frag | 5.18 (mvneta trước) | Không dùng được với i40e | Có |
| **i40e** XDP multi-buffer Rx | Gom mọi HW desc tới EOP rồi gọi XDP | **6.4** | Không — MTU lớn → `-EINVAL` | Có; `NETDEV_XDP_ACT_RX_SG` |
| AF_XDP `XDP_USE_SG` / `XDP_PKT_CONTD` | Nhiều UMEM desc / gói | **6.6** | Bind SG → `-EINVAL`; không split | Có |
| i40e AF_XDP ZC multi-buffer Tx/Rx | ZC + SG | 6.6 (cùng series xsk SG) | ZC chỉ gói vừa 1 buffer | Có; COPY+SG **không** cần ZC |

5.15 đủ cho dataplane hiện tại: native **drv**, MTU 1500, UMEM 2048, `XDP_COPY`, một desc một gói. Thiếu **ba** mốc 5.18 + 6.4 + 6.6 thì không có `xdp.frags` trên i40e. 6.8 (sau 6.6) đủ cả ba.

Ubuntu 22.04 GA = 5.15; 24.04 GA = 6.8. HWE 5.19/6.2 trên 22.04 vẫn có thể thiếu i40e Rx SG (6.4) và/hoặc AF_XDP SG (6.6) — **6.8 là mốc chắc**.

#### 5.15 đang chạy (đúng với code)

```
i40e  RX 3072B/desc
  gói ≤ ~3KB  → 1 desc  → XDP native  → redirect XSK
  kernel XDP_COPY  → 1 UMEM 2048B   (1514+PQC vừa)
  recv_queue 1 desc, options=0
```

Gói > 1 RX buffer: driver 5.15 không đưa vào XDP. Attach XDP khi MTU 9000 fail. `lan.c` DROP >1514 là trần userspace; trần **driver** còn chặt hơn (~3KB) khi XDP bật.

i40e **có** AF_XDP zero-copy trên 5.15 (single-buffer). Code **không** dùng: `bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP`. COPY: thêm 1 memcpy NIC-page → UMEM; jumbo trên 6.8 vẫn đi COPY+SG được (xsk core cắt `xdp_buff` thành nhiều frame UMEM).

#### 6.8 sau khi nâng — i40e cấp jumbo thế nào

Prog `xdp.frags` + MTU 9000: `i40e_xdp_setup` **không** còn `-EINVAL` vì `prog->aux->xdp_has_frags`.

NAPI:

1. Desc 0: `xdp_buff` linear ~3072B (trừ pad).
2. Desc 1..n-1: thêm frag vào `skb_shared_info` của `xdp_buff`; `next_to_process` tăng; XDP **chưa** chạy.
3. Desc EOP: gọi BPF một lần trên cả gói.
4. `XDP_REDIRECT` → XSK.

COPY + `XDP_USE_SG`: xsk core copy từng mảnh vào FQ UMEM 2048; RX ring chuỗi `XDP_PKT_CONTD`. 9000/2048 ≈ 5 desc. COPY: trần số mảnh ≈ `CONFIG_MAX_SKB_FRAGS+1` (an toàn ≤18).

ZC + SG trên i40e 6.8: DMA thẳng UMEM, `NETDEV_A_DEV_XDP_ZC_MAX_SEGS`. Dataplane chưa bind ZC — không đụng path này cho đến khi đổi `bind_flags`.

#### Đối chiếu 5.15 vs 6.8 (i40e + app hiện tại)

| | 5.15.0 i40e | 6.8 i40e |
|--|-------------|----------|
| XDP drv MTU 1500 | Có | Có |
| XDP drv MTU 9000 | **Không** (`-EINVAL`) | Có nếu BPF frags |
| `SEC("xdp.frags")` load | Kernel không hiểu cờ | Có |
| `XDP_USE_SG` bind | `-EINVAL` | Có |
| Jumbo tới AF_XDP | Không | COPY+SG hoặc ZC+SG |
| App `recv_queue` 1:1 desc | Đủ cho 1500 | **Thiếu** coalesce CONTD |

Nâng 6.8 **không** tự MTU 9000: vẫn phải `ip link set mtu 9000`, BPF frags, `XDP_USE_SG`, bỏ DROP 1514, coalesce RX (§20.10–20.12). 6.8 chỉ **mở cửa driver/kernel**.

Sau 6.8, kiểm tra:

```
ethtool -i <iface>          # driver: i40e
uname -r                    # 6.8.x
ip -d link show <iface>     # xdp / mtu
```

Netlink `xdp_features`: `NETDEV_XDP_ACT_RX_SG` (jumbo XDP drv) và `NETDEV_XDP_ACT_XSK_ZEROCOPY` (ZC; COPY+SG chỉ cần RX_SG).

### 20.0a Cùng source: 1500 và 9000 song song, mode vẫn drv + `XDP_COPY`

Không tách hai binary, không hai mode XDP. Một process, một UMEM, bind **giữ**:

```
attach:  XDP_FLAGS_DRV_MODE
socket:  XDP_COPY | XDP_USE_NEED_WAKEUP   (+ XDP_USE_SG trên 6.8 để *thêm* jumbo)
BPF:     một prog — trên 6.8 là xdp.frags (vẫn nhận gói linear 1500)
```

`XDP_USE_SG` **không** tắt đường 1-desc. Kernel: gói vừa một UMEM frame → một `xdp_desc`, `options=0` (y như 5.15). Gói lớn hơn `frame_size` (2048) hoặc multi-buffer từ i40e → chuỗi CONTD. Cùng RX ring, cùng `recv_queue` phải xử lý **cả hai** hình.

MTU NIC là **trần**, không phải kích thước mọi frame. Iface `mtu 9000` vẫn nhận 64B…1514B…9014B. Iface `mtu 1500` chỉ nhận tới ~1514 — jumbo vào NIC đó bị drop ở driver, không phải do COPY/drv.

#### i40e: gói nhỏ và jumbo khác nhau ở số desc HW, cùng NAPI/XDP

RX buffer 3072B. Frame Ethernet 1514 **luôn vừa 1 desc** (kể cả khi iface MTU 9000). Frame ~9014 **nhiều desc**, EOP ở desc cuối.

| Frame trên dây | HW i40e (6.8 + frags) | XDP buff | AF_XDP COPY + SG, UMEM 2048 |
|----------------|------------------------|----------|------------------------------|
| ~1514 (MTU 1500) | 1 desc | linear, không frags | **1** UMEM desc, `options=0` |
| ~9014 (MTU 9000) | ~3 desc 3072 | linear + frags | **~5** UMEM desc, CONTD rồi 0 |

Prog `xdp.frags` chạy cho **cả hai**. Cờ frags = “chấp nhận multi-buffer”, không = “chỉ jumbo”. Gói 1500: `data`/`data_end` đủ header; `bpf_xdp_get_buff_len` = ~1514. Không cần prog thứ hai `SEC("xdp")`.

Hai NIC khác MTU (LAN 1500, WAN 9000, hoặc ngược): **cùng** drv+COPY, **cùng** prog frags (frags trên NIC 1500 vẫn hợp lệ — mọi gói linear). NIC 1500 không bao giờ sinh CONTD từ HW nếu MTU không cho jumbo. NIC 9000: mix 1514 và 9014 trên cùng queue.

#### Mode không đổi

| Giữ | Không làm (cho mục tiêu này) |
|-----|------------------------------|
| `XDP_FLAGS_DRV_MODE` | Không fallback SKB để “được jumbo” |
| `XDP_COPY` | Không bắt buộc ZC; ZC là path khác |
| UMEM 2048 + pool hiện tại | Không bắt buộc `NE_FRAME=16384` (cách A) — 1500 vẫn 1 chunk 2048 |
| Một `ne_pair`, một set thread | Không process riêng 1500 / 9000 |

`XDP_USE_SG` trên 6.8 là **cờ thêm** trên cùng COPY+wakeup. 5.15 không có SG → chỉ 1500 (đúng hiện trạng). 6.8: 1500 như cũ + jumbo qua SG.

#### Dataplane: hai kích thước, không hai crypto mode

Encrypt vẫn L2 PQC + COPY không liên quan. Khác nhau ở **độ dài frame** và **có cắt UDP không**:

- Ra WAN MTU 1500: `need_split` như hiện tại (`pkt_len+35 > 1500`).
- Ra WAN MTU 9000: datagram UDP lớn có thể **một** GCM, không vào bảng reasm.
- Bonding per-packet: datagram N → WAN0 (1500) vẫn cắt; N+1 → WAN1 (9000) không cắt — cùng flow, cùng worker. `resolve_runtime_frag_mtu` **min toàn cục 1500** hiện tại ép mọi WAN như 1500; song song 1500/9000 cần MTU **theo WAN đích** (hoặc min các WAN đang mang gói đó), không chọn một số 1500 *hoặc* 9000 cho cả process.

`lan.c` DROP >1514: giết jumbo, **1500 vẫn qua**. Để song song: trần DROP ≥ jumbo (hoặc bỏ check length), **giữ** redirect ARP/IPv4 cho frame nhỏ. Không xóa nhánh 1500.

`recv_queue`: `options==0` → một `ne_packet` (1500 và mọi gói <2048). CONTD → coalesce thành một buffer tuyến tính rồi một `ne_packet` (jumbo). Thiếu nhánh CONTD = mất jumbo; nhánh `options==0` vẫn là hot path 1500.

TX: frame ≤2048 một desc (1500+PQC ~1544). Frame jumbo: nhiều desc CONTD hoặc gather. Cùng `tx_drain_queue`, cùng COPY+drv.

Scratch/`NE_FRAME`/reasm 1600: path 1500 giữ. Path 9000 không qua split thì không vào `opt_entry`; nếu vẫn cắt nửa jumbo thì 1600/2048 **vỡ** — đó là trần path cắt, không phải lý do bỏ 1500.

---

### 20.1 Mô hình gói hiện tại (một desc = một gói)

```
NIC DMA / driver
  → XDP native (drv)  bpf/lan.c | bpf/wan.c
  → bpf_redirect_map(xsks_map, queue_id)
  → kernel COPY vào 1 UMEM frame (XDP_COPY)
  → RX ring: 1 xdp_desc { addr, len, options=0 }
  → recv_queue: ne_packet.addr = d->addr; ne_packet.len = d->len
  → ne_packet_data(p, addr) = bufs + addr     // tuyến tính, không offset unpack
```

`recv_queue` **không** đọc `d->options`. `tx_drain_queue` **không** ghi `d->options`. Kernel header:

```
XDP_PKT_CONTD (1<<0)  // desc này chưa hết gói; desc kế tiếp trên cùng RX/TX ring là mảnh tiếp
```

Gói một buffer: mọi desc `options=0`. Đó là toàn bộ traffic hiện tại (MTU 1500, frame 2048 đủ 1514+overhead L2 PQC).

`dp_ring_push`: `pkt->len > fwd->pair.frame_size` → free frame, drop. TX: `d->len = min(job.len, frame_size)` — cắt im lặng nếu len lớn hơn chunk.

### 20.2 Mode đang bind / attach

`xsk_create_queue`:

```
xdp_flags   = XDP_FLAGS_DRV_MODE          // native, không SKB
libbpf_flags= XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD  // không load prog mặc định libxdp
bind_flags  = XDP_COPY | XDP_USE_NEED_WAKEUP
              // i40e, copy mode — không zero-copy
```

`xsk_socket__create_shared(..., p->umem, rx, tx, fq, cq)` — mọi queue **share một umem**. Queue đầu tiên tạo umem “sở hữu” fd; các queue sau `XDP_SHARED_UMEM` bên trong libxdp.

**`XDP_COPY`:** kernel memcpy gói vào địa chỉ FQ. Userspace không map DMA NIC. i40e 5.15/6.8 đều làm được path này; jumbo trên 6.8 dùng COPY + SG, không cần ZC.

**`XDP_USE_NEED_WAKEUP`:** FQ/TX có thể set `XDP_RING_NEED_WAKEUP`. Code kick:

- FQ: `recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT)` trong `refill_fq_queue` / `kick_fq_queue`
- TX: `sendto(xsk_fd, NULL, 0, MSG_DONTWAIT)` trong `tx_drain_queue` khi full hoặc sau submit

**Không có `XDP_USE_SG` (bit 4).** Kernel: nếu gói XDP multi-buffer mà socket không SG thì **drop**. Native jumbo + `xdp.frags` tạo multi-buffer; COPY không SG = mất gói lớn dù NIC MTU 9000.

Attach BPF (`profile_xdp.c`): `bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL)`. Trùng drv với socket. Load `bpf_object__open_file` + `bpf_object__load` — **không** `bpf_program__set_flags(..., BPF_F_XDP_HAS_FRAGS)`, clang `SEC("xdp")` không phải `xdp.frags`.

Ba lớp độc lập — **cùng lúc** cho 1500 và 9000; không chọn một mode:

| Lớp | Cờ hiện tại (5.15, chỉ 1500) | 6.8 song song 1500+9000 |
|-----|------------------------------|-------------------------|
| Attach NIC | `XDP_FLAGS_DRV_MODE` | **Giữ drv** (không SKB) |
| BPF program | `SEC("xdp")` | `xdp.frags` — vẫn nhận gói 1514 linear |
| AF_XDP socket | `XDP_COPY` \| wakeup | **Giữ COPY + wakeup**, thêm `XDP_USE_SG` (jumbo); gói 1500 vẫn 1 desc |

Không SG: jumbo drop, **1500 vẫn chạy**. Có SG: 1500 không đổi hình; jumbo thêm chuỗi CONTD. COPY không thay bằng ZC.

### 20.3 UMEM một khối, pool địa chỉ

`ne_pair_open`:

1. `setrlimit(RLIMIT_MEMLOCK, INF)` — mmap pin.
2. `frame_size = NE_FRAME` (2048). `n_frames = NE_N_FRAMES` (2²⁰). `bufsize = 2 GiB`.
3. `mmap` anonymous RW. `pool_init` cap = n_frames (power of 2).
4. Push mọi `addr = i * frame_size` vào pool (địa chỉ **aligned**, không packed offset).
5. Promisc on mọi LAN/WAN. `ip link xdp off` (tránh EINVAL recreate).
6. `xsk_umem__create` trên `locals[0].queues[0].fq/cq`:

```
fill_size = comp_size = NE_RING (16384)
frame_size = 2048
frame_headroom = 0
flags = 0     // không XDP_UMEM_UNALIGNED_CHUNK_FLAG
```

7. `umem_fq_li = 0`, `umem_fq_q = 0` — queue này **owner** FQ/CQ umem. `zero_queue_rings(..., preserve=1)` không xóa fq/cq owner khi recreate socket.
8. `open_iface_queues` từng LAN rồi WAN. Fail → detach XDP, sleep 150ms, retry một lần.
9. `prefill_iface` mỗi queue `NE_FQ_PREFILL` (16384) địa chỉ từ pool → FQ. Nhiều queue × 16384 có thể cạn pool (1M frame; 64 queue lý thuyết đầy).

`ne_packet_data`: `xsk_umem__get_data(bufs, addr)` = `bufs[addr]`. **Không** `xsk_umem__add_offset_to_addr`. Đúng vì aligned + headroom 0 + COPY ghi từ đầu chunk. Bật unaligned hoặc metadata TX thì addr pack offset — phải unpack trước khi deref.

RAM: 1M × 2048 = 2 GiB. Tăng `NE_FRAME` lên 16384 giữ 1M frame = 16 GiB. Giảm `NE_N_FRAMES` nếu jumbo một buffer lớn.

Kernel thường yêu cầu `frame_size` power-of-two. 9000 không phải 2ⁿ → chunk **16384** (hoặc 4096 nếu chỉ SG, không nhét cả jumbo một frame).

### 20.4 Queue NIC ↔ RX/TX slot CPU

`NE_QUEUE_OVERRIDE=0`: số queue = số `rx-*` trong sysfs, trần `MAX_QUEUES=64`. Override >0 thì `ethtool -L combined` (fail thì rx/tx riêng).

RX LAN 1 thread (`NE_RX_LAN_SLOTS=1`): `xsk_queue_for_rx_slot` — mọi HW queue `q % 1 == 0` → **mọi queue LAN** do CPU 0 đọc. WAN tương tự CPU 11.

TX 4 slot: `xsk_queue_for_tx_slot` — `q % min(nq, 4) == tx_slot`. `tx_drain_iface_ring` chỉ drain **queue primary đầu tiên** khớp slot, không round-robin mọi queue của slot. Một TX thread ↔ một (vài) HW TX queue.

`ne_rx_slots_for_queues`: nếu NIC ít queue hơn slot CPU, chỉ dùng `nq` slot.

### 20.5 Vòng đời RX (LAN và WAN cùng pattern)

`local_rx_thread` / `wan_rx_thread`:

```
loop:
  ne_refill_fq_*_slot     // pool → FQ, kick wakeup
  n = ne_recv_*_slot(batch, 64)
  nếu n==0: kick FQ, poll fd, continue
  xử lý từng ne_packet (crypto ring hoặc process ngay)
  ne_recv_release_*_slot  // xsk_ring_cons__release(rx, rx_pending)
```

`recv_queue`: `peek` tối đa `max`, copy `addr/len/dir/wan_idx/local_idx`, `rx_pending = n`. **Chưa** release RX ring cho đến `ne_recv_release_*`. Trong lúc đó địa chỉ thuộc userspace; FQ chưa nhận lại. Gói đẩy `local_to_mid` **giữ** addr (không free). Gói drop: `ne_frame_free` ngay. Sau release, kernel có thể tái sử dụng desc slot; frame UMEM vẫn của userspace cho đến CQ (TX) hoặc `ne_frame_free` (drop/xong LAN).

`reclaim_rx_queue` (unplumb): trả addr pending + peek còn lại về pool, rồi release.

### 20.6 FQ / CQ / TX

**FQ (fill):** kernel lấy addr trống để COPY RX vào. `refill_fq_queue`: `xsk_prod_nb_free` → `pool_pop` → `reserve` FQ → ghi addr → submit. Hết pool → RX starve (loss NIC).

**CQ (completion):** sau NIC TX xong, addr về CQ. `drain_cq_queue` (TX thread, theo `tx_slot`): peek CQ → `pool_push`. Pool đầy giữa chừng: release số đã push, dừng — addr kẹt CQ đến lần drain sau.

**TX:** `ne_tx_drain_*` ← `mid_to_local|wan[iface][tx_slot]`. Batch 32. `xsk_prod_nb_free` TX = 0 → wakeup sendto, return 0 (gói còn userspace ring). Pop job, ghi `d->addr`, `d->len = min(len, frame_size)`, submit, wakeup. **Không** free addr ở TX — chờ CQ. `XDP_COPY`: kernel copy UMEM → skb/driver, rồi complete.

Tên `NE_XSK_COPY_TX_BATCH`: batch userspace, không phải cờ socket.

### 20.7 Shared umem: tạo / xóa / plumb nóng

Xóa socket: 2 pass — socket **không** trùng `xsk_umem__fd` trước, owner fd sau (libxdp share umem fd).

`ne_pair_plumb_local`: nếu `!p->umem` → `ne_pair_create_umem_on_local` trên queue 0 LAN đó. WAN plumb **đòi hỏi umem đã có** (LAN trước).

`ne_pair_unplumb_local`: reclaim FQ/RX/CQ → delete xsk. Nếu iface cầm umem fd và không còn iface live → `ne_pair_destroy_umem` (delete umem object, `pool_reset_full` đẩy lại mọi `i*frame_size`; **không** munmap). LAN plumb sau tạo umem mới trên cùng `bufs`.

`ne_pair_close`: delete mọi xsk → close bpf object → `ip link xdp off` → `xsk_umem__delete` → munmap.

### 20.8 BPF đang chặn jumbo (ngoài `xdp_interface.c`)

`bpf/lan.c`:

```
PATH_MTU = 1500
ETH_FRAME_MAX = 1514
VLAN = 1518
pkt_len = data_end - data     // với xdp.frags: chỉ linear đầu, không phải cả jumbo
nếu pkt_len > MAX → XDP_DROP
```

MTU NIC 9000 mà prog này còn load: jumbo LAN **DROP**, frame 1514 **vẫn redirect** — đang là “chỉ 1500 sống”. Song song: nới/bỏ trần length, **giữ** ARP/IPv4 redirect cho gói nhỏ.

`bpf/wan.c` không trần độ dài. Vẫn vỡ ở UMEM 2048 / không SG.

`pkt_len` khi `xdp.frags`: `ctx->data_end - ctx->data` = mảnh tuyến tính đầu (thường ≤ page/2k). Check 1514 có thể DROP nhầm hoặc không thấy đủ header L3 nếu header cắt sang frag sau — cần `bpf_xdp_get_buff_len` + load byte, không so sánh `data_end-data` với 9014.

### 20.9 Crypto MTU vs NIC MTU

`resolve_runtime_frag_mtu` (`forwarder.c`): khởi điểm **1500**, chỉ **hạ** nếu WAN `SIOCGIFMTU` nhỏ hơn. Mọi WAN 9000 → crypto MTU **vẫn 1500** → UDP lớn **vẫn cắt** dù dây jumbo. Mix WAN 1500 + WAN 9000: min=1500 → WAN 9000 cũng bị cắt. Song song 1500/9000: ngưỡng split theo **MTU WAN đích của datagram đó** (WRR), không một hằng 1500 *hoặc* 9000 cho cả process. `crypto_option_set_mtu` clamp `mtu > NE_FRAME` — UMEM 2048 thì hằng số global không mô tả jumbo; jumbo không đi `need_split` nếu so với MTU 9000.

### 20.10 Chứa 9000 **cùng** path 1500 (không thay mode COPY+drv)

Dataplane giả định buffer tuyến tính. Mục tiêu: 1514 và 9014 **cùng** `recv`/`tx`/`encrypt`, drv + `XDP_COPY`.

**A — `NE_FRAME=16384`, không SG**

Mỗi gói một desc kể cả jumbo. Frame 1500 cũng chiếm chunk 16k (lãng phí). Bind COPY+drv như cũ. i40e native jumbo vẫn có thể multi-buffer → không SG vẫn drop jumbo; 1500 sống. A không phải hướng chính nếu muốn giữ UMEM 2048 và mix hai cỡ.

**B — `xdp.frags` + drv + `XDP_COPY` + `XDP_USE_SG` (1500 và 9000 chung socket)**

Cùng bind COPY+wakeup+drv. SG **cộng** vào. UMEM **giữ 2048**:

1. NIC có thể MTU 9000 (trần); NIC khác giữ 1500 — cùng process.
2. Một BPF `xdp.frags`, attach drv.
3. Redirect cả gói nhỏ lẫn jumbo (không DROP 1514).
4. RX: 1500 → 1 desc `options=0` (code hiện tại đủ). 9000 → CONTD…0; `recv_queue` coalesce **chỉ** chuỗi đó.
5. TX: ≤2048 một desc (1500+PQC). Jumbo: CONTD hoặc gather.

Gather jumbo về một buffer tuyến tính rồi `ne_packet` một `addr` — path 1500 không gather. Không đổi `ne_packet` cho gói nhỏ.

`NE_BATCH_SIZE=64` đếm desc: mix 60 gói 1500 + 1 jumbo 5 desc có thể vượt 64 giữa chuỗi jumbo — coalesce phải peek nốt CONTD, không biến gói 1500 cạnh đó thành jumbo.

### 20.11 Việc `xdp_interface.c` đang làm từng hàm (bản đồ)

| Hàm | Việc |
|-----|------|
| `ne_pair_open` | mmap UMEM, umem trên LAN0 q0, XSK mọi queue, prefill FQ |
| `ne_pair_close` | xsk → bpf close → xdp off → umem delete → munmap |
| `open_iface_queues` / `xsk_create_queue` | drv + COPY + wakeup, shared umem, ring 16384 |
| `ne_recv_*_slot` | peek RX queues thuộc slot → `ne_packet` 1-1 với desc |
| `ne_recv_release_*` | release RX cons |
| `ne_refill_fq_*` / `ne_kick_fq_*` | FQ từ pool + wakeup |
| `ne_drain_cq_*` | CQ → pool |
| `ne_tx_drain_*` | userspace ring → TX desc, clamp len ≤ frame_size |
| `ne_frame_alloc/free` | pool spinlock; split UDP lấy frame thứ hai |
| `ne_packet_data` | `bufs[addr]` |
| `ne_ring_*` | MPSC userspace (mid rings), không phải XSK |
| `ne_pair_plumb_*` / `unplumb_*` | hot add/remove NIC, umem sống nếu còn iface |
| `interface_get_mtu` | chỉ log lúc XSK fail; **không** set `p->frame_size` |

`p->xdp_flags` gán `DRV_MODE` lúc open; per-iface `iface->xdp_flags` sau bind thành công.

### 20.12 Chỗ logic chạm — 1500 vẫn chạy, 9000 thêm, COPY+drv giữ

| Khâu | Hiện tại (1500) | Song song 1500+9000 |
|------|-----------------|---------------------|
| Attach / bind | drv + COPY + wakeup | **Giữ**; 6.8 thêm `XDP_USE_SG` — không ZC, không SKB |
| BPF | `SEC("xdp")` | `xdp.frags` **một** prog; gói 1514 vẫn linear |
| `lan.c` DROP >1514 | 1500 OK, jumbo chết | Nới trần; **không** bỏ redirect ARP/IPv4 nhỏ |
| `recv_queue` | 1 desc = 1 gói | `options==0` giữ 1500; chỉ CONTD mới coalesce |
| `tx_drain_queue` | 1 job 1 desc, clamp 2048 | ≤2048 như cũ; jumbo CONTD/gather |
| UMEM 2048 | vừa 1500+PQC | Giữ 2048: 1500 = 1 frame; 9000 = N frame |
| Split UDP | so 1500 global | So **MTU WAN đích**; WAN 1500 vẫn cắt, WAN 9000 có thể không |
| `opt_entry` 1600 | path cắt 1500 | Giữ cho path cắt; jumbo không cắt thì không vào bảng |
| i40e 5.15 | chỉ 1500 + XDP | 6.8: cùng NAPI, 1514 = 1 HW desc, 9014 = nhiều desc |

`interface_get_mtu` lúc XSK fail in `mtu=` — không thay `NE_FRAME`. `ip link set mtu 9000` trên một NIC **không** tắt frame 1500 trên NIC đó; NIC kia có thể giữ mtu 1500. Cùng source, cùng COPY+drv.
