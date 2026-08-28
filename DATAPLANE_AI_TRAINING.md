# NE MAC Learn — Dataplane: luồng và logic

Mô tả **cách hệ thống đang chạy**: forward gói, gộp kênh WAN, mã hóa L2 PQC, chia đa core. Không gồm Postgres / schema / reload DB / vault (`src/db/*`).

UDP cắt/rã ráp: **§16**, join mảnh **§16.8**, buffer giảm OOO sau join **§16.9**. Gộp kênh per-packet: **§7**, **§18**. Chặn chiều OUT (LAN→WAN) và IN (WAN→LAN): **§8.1–8.2**. Vì sao 2 WAN OOO còn 1 WAN ổn: **§17**. Lớp mã hóa: **§19**. Handshake PQC + lifetime key 30 ngày + CLI `-tk`: **§19.3**, **§19.6**. AF_XDP / UMEM: **§20**. i40e + 5.15→6.8: **§20.0**. **1500 và 9000 cùng chạy**, mode **drv + `XDP_COPY`**: **§20.0a**.

**Bài đo 1 LAN + 1 WAN (2026-08-27):** UDP 10 stream ~100s → **8.38 Gbit/s**, loss **0.16%**, OOO **45 / 71.3M**. Cùng L2 PQC, cùng cắt UDP ×2; chỉ khác một path. Bài 2 WAN OOO lớn ở §7.7 đo **trước** buffer §16.9 (WRR không đổi).

---

## 0. Sản phẩm là gì

`network-encryptor` là **L2 encryptor + WAN bonder** chạy userspace trên AF_XDP.

Máy có N NIC LAN (phía client) và M NIC WAN (phía đường truyền). Gói vào LAN:

1. Parse 5-tuple, chọn crypto policy.
2. **Bypass** → không mã hóa, vẫn gộp kênh, RX/TX cores only.
3. **Encrypt** → mã hóa L2 PQC trên crypto core, ghi marker + worker_idx lên wire, gộp kênh per-packet ra WAN.
4. **ARP** → bridge LAN↔WAN, mã hóa key tĩnh, **không** đi bypass, **không** vào WRR data.

Chiều ngược: WAN RX đọc marker / worker_idx → đúng crypto core giải mã / ráp fragment → **UDP thì buffer seq** (§16.9) → MAC FDB → TX LAN. Bonding WAN vẫn per-packet; reorder không dính WAN.

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
| `src/core/forwarder/crypto_runtime.c` | Ctx mã hóa per policy, sync key PQC, frag GC, **đồng hồ lifetime 30 ngày** |
| `src/core/dataplane/local_egress.c` | LAN→WAN: **cổng OUT** policy, pick WAN, encrypt/bypass/ARP |
| `src/core/dataplane/wan_ingress.c` | WAN→LAN: decrypt, **cổng IN**, join UDP, reorder, FDB |
| `src/db/config.c` | `config_select_crypto_policy` (OUT) + bảng đảo `config_policy_in_ok` (IN) |
| `inc/core/dataplane/udp_reorder.h` | Key 4-tuple, ops emit/drop, stats |
| `src/core/dataplane/udp_reorder.c` | Buffer seq UDP sau join (giảm OOO 2 WAN) |
| `tests/test_udp_reorder.c` | In-order / hold / skip-gap / dup / wrap / epoch |
| `src/core/dataplane/crypto_route.c` | Sticky flow → crypto worker + TX slot; `dp_udp_next_tx_seq` |
| `src/core/dataplane/idle.c` | Adaptive idle + eventfd wake |
| `src/core/dataplane/arp_bridge.c` | ARP encrypt/bridge, không bị weight=0 chặn |
| `src/core/dataplane/packet_util.c` | `dp_parse_flow`, `dp_ring_push` |
| `src/core/flow/flow_table.c` | `flow_table_pick_wan_per_packet` (live) |
| `src/core/flow/mac_learn.c` | FDB MAC cho WAN→LAN unicast |
| `src/core/iface/xdp_interface.c` | UMEM, AF_XDP RX/TX, ring MPSC |
| `bpf/lan.c` | XDP LAN: ARP+IPv4 → AF_XDP |
| `bpf/wan.c` | XDP WAN: ARP / 0x1048 / **0x104B** / IPv4; map 0x104A+0x104B; CFM PASS |
| `src/crypto/common/packet_crypto.c` | 3 key slot, diversify PQC |
| `src/crypto/common/crypto_option_router.c` | Dispatch encrypt/decrypt/split; TLS UDP epoch/seq/datagram_id |
| `src/crypto/common/eth_parse.c` | Marker 0x104A/0x104B, policy_id, worker_idx, MSS clamp |
| `src/crypto/pqc/pqc_l2_option.c` | L2 PQC; UDP 0x104B + shim; join `opt_table` |
| `src/crypto/pqc/pqc_handshake.c` | Handshake UDP `:7090` trên tunnel; nạp key RAM; **không** tự đếm 30 ngày |
| `src/crypto/pqc/pqc_ipc.c` | Unix socket CLI: `-r` retry HS, `-tk <policy_id>` remaining lifetime |
| `src/crypto/options/bypass.c` | No-op crypto ops |
| `inc/crypto/eth_parse.h` | `NE_L2_FAKE_ETHERTYPE` 0x104A, `_UDP` 0x104B, ARP 0x1048 |
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

UDP split: 2 mảnh **cùng** WAN (đúng). Datagram kế WRR sang WAN kia. Join-pending rồi **reorder 2ms** (§16.9). WRR không đổi.

**Nhân ×2 (lý do per-packet 2 WAN nặng, 1 WAN vẫn ổn):** iperf UDP `-l 1470` luôn `need_split` → **mỗi datagram gốc = 2 frame wire + 2 AES-GCM encrypt + 2 AES-GCM decrypt + 1 lần join bảng**. WRR một lần / datagram gốc; trên dây ×2. 1 WAN: TX tuần tự → OOO ~0 (bài D). 2 WAN: N và N+1 khác NIC → join xong lệch seq; buffer giữ future seq. Chi tiết: **§16.9**, **§18**.

UDP 0x104B mang `epoch+seq+datagram_id` trong GCM. Phía nhận reorder per 5-tuple trên crypto worker. Iperf OOO đo payload sau LAN TX.

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

Loss **ổn** (sub-percent). OOO **không chấp nhận** trên bài đo **trước** §16.9 (stripe 2 path + join-pending + ×2 split). Sau reorder: cùng WRR, hold 2ms / skip-gap — số OOO 2 WAN cần đo lại; bài D (1 WAN) gần passthrough.

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

Không khớp policy / parse 5-tuple fail / LAN không thuộc profile → **drop** (`ne_dp_stats_local_drop`). Không “PASS kernel”, không forward ngầm. Chi tiết khớp và chiều ngược: **§8.1–8.2**.

---

### 8.1 Chặn chiều OUT — LAN → WAN

Policy viết theo **chiều máy khách trên LAN**: `src` = IP/port phía LAN, `dst` = IP/port phía đường/WAN. Không conntrack, không cột “IN/OUT” riêng trong DB — một `crypto_policy` dùng cho OUT đúng chiều; IN thì **đảo** (§8.2).

File: `local_egress.c` `pick_profile_policy` + `config_select_crypto_policy` (`src/db/config.c`). Live một profile (`profiles[0]`).

#### Ai bị xét, ai không

| Gói LAN RX | Việc |
|------------|------|
| ARP | Không match 5-tuple. `arp_bridge_from_local`. Policy bypass **không** áp cho ARP. |
| IPv4 parse được (`dp_parse_flow`) | Match policy. Fail → drop. |
| Không IPv4 / parse fail (`flow_ok=0`) | `c = NULL` → drop. Không encrypt, không bypass. |
| `local_idx` không nằm `profile.local_indices[]` | drop |
| Profile `enabled=0` | drop |

`dp_parse_flow`: chỉ IPv4. TCP/UDP lấy port; ICMP/OSPF port = 0.

XDP `lan.c` chỉ đưa ARP + IPv4 vào AF_XDP. Frame khác không vào userspace.

#### Thuật toán match OUT

`config_select_crypto_policy(cfg, 0, src_ip, dst_ip, src_port, dst_port, proto)`:

Duyệt `profile.policy_indices[]`. Rule khớp `crypto_policy_match_packet` thì giữ **một** winner:

- `priority` **nhỏ hơn** thắng (số thấp = ưu tiên cao).
- Cùng priority → `id` (wire policy_id) nhỏ hơn thắng.

Không first-match. Không action DENY — không khớp **bất kỳ** rule → `NULL` → drop.

`crypto_policy_match_packet` từng field (AND):

1. **Proto**
   - `POLICY_PROTO_ANY` (0) → mọi proto parse được.
   - `POLICY_PROTO_TCP_UDP` (254) → chỉ 6 hoặc 17.
   - Khác → `ip->protocol` phải đúng (1 ICMP, 89 OSPF, …).
2. **IP src / dst** — `cidr_match_with_negate`:
   - `src_any` / `dst_any` → field đó luôn đúng.
   - Không any: `(ip & mask) == (net & mask)`. `*_negate` → đảo kết quả (CIDR “trừ”).
3. **Port** (mặc định bật; `CRYPTO_POLICY_MATCH_IP_ONLY=0`)
   - `src_port_from/to < 0` hoặc `dst_* < 0` → field đó any.
   - Không thì port nằm `[from, to]`.
   - ICMP/OSPF: port 0. Rule port cụ thể (vd 53) **không** khớp ICMP.

`action` **không** tham gia match. Match xong mới rẽ:

```
cp == NULL                         → drop (chặn OUT)
cp->action == BYPASS               → push_to_wan, không AES
cp encrypt + crypto_enabled        → encrypt L2 PQC (live luôn L2)
cp encrypt + !crypto_enabled       → drop
!fwd_crypto_policy_ready(cp)       → drop (HS/key chưa sẵn)
```

#### `needs_mid` vs chỗ drop

`dataplane_local_needs_mid` (CPU 0, trước đẩy crypto):

- ARP → 1 (crypto worker).
- `!crypto_enabled` → 0 (ở lại CPU 0).
- `pick_profile_policy` fail → **0** — rồi `dataplane_process_local` trên CPU 0 **cũng** fail pick → drop. Gói không khớp **không** vào core 3–8.
- Bypass → 0 — xử lý CPU 0.
- Encrypt → 1 — `local_to_mid[W]`; crypto worker gọi `dataplane_process_local` **lần nữa** (pick lại cùng 5-tuple).

Drop OUT: `ne_dp_stats_local_drop`, `ne_frame_free`. Phía client = Lost (không ra WAN).

#### Ví dụ OUT

Rule: src `10.0.0.0/24`, dst `8.8.8.8/32`, UDP, dport 53, encrypt.

- `10.0.0.5:50000 → 8.8.8.8:53` UDP → encrypt, ra WAN.
- `10.0.0.5:50000 → 1.1.1.1:53` UDP → **drop** (dst không khớp).
- `10.0.0.5 → 8.8.8.8` ICMP → **drop** (proto).
- Hai rule, priority 10 bypass `10.0.0.0/8` any và priority 5 encrypt UDP/53: UDP/53 lấy encrypt (5 < 10).

---

### 8.2 Chặn chiều IN — WAN → LAN

Chiều này **không** chạy `config_select_crypto_policy` đúng chiều gói. Sau decrypt, 5-tuple vẫn như lúc LAN TX: return `8.8.8.8:53 → 10.0.0.5:50000` trong khi policy OUT viết `src=10/24 dst=8.8.8.8 dport=53`. Khớp IN = **đảo src↔dst, sport↔dport** lúc dựng bảng.

Hai nhánh: **đã mã hóa** vs **bypass plaintext**. ARP IN: `arp_bridge_from_wan`, không 5-tuple policy.

Stats: không khớp IN encrypted → `wan_policy_drop` + `wan_drop`. Nhánh khác (sai marker, bypass không khớp, FDB miss) → `wan_drop` thường.

#### A. Gói mã hóa (0x104A / 0x104B / marker)

Thứ tự trong `dataplane_process_wan`:

1. `decrypt_wan` — `policy_id` trên wire phải có ctx; `fwd_policy_by_wire_id` **bỏ** `action==BYPASS`. Decrypt fail → drop. UDP mảnh pending → free, chưa xét IN.
2. `wan_profile_pi` đọc `policy_id` (snapshot header trước decrypt) → profile 0 nếu wire_id thuộc profile. Không map → drop (**không** đếm `wan_policy_drop`).
3. **Cổng 5-tuple IN** — chỉ khi `profile.policy_in_any == 0`:
   - Parse 5-tuple **plaintext sau decrypt**.
   - `wan_policy_in_ok` → `config_policy_in_ok`.
   - Fail → `policy_drop`.
4. `policy_in_any == 1` → **bỏ qua** bước 3.
5. UDP tagged → reorder §16.9; khác → FDB `forward_wan_to_local`.

Decrypt **xong rồi mới** cổng IN: AES đã chạy; gói lệch policy tốn CPU rồi mới drop.

`policy_in_any` (`config_refresh_policy_in_any` lúc load/reload):

- Có **một** rule catch-all: `src_any && dst_any && proto ANY && port src/dst any` → `policy_in_any=1`, log `[CRYPTO-GUARD] WAN IN 5-tuple gate OFF (catch-all any/any)`.
- Không catch-all → `ON`, dựng bảng compact `s_pol_in[0][]`.

Bảng `pol_in_fill` — **đảo lúc compile**, field trên entry theo **gói sau decrypt**:

| Entry IN (`pol_in_match`) | Lấy từ policy OUT |
|---------------------------|-------------------|
| packet **src** IP | policy **dst** (mask/net; `dst_any` → mask 0; `dst_negate` → `POL_IN_SRC_NEG`) |
| packet **dst** IP | policy **src** (`src_negate` → `POL_IN_DST_NEG`) |
| packet **sport** | policy **dst port** range |
| packet **dport** | policy **src port** range |
| proto | giữ nguyên |

`config_policy_in_ok`: duyệt **mọi** entry (mọi policy của profile, encrypt **và** bypass). Proto → IP (+negate) → port. **Một** rule đảo khớp → cho qua. Không khớp rule nào → chặn.

Không chọn lại winner theo priority. Không đòi inner 5-tuple thuộc **đúng** `policy_id` trên wire — cổng là allowlist đảo, OR. Wire_id chỉ chọn key decrypt / profile.

Ví dụ cùng rule OUT `10.0.0.0/24 → 8.8.8.8:53` UDP:

- Inner `8.8.8.8:53 → 10.0.0.5:50000` UDP → IN **ok** (return).
- Inner `8.8.8.8:53 → 10.0.0.5:50000` TCP → **chặn** (proto).
- Inner `1.1.1.1:53 → 10.0.0.5:50000` UDP → **chặn** (src không phải dst-policy).
- Inner `10.0.0.5:50000 → 8.8.8.8:53` (cùng chiều OUT trên WAN) → **chặn** trừ khi có rule khác phủ (cổng IN không khớp chiều OUT).

Không stateful: không nhớ “đã thấy SYN OUT”. Hai chiều độc lập. Ai decrypt được (đúng key + wire_id) rồi 5-tuple giống return của **một** rule đều qua cổng.

#### B. Gói bypass plaintext (IPv4, không marker L2)

`wan_l2_plain_ipv4` bắt buộc. Không IPv4 → drop.

`wan_profile_pi_bypass`:

```
cp = config_select_crypto_policy(cfg, 0,
        dst_ip, src_ip,      // đảo IP
        dst_port, src_port,  // đảo port
        proto)
nếu !cp || cp->action != BYPASS → -1 → drop
```

Đảo **tham số** rồi dùng **cùng** hàm OUT (priority + id). Khác cổng encrypted:

- Phải thắng select **và** `action == BYPASS`. Rule encrypt không mở cửa IPv4 trần trên WAN.
- Không dùng bảng `s_pol_in`. Fail → `wan_drop` (không `wan_policy_drop`).
- Không decrypt. Không reorder §16.9.

Cùng ví dụ: plaintext `8.8.8.8:53 → 10.0.0.5:50000` chỉ qua nếu có **bypass** rule OUT `10/24 → 8.8.8.8:53`. Chỉ có rule encrypt → plaintext IN **drop** (return phải là 0x104A/0x104B).

#### C. Sau khi cổng IN mở

`forward_wan_to_local`: chỉ unicast (`dmac` bit 0 = 0). Broadcast/multicast data → drop. FDB `mac_lookup`; miss thì `mac_fwd_local_for_wan_dp`. LAN đích phải thuộc profile. Miss → drop, không flood data.

#### Tóm tắt hai chiều

| | OUT LAN→WAN | IN encrypted | IN bypass |
|--|-------------|--------------|-----------|
| Hàm | `config_select_crypto_policy` đúng 5-tuple | decrypt → `config_policy_in_ok` bảng đảo | `select` **đảo** 5-tuple, bắt `BYPASS` |
| Không khớp | `local_drop` | `wan_policy_drop` | `wan_drop` |
| Nhiều rule | một winner: priority rồi id | OR mọi rule đảo; catch-all → tắt cổng | một winner, phải bypass |
| Catch-all any/any | khớp mọi 5-tuple OUT | `policy_in_any=1` bỏ so 5-tuple | như OUT (bypass thắng thì plaintext qua) |
| ARP | bridge, không policy | bridge | không |

`[CRYPTO-GUARD] ... WAN IN 5-tuple gate ON/OFF` lúc refresh policy: OFF = có any/any, IN encrypted không lọc 5-tuple (vẫn cần decrypt đúng key).

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

Handshake (`pqc_handshake.c`): **chỉ trao key**. DB phải có `pqc_exchange_tunnels` → bind UDP `:7090` trên IP tunnel. Rekey dùng HELLO/RESP để stage key vào NEXT, sau đó READY/COMMIT có chữ ký mới promote; CURRENT cũ vẫn phục vụ trong cửa sổ chuyển đổi. **NE** (`crypto_runtime.c`) sở hữu đồng hồ 30 ngày per DB policy. Clock start ngay khi CURRENT được nạp vào RAM (`ne_pqc_on_key_material`), **không** chờ traffic encrypt. PREV chỉ bị xóa sau khi keepalive xác nhận peer đã dùng CURRENT mới và hết grace 90 giây. Chi tiết: **§19.3**, **§19.6**. **Mã hóa dataplane vẫn L2 PQC** 0x104A/0x104B.

Hot path: worker giữ snapshot ctx. Các event handshake copy đủ PREV/CURRENT/NEXT từ PQC control-plane vào master ctx; worker nhận snapshot mới theo generation. Không lấy `g_key_mutex` mỗi gói.

Không key / HS chưa ready → drop (không encrypt bằng key rác).

### 9.3 Fragment UDP

TCP không cắt (MSS clamp). UDP sát MTU thì cắt 2 frame, ráp, rồi buffer seq: **§16** / **§16.9**.

### 9.4 WAN → LAN decrypt — `dataplane_process_wan`

```
ARP marker / ARP → arp_bridge_from_wan
encrypted?
  wan_try_l2_pqc_udp  (pending 1=đợi mảnh; fail tagged = drop)
  decrypt_l2 (TCP/ICMP 0x104A)
  !policy_in_any? wan_policy_in_ok  (§8.2) else skip
  UDP take_rx_meta → dp_udp_reorder_submit  (§16.9)
  else bind TX: dp_flow_pick_tx_slot
plain bypass IPv4 → wan_profile_pi_bypass (5-tuple đảo, bắt BYPASS)  (§8.2)
mac_lookup → mid_to_local[li][tx_slot]
```

Decrypt xong mới pick TX slot (5-tuple plaintext), trừ UDP đi qua emit của reorder (cũng bind slot lúc emit). Cổng 5-tuple IN sau decrypt: **§8.2**.

---

## 10. Bypass

Policy `POLICY_ACTION_BYPASS`:

- `needs_mid` = 0 → **RX thread** xử lý, core 3–8 không nhận gói.
- Không marker, không worker_idx, không overhead.
- Vẫn `fwd_wan_pick_for_local` (gộp kênh per-packet).
- TX slot = `dp_pick_tx_slot` (hash), không crypto route table.

`crypto_enabled=0`: `needs_mid` = 0 với IPv4 non-ARP; `process_local` vẫn pick policy — chỉ **bypass khớp** mới `push_to_wan`, rule encrypt → drop. Không phải “mọi IPv4 đi RX→TX”.

ARP **không** bypass dù policy bypass.

Chiều WAN plaintext bypass: 5-tuple **đảo** + bắt `action==BYPASS` — **§8.2 B**.

---

## 11. XDP filter

`bpf/lan.c`: ARP hoặc IPv4 → `xsks_map[rx_queue_index]`. Frame > 1514 (hoặc VLAN 1518) **DROP** — trần cứng PATH_MTU 1500, chặn jumbo trước AF_XDP. Khác PASS kernel.

`bpf/wan.c`: CFM `0x8902` **PASS**. ARP, `0x1048`, **`0x104B` (UDP L2 PQC)**, IPv4 ICMP/TCP/UDP/OSPF → XSK. `wan_config_map[0]=0x104A` (TCP/ICMP…), `[1]=0x104B`. WAN **không** drop theo độ dài.

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
| `NE_PQC_KEY_LIFETIME_MS` | 30 ngày | NE đếm sau lần **encrypt** đầu / policy; hết hạn → `sig_pqc_request_new_session` |
| `PQC_HS_PORT` | 7090 | UDP handshake trên IP tunnel, không đi L2 0x88B5 |
| `PQC_HS_KEEPALIVE_INTERVAL_MS` | 15 s | Probe liveness; **không** drop key, **không** start clock |
| `PQC_HS_KEEPALIVE_MISSED_LIMIT` | 3 | Timeout keepalive = 45 s; chỉ log, key NE giữ nguyên |
| `PACKET_CRYPTO_NONCE_BYTES` | 12 | |
| `NE_L2_FAKE_ETHERTYPE` | 0x104A | TCP/ICMP/OSPF L2 PQC |
| `NE_L2_FAKE_ETHERTYPE_UDP` | 0x104B | mọi UDP L2 PQC (cắt và không cắt) |
| `NE_L2_FAKE_ETHERTYPE_ARP` | 0x1048 | ARP enc |
| UDP marker | `5B 55 44 01` | `0x5B 'U' 'D' v1` — plaintext sau nonce |
| `OPT_FRAG_META_LEN` | 47 | overhead UDP wire (marker 4 + shim 13 + tag 16 + …) |
| `UDP_REORDER_WINDOW` | 256 | seq slot / flow |
| `UDP_REORDER_HOLD` | 2 ms default | `NE_UDP_REORDER_US` 100–20000 |
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

Hai tầng trên máy nhận, **không** dính sticky WAN:

1. **Join mảnh** (`opt_table`, 200ms) — ráp frag0+frag1 **một** datagram. Hold-gap nội bộ: mảnh lẻ chưa TX LAN.
2. **Reorder datagram** (`udp_reorder.c`, hold 2ms default) — sau join (và UDP FULL không cắt), sắp lại theo `epoch+seq` per 5-tuple. Đây là chỗ giảm OOO 2 WAN.

WRR per-packet vẫn rải datagram liên tiếp sang 2 NIC. Reorder ngồi **sau** decrypt/join, trên **cùng** crypto worker sticky của flow. Luồng từng bước: §18.

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
if UDP:
    dp_udp_next_tx_seq(pkt) → crypto_option_udp_set_tx_seq(seq)
    // TLS: epoch process-wide, datagram_id worker-local clock
if crypto_option_need_split(opt_id, pclass, job.len):   // chỉ UDP ops trả 1
    split_tail_take → crypto_option_split → push_split_to_wan
    return 1   // đã TX 2 frame, caller không push_to_wan nữa
crypto_option_encrypt(...)  // UDP vừa MTU (vẫn 0x104B+shim FULL), hoặc TCP/ICMP/OSPF
return 0                    // caller push_to_wan 1 frame
```

TCP: trước đó `crypto_tcp_clamp_mss(1500, 30)` nên plaintext + 30B PQC ≤ MTU → không bao giờ `need_split`.

Registry: `g_ops[CRYPTO_OPT_L2_PQC][CRYPTO_PROTO_UDP] = crypto_opt_l2_pqc_udp_ops()`.

Worker TLS: `crypto_option_bind_worker_idx(w)` lúc `crypto_worker_thread` start. Mọi `l2_write_wire_header` ghi byte `worker_idx` = giá trị này. WAN RX `dp_crypto_pick_wan_worker` đọc đúng byte đó.

---

### 16.1 Wire layout (không VLAN; et_off = 12, eth header 14B)

Offset từ đầu frame. `et_off = crypto_eth_l2_prefix_len` = 12 (thường) hoặc 16 (VLAN). Dưới đây **không VLAN**. `crypto_eth_l2_has_marker` nhận **cả** `0x104A` và `0x104B`.

**A. TCP / ICMP / OSPF — `l2_do_encrypt` (không UDP)**

```
 0..5    dst MAC
 6..11   src MAC
12..13   EtherType = 0x104A
14       policy_id  = ctx->wire_id
15       worker_idx = crypto_option_worker_idx()
16..27   nonce 12B
28..     ciphertext(IPv4) || GCM tag 16B
```

`enc_start = 14+1+1+12 = 28`. Overhead 30B (`crypto_option_wire_overhead`). Không marker `5B 55 44 01`, không shim. Decrypt `l2_do_decrypt` → 0x0800.

**B. Mọi UDP L2 PQC — EtherType `0x104B` + marker plaintext + shim trong GCM**

Cả UDP vừa MTU (`L2_UDP_KIND_FULL`) lẫn hai mảnh (`FRAG0`/`FRAG1`) dùng **cùng** khung. File: `pqc_l2_option.c`. Marker 4B **ngoài** GCM (nhận diện không cần decrypt). Shim 13B **trong** GCM (không giả mạo kind/seq).

```
 0..5    dst MAC
 6..11   src MAC
12..13   EtherType = 0x104B     (NE_L2_FAKE_ETHERTYPE_UDP)
14       policy_id
15       worker_idx             ← CÙNG worker hai mảnh
16..27   nonce 12B              ← khác nhau từng frame (GCM riêng)
28..31   marker plaintext       {0x5B, 'U', 'D', 0x01}
32..     ciphertext:
           shim 13B:
             [0]  version<<4 | kind     kind: 0=FRAG0, 1=FRAG1, 2=FULL
             [1..4]  epoch u32 BE       process-wide, random lúc first use
             [5..8]  seq u32 BE         per-flow dataplane (bond seq)
             [9..12] datagram_id u32 BE worker-local clock / datagram
           || payload (IPv4 FULL/FRAG0, hoặc app-tail FRAG1)
         || GCM tag 16B
```

`enc_start = magic_off + 4 = 32`. `OPT_FRAG_META_LEN = 47` = policy+core+nonce (14 thay ethertype area) + marker 4 + shim 13 + tag 16, dùng trong `need_split` vs MTU.

Hai mảnh cùng datagram: cùng `epoch`, cùng `seq`, cùng `datagram_id`, khác `kind` và nonce. UDP không cắt: `kind=FULL`, vẫn 0x104B + marker + shim — **không** còn layout A cho UDP.

Nhận diện RX: `wan_l2_is_udp_tagged` = `crypto_eth_l2_has_marker` **và** `memcmp` 4B marker. Không còn false-positive 1 byte `0x5B` trong CT gói TCP. Tagged UDP mà decrypt/reasm fail → `wan_try_l2_pqc_udp` return **-1 drop** (không restore-scratch rồi `decrypt_l2`).

**C. ARP** ethertype 0x1048, không marker UDP, không split. Path `arp_bridge`.

BPF WAN (`bpf/wan.c`): hardcode redirect `0x104B`; `wan_config_map[0]=0x104A`, `[1]=0x104B` (`profile_xdp.c` `update_wan_fake_ethertype`).

---

### 16.2 Vì sao UDP iperf luôn cắt

```
l2_udp_need_split(pkt_len):
    return (pkt_len + 47) > crypto_option_get_mtu();  // default 1500
```

`pkt_len` = độ dài **Ethernet plaintext LAN** (UMEM), không phải `-l` iperf.

Iperf `-u -l 1470`: `14+20+8+1470 = 1512`. `1512+47 = 1559 > 1500` → **mọi datagram lớn đều 2 wire frames**.

UDP nhỏ (`pkt_len+47 ≤ 1500`): `need_split=0` → `l2_udp_encrypt` = `l2_do_encrypt_udp` (layout B, `kind=FULL`). Vẫn có seq trên dây; máy nhận vẫn `crypto_option_udp_set_rx_meta` → vào reorder. **Không** vào `opt_table`.

---

### 16.3 Thuật toán cắt — `l2_split` / `l2_udp_split`

Một datagram → **đúng 2** mảnh. Chỉ `ip_proto==17`. Cắt **app payload UDP**, không cắt IP/UDP header.

Ký hiệu (không VLAN): `l3_off=14`, `ip_hdr_len` = IHL*4 (thường 20), UDP header 8B, `app_len` = UDP payload.

```
frag_mtu       = crypto_option_get_mtu()          // 1500
frag_overhead  = l3_off + 47                      // 14+47=61
max_plain0     = frag_mtu - frag_overhead         // 1439
fixed_plain0   = ip_hdr_len + 8                   // 28
half1          = max_plain0 - fixed_plain0        // 1411 byte app trên frag0
nếu half1 >= app_len: half1 = app_len - 1         // luôn ≥1 byte cho frag1
half2          = app_len - half1
crypto_option_udp_tx_meta → epoch, seq, datagram_id
frag0_plain    = IP || UDP-hdr || app[0..half1)
frag1_plain    = app[half1..end)                  // KHÔNG IP, KHÔNG UDP
```

`seq` = `dp_udp_next_tx_seq` trên `g_route_table[].udp_tx_seq[direction]` (atomic per 5-tuple chuẩn hoá, 2 chiều độc lập). `datagram_id` = TLS `g_udp_tx_datagram_clock++` trên worker encrypt (khác seq: id ráp mảnh, seq sắp datagram). `epoch` = atomic process-wide, random lần đầu (`crypto_option_udp_epoch`).

Thứ tự encrypt trong `l2_split` (**frag1 trước**, rồi đè frag0 in-place):

1. `l2_encrypt_fragment_single(..., kind=FRAG1, epoch, seq, datagram_id, out=tail_buf)`
2. `l2_encrypt_fragment0_inplace(..., kind=FRAG0, cùng epoch/seq/datagram_id, in-place)`

Hai nonce độc lập. Cùng `wire_id`, `worker_idx`, `epoch`, `seq`, `datagram_id`.

Frag1 **không** tự thành IPv4. Join lấy L3 từ frag0. `opt_table` keyed `(epoch, datagram_id)` + khớp `bond_seq`; hash `datagram_id ^ (epoch * 0x9e3779b9) % 4096`, probe 8.

Ví dụ 1512B plaintext, half1=1411, app=1470 → half2=59B. Frag0 inner 20+8+1411=1439B.

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

### 16.5 RX — nhận diện, decrypt, join, rồi reorder

Chi tiết join: **§16.8**. Reorder sau join: **§16.9**.

**Nhận diện UDP tagged** `wan_l2_is_udp_tagged` (trước decrypt):

- `crypto_eth_l2_has_marker` (0x104A **hoặc** 0x104B)
- `memcmp` 4B `{0x5B,'U','D',0x01}` ngay sau nonce
- đủ chỗ shim 13 + tag 16

`l2_udp_is_fragment` cùng marker; `*pkt_id=0`, `*frag_index=0` — API cũ detection-only, seq nằm trong CT. Tagged UDP decrypt/reasm fail → drop, không fallback `decrypt_l2` vì trùng 1 byte 0x5B.

**Worker:** `dp_crypto_pick_wan_worker` đọc byte 15. Đẩy `wan_to_mid[wi]`. Bảng `g_tables[profile_slot][wi]` — sai worker = hai nửa không gặp nhau → timeout 200ms = loss.

**`l2_udp_reasm`** (trong `crypto_option_reassemble(..., CRYPTO_PROTO_UDP, ...)`):

```
nd = l2_do_decrypt_udp → epoch, seq, datagram_id, kind
kind == FULL:
    set_rx_meta(epoch, seq); IPv4 plaintext; return 1   // không opt_table
kind FRAG0/FRAG1:
    l2_reassemble(opt_table(slot, worker, create=1), epoch, datagram_id, seq, kind)
    join xong → set_rx_meta(epoch, seq)
```

`l2_reassemble`:

- `inner = pkt + wire_eth`, `inner_len = len - 14`
- `idx = opt_pick_slot(ft, epoch, datagram_id, now)`
- `kind==FRAG0`: inner IPv4; `opt_store_first` copy eth + inner
- `kind==FRAG1`: `opt_store_second` copy inner (không eth)
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

**`wan_try_l2_pqc_udp`:** không tagged → 0. Tagged + reasm ok → **1**. Tagged + reasm fail → **-1** (`decrypt_wan` drop).

**`decrypt_wan` rồi `dataplane_process_wan`:**

```
l2_fast = wan_try_l2_pqc_udp(...)
l2_fast==1 && pending==1 → decrypt_wan return 1 → ne_frame_free(job); return
                          // chưa vào reorder — join hold-gap
l2_fast==1 && pending==0 → datagram FULL hoặc đã join; return 0
l2_fast==0               → decrypt_l2 (TCP/ICMP 0x104A)
l2_fast<0                → drop

decrypt 0 + take_rx_meta ok + inner UDP → dp_udp_reorder_submit (§16.9)
decrypt 0 + không UDP meta             → forward_wan_to_local
```

Join-pending (bảng mảnh, chưa reorder):

```
t0  A-frag0  store, free frame, không TX LAN, chưa submit reorder
t1  B join xong  → reorder_submit(seq=B)
t2  A-frag1  join A → reorder_submit(seq=A)
```

Nếu `seq(A) < seq(B)`: B `delta>0` được **hold** trong cửa sổ 256 / 2ms; A tới `delta==0` → emit A rồi flush B. Trước đây t1 TX LAN ngay = OOO. 1 WAN bài D: hai mảnh kề nhau, A join trước B, reorder passthrough (~45/71.3M). 2 WAN: t1 thường xuyên — đúng chỗ reorder ngồi.

---

### 16.5b Bảng reasm (join mảnh — không phải reorder)

```
g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS]   // calloc khi create=1
struct opt_entry {
    uint32_t epoch, datagram_id, bond_seq;
    uint32_t first_len, second_len;
    uint64_t timestamp_ns;
    uint8_t  eth_hdr[18], eth_len, got_first, got_second;
    uint8_t  first[1600], second[1600];
};
struct opt_table { gc_cursor; entries[4096]; }
```

`opt_pick_slot(epoch, datagram_id)`: `base = (datagram_id ^ epoch*0x9e3779b9) % 4096`, probe **8**. Ô cùng cặp còn sống → trống (GC age > 200ms) → occupied già nhất (**evict** = loss nửa kia).

`opt_prepare_entry`: epoch/datagram_id/`bond_seq` khác hoặc quá 200ms → `opt_clear_entry` (chỉ metadata, không memset 3248B).

`opt_time_ns`: `CLOCK_MONOTONIC_COARSE`. GC slice **256** ô / tick 2048 vòng crypto. `opt_table(..., create=0)` trên path GC — không calloc worker chưa UDP cắt.

1600B đủ nửa MTU; `first_len+second_len+eth > NE_FRAME(2048)` → join fail.

---

### 16.5c Mã trả về tóm tắt (để debug)

| Hàm | 0 | 1 | -1 |
|-----|---|---|-----|
| `l2_udp_need_split` | không cắt | cắt | (không) |
| `encrypt_to_wan` | 1 frame, caller push | đã push 2 mảnh | drop |
| `l2_udp_reasm` / `l2_reassemble` | đợi mảnh kia | đã join | lỗi decrypt/store |
| `wan_try_l2_pqc_udp` | không tagged | đã xử lý UDP tagged | decrypt/reasm fail → drop |
| `decrypt_wan` | xong | pending, free frame | drop |
| `dataplane_process_wan` | TCP/bypass TX LAN | UDP tagged → reorder | — |

### 16.6 Hai tầng OOO (join vs reorder)

| Nguồn | Cơ chế | Hiện tại |
|-------|--------|----------|
| Per-packet 2 WAN (§7) | Datagram N WAN0, N+1 WAN1 | Vẫn stripe; **sau join** buffer seq §16.9 |
| UDP split ×2 + crypto ×2 | 1 datagram = 2 frame + 2 AES | 1 WAN gần vô hại (bài D). 2 WAN nhân join-pending |
| Join hold-gap | Frag0 giữ A trong `opt_table`, B join trước | A chưa vào reorder; B `delta>0` → **hold B** tới A hoặc timeout 2ms |
| Reorder late/dup | `delta<0` hoặc slot cùng seq | drop (`late_or_duplicate`) |
| Reorder skip-gap | hold hết, seq thiếu | nhảy `next_seq`, `gap_skipped`; gói trễ sau đó drop |
| 1 LAN+1 WAN bài D | `n==1`, TX tuần tự | **8.38G, loss 0.16%, OOO 45/71.3M** — reorder gần passthrough |
| 1 LAN+1 WAN overrun | `fwd_wan_has_tx_room` drop | Loss — bão hòa NIC |
| Tắt per-packet | Sticky 1 WAN/flow | OOO giảm vì hết stripe — **không** làm vậy |
| TX slot sticky | 1 flow 1 TX consumer / ring | Không giữ thứ tự giữa 2 NIC |
| 2 mảnh cùng WAN+slot | push 0 rồi 1 | Không đổi |

Reorder **không** pick WAN, **không** đổi WRR. Tắt: `NE_UDP_REORDER=0`. Bài D: join không phải nguồn OOO hàng loạt; 2 path × 2 mảnh là điều kiện reorder phải gánh.

### 16.7 Cách hai mảnh đang gắn với nhau

Hành vi hiện tại:

1. Cùng `worker_idx` trên wire → cùng crypto core.
2. Cùng `wan_dp` + `tx_slot` lúc TX.
3. Cùng `epoch` + `datagram_id` + `bond_seq` (shim GCM).
4. TCP không split (MSS clamp).
5. Reasm table per `(profile_slot, worker)`.
6. Frag1 không IP/UDP — L3 từ frag0.

WRR từng *mảnh* làm hai nửa không gặp nhau. Timeout join 200ms ≠ cửa sổ reorder 2ms. Jumbo / `pkt_len+47 ≤ MTU` thì hết join; UDP FULL vẫn có seq → vẫn reorder (lệch delay 2 WAN một frame).

---

## 16.8 Rã ráp UDP — join mảnh (opt_table)

Đây là ráp **hai mảnh một datagram**, không phải handshake PQC, **không** phải buffer seq datagram (§16.9).

| Đây | Không phải đây |
|-----|----------------|
| `src/crypto/pqc/pqc_l2_option.c` — `l2_udp_reasm` / `l2_reassemble` / `opt_*` | Handshake PQC (`pqc_handshake.c` UDP :7090) |
| `wan_ingress.c`: `wan_try_l2_pqc_udp` → `reassemble_l2` → `decrypt_wan` | TCP / ICMP / OSPF / ARP |
| TX cắt: `local_egress.c` `encrypt_to_wan` / `push_split_to_wan` / `l2_split` | `l2_do_encrypt` TCP; UDP nhỏ = `l2_do_encrypt_udp` FULL |
| Sau join: `crypto_option_udp_set_rx_meta` → §16.9 | emit LAN ngay (cũ) |

Hằng số live:

| Tên | Giá trị | Ý |
|-----|---------|---|
| `OPT_FRAG_TABLE_SIZE` | 4096 | số ô / bảng |
| probe | 8 | cửa sổ từ hash `(datagram_id ^ epoch*0x9e3779b9) % 4096` |
| `OPT_FRAG_TIMEOUT_NS` | 200 ms | GC mảnh mồ côi; **không** phải reorder hold |
| `OPT_FRAG_META_LEN` | 47 | overhead UDP trên dây (so MTU) |
| `L2_UDP_MARKER_SIZE` | 4 | `{0x5B,'U','D',0x01}` plaintext |
| `L2_UDP_SHIM_SIZE` | 13 | kind+epoch+seq+datagram_id **trong GCM** |
| `crypto_option_wire_overhead(L2_PQC)` | 30 | TCP/ICMP gói nguyên (không marker/shim) |
| MTU | 1500 default | `crypto_option_get_mtu()` |
| `NE_FRAME` | 2048 | trần join / UMEM |
| `first[]`/`second[]` | 1600 | trần inner mỗi nửa |
| GC tick | 2048 vòng crypto | slice **256** ô, `create=0` không calloc |

Một connect = một crypto worker. WAN không sticky. Hai mảnh cùng worker, cùng WAN, cùng TX slot, cùng `(epoch, datagram_id, seq)`.

---

### 16.8.1 Cặp mảnh trên dây (đầu vào của ráp)

`l2_udp_need_split`: `(pkt_len + 47) > mtu`. Đúng **2** mảnh. Cắt **app UDP**; IP+UDP hdr trên frag0.

So sánh 47 vs 30: TCP `+30`. UDP luôn marker+shim nên `+47` kể cả FULL. `need_split` dùng 47. iperf `-l 1470` frame LAN 1512, cắt chắc.

Công thức `l2_split` (không VLAN):

```
frag_overhead = l3_off + 47 = 61
max_plain0    = 1500 - 61 = 1439
fixed_plain0  = 20 + 8 = 28
half1         = 1439 - 28 = 1411
nếu half1 >= app_len: half1 = app_len - 1
half2         = app_len - half1
```

iperf `-l 1470`: `half1=1411`, `half2=59`.

IP `tot_len` / UDP `length` trên frag0 **vẫn gốc**. Join không sửa checksum.

`seq` = `dp_udp_next_tx_seq` (atomic per flow+direction trên `g_route_table`). `datagram_id` = TLS clock worker. `epoch` = process-wide. Không còn `g_opt_pkt_id` u16.

Layout dây: **§16.1 B**. `enc_start=32` (không VLAN). GCM phủ shim+payload. Marker 4B ngoài GCM.

VLAN: `et_off=16`, offset +4. `ETH_L2_HDR_MAX=18`.

`l2_split`: encrypt frag1 trước (`L2_UDP_KIND_FRAG1`), rồi frag0 in-place (`FRAG0`). `push_split_to_wan` không đổi: 2 chỗ trống; frag1 fail sau frag0 queued = orphan 200ms = loss.

### 16.8.2 Gói đi vào worker nào

WAN RX: `crypto_eth_l2_read_worker_idx` = byte 15 → `wan_to_mid[W]`. Crypto thread W gọi `reassemble_l2` với `dp_crypto_current_worker_idx()` = W. Bảng `g_tables[profile_slot][W]`. Chỉ thread đó đọc/ghi — **không lock**.

Sai worker (byte 15 ≠ thread đang chạy): hai nửa không chung bảng, 200ms GC = loss. Sticky crypto lúc LAN RX (`crypto_route.c`) ghi `worker_idx` lên header lúc encrypt, nên hai mảnh cùng W nếu cùng datagram.

`profile_slot` = `fwd_crypto_profile_slot_for_id(fwd_crypto_profile_id_for_wire_id(policy_id))`. Live một profile → slot 0. `opt_table` clamp slot/worker về 0 nếu out of range.

`opt_table` lần đầu `calloc` khi **`create=1`** (reasm UDP cắt). Path GC gọi `opt_table(..., create=0)` — worker chưa từng UDP cắt **không** calloc ~13 MB.

---

### 16.8.3 Nhận diện UDP tagged — trước AES

`wan_l2_is_udp_tagged` (`wan_ingress.c`), **không decrypt**:

1. `crypto_eth_l2_has_marker` — 0x104A **hoặc** 0x104B
2. `mark_off = crypto_eth_l2_frag_magic_off(..., 12)` = **28** không VLAN, **32** VLAN
3. `memcmp` 4B `{0x5B,'U','D',0x01}`
4. đủ `marker + shim 13 + tag 16`

`kind`/`seq` **không** đọc trước decrypt. `l2_udp_is_fragment` cùng marker; output `pkt_id`/`frag_index` luôn 0.

Nhánh nhanh `wan_try_l2_pqc_udp` không gọi `l2_udp_is_fragment`. Fail tagged → **-1 drop**, không restore-scratch + `decrypt_l2`. TCP 0x104A không có marker 4B → không vào nhánh này.

---

### 16.8.4 Decrypt UDP — `l2_do_decrypt_udp`

In-place:

1. Marker match; `enc_start = magic+4` (=32 không VLAN).
2. GCM decrypt từ enc_start (shim + payload + tag).
3. Parse shim: version nibble, kind, epoch BE, seq BE, datagram_id BE.
4. `memmove` payload về `l3_off`. EtherType ghi 0x0800 khi FULL / lúc join.

| kind | Buffer từ offset 14 |
|------|---------------------|
| FULL / FRAG0 | IPv4 \|\| UDP \|\| … |
| FRAG1 | half2 thuần |

Decrypt fail → `l2_udp_reasm` -1 → `wan_try_l2_pqc_udp` -1 → drop.

---

### 16.8.5 Bảng — struct, RAM, layout cache

```
g_tables[MAX_PROFILES][NE_CRYPTO_WORKERS]   // con trỏ; calloc trong opt_table()

struct opt_entry {                 // ~3248 B, payload arrays vẫn 1600
    uint32_t epoch, datagram_id, bond_seq;  // đầu struct — probe cùng cache line hơn pkt_id cũ
    uint32_t first_len, second_len;
    uint64_t timestamp_ns;         // CLOCK_MONOTONIC_COARSE
    uint8_t  eth_hdr[18], eth_len, got_first, got_second;
    uint8_t  first[1600], second[1600];
};

struct opt_table { gc_cursor; entries[4096]; }
```

`opt_clear_entry` chỉ hạ metadata (không memset 3248B mỗi join). Probe vẫn đọc got_* + timestamp; payload array vẫn lớn — miss khi copy inner.

Pending: `dec==1` → `ne_frame_free`. Join xong **không** TX LAN ngay: `set_rx_meta` → `dataplane_process_wan` → §16.9.

**Copy-based:** không giữ frame UMEM. `crypto_l2_pqc_bind_pair` / `reasm_set_addr` no-op. `crypto_l2_pqc_reasm_held()` **luôn 0**. `crypto_l2_pqc_reasm_out_addr()` **luôn 0**. `reassemble_l2` gọi `crypto_l2_pqc_reasm_set_addr(addr)` rồi bỏ qua. Join ghi đè `out_buf = pkt` (cùng UMEM mảnh vừa decrypt).

Pending: `dataplane_process_wan` `dec==1` → `ne_frame_free(job.addr)`. Dữ liệu mảnh chỉ còn trong `opt_entry`. Mảnh kia tới: decrypt vào frame mới, join vào frame đó, TX LAN. FQ UMEM không bị giữ.

`decrypt_wan` có nhánh `if (out_addr && out_addr != job->addr)` đổi frame — **chết** vì `out_addr` luôn 0.

---

### 16.8.6 Chọn ô — `opt_pick_slot` rồi `opt_prepare_entry`

Mỗi `l2_reassemble`: `now = opt_time_ns()` = `CLOCK_MONOTONIC_COARSE`.

```
base = (datagram_id ^ epoch * 0x9e3779b9) % 4096
probe 8
occupied && age > 200ms → opt_clear_entry (metadata only)
cùng epoch+datagram_id → return idx
trống → empty; occupied khác → oldest → evict
opt_prepare_entry: epoch/id/bond_seq khác hoặc quá hạn → clear metadata
gán epoch, datagram_id, bond_seq; timestamp = now
```

Cùng cặp luôn cùng cửa sổ 8. `bond_seq` phải khớp khi thêm nửa thứ hai. Evict = loss nửa cũ. Không lock.

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
opt_clear_entry (metadata)
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
3. `decrypt_wan` → `wan_try_l2_pqc_udp` (không scratch full-frame vì marker 4B unambiguous):
   - `reassemble_l2`: `crypto_option_reassemble(L2_PQC, UDP, ...)`.
4. `l2_udp_reasm`: AES-GCM → parse shim → `l2_reassemble`.
5. `opt_pick_slot` ô trống, `opt_store_first`, `opt_emit_join` return 0.
6. `pending=1`. `wan_try_l2_pqc_udp` return 1. `decrypt_wan` return 1.
7. `ne_frame_free(A0)`. A nằm bảng. Chưa reorder.

**A1 tới**

1–4 decrypt inner half2.
5. `opt_pick_slot` cùng epoch+datagram_id, `opt_store_second`, join, `set_rx_meta(epoch, seq)`.
6. `decrypt_wan` return 0.
7. `dataplane_process_wan`: `take_rx_meta` → `dp_udp_reorder_submit` (§16.9) — **không** `forward_wan_to_local` trực tiếp.

Giữa A0 pending và A1 join, worker có thể join B trước → B vào reorder trước A; buffer seq giữ B nếu `seq(A)` nhỏ hơn.

**A1 tới trước A0:** store second, pending free A1; A0 tới join trên frame A0. Cùng đúng.

---

### 16.8.10 Chuỗi mã trả về

`l2_udp_reasm` / `l2_reassemble`: 0 đợi / 1 xong / -1 lỗi.

`reassemble_l2`: rr=1 → `*len=blen`, pending không set (0). rr=0 → pending 1. rr khác → -1.

`wan_try_l2_pqc_udp`: không tagged → 0. reasm ok → **1**. reasm -1 → **-1** (`decrypt_wan` drop). Không restore-scratch.

`decrypt_wan` khi `l2_fast==1`:

| pending | return | `dataplane_process_wan` |
|---------|--------|-------------------------|
| 2 | 2 | không xảy ra (`held=0`) |
| 1 | 1 | `ne_frame_free`; chưa reorder |
| 0 | 0 | FULL hoặc join xong → `take_rx_meta` → §16.9 |

`l2_fast==0`: TCP/ICMP `decrypt_l2`. Tagged UDP không đi nhánh này.

---

### 16.8.11 Hold-gap join vs reorder

Mảnh thứ nhất: store, free UMEM, **không** `set_rx_meta`. Mảnh thứ hai: join, `set_rx_meta(seq)`, **reorder** — không TX LAN ngay.

```
t0  A0  store A, free frame
t1  B join  → reorder_submit(B)
t2  A1  join A → reorder_submit(A)
```

Nếu seq(A) < seq(B): B hold tới A hoặc hết 2ms (`gap_skipped`). Tăng `OPT_FRAG_TIMEOUT_NS` (200ms) không phải cửa sổ reorder. Ráp không TX từng mảnh của A; OOO giữa A và B là việc của §16.9.

---

### 16.8.12 Occupancy, evict (không còn wrap u16 global)

Key 32-bit `(epoch, datagram_id)` + `bond_seq`. Hash mix epoch. Wrap datagram_id worker-local u32 — không còn wrap 0.65s của pkt_id 16-bit.

Pending ≈ skew A0→A1 × dps / worker. Probe 8 vẫn trần va chạm cửa sổ. Sticky nhiều flow một worker + skew lớn → evict = loss nửa.

---

### 16.8.13 GC định kỳ

Cùng tick 2048: `fwd_crypto_frag_gc_worker_tick` **và** `dataplane_udp_reorder_gc`.

Frag: `opt_table(..., 0)` — không calloc. `opt_frag_gc_table` slice **256** ô, `opt_clear_entry` metadata. Probe 8 vẫn GC tại chỗ.

Reorder GC: slice 16 flow / tick — §16.9.

---

### 16.8.14 Chi phí byte trên hot path

Một datagram cắt = 2 mảnh RX. iperf 1470, không VLAN, ráp thành công, A0 trước A1:

| Bước | A0 | A1 (join) |
|------|----|-----------|
| scratch copy wire | không (marker 4B) | không |
| AES-GCM decrypt | shim+inner+16 | shim+half2+16 |
| memmove inner về 14 | inner | half2 |
| clock_gettime COARSE | 1 | 1 |
| probe 8 | 8 | 8 |
| memcpy vào bảng | eth+first | second |
| memcpy join ra UMEM | — | eth+first+second |
| opt_clear_entry | — (pending) | metadata |
| ne_frame_free | có | không (frame join → reorder) |

TX (chiều gửi, không phải ráp nhưng tạo input ráp): 2 AES encrypt, 1 `split_tail_take`, 2 `ne_ring_try_push`, alloc batch 32 khi cache cạn.

False 0x5B 1-byte trên TCP: không vào path UDP (thiếu marker 4B). Tagged fail = drop.

---

### 16.8.15 Việc **join** không làm (reorder làm ở §16.9)

- Không giữ UMEM (`held=0`).
- Không sửa L3/L4 lúc join.
- Không lock trên `opt_entry`.
- Không WRR lại hai mảnh.
- Không ráp TCP.
- Timeout 200ms = GC orphan join, **không** phải hold reorder.

---

### 16.8.16 Chỗ logic chạm khi tối ưu ráp

Hành vi hiện tại, từng khâu — đổi khâu nào thì hệ quả đi theo:

| Khâu | Việc đang làm | Hệ quả gắn với ráp |
|------|----------------|-------------------|
| Copy `first[]`/`second[]` | Không giữ UMEM | 2 memcpy/mảnh + join |
| `held`/`out_addr` = 0 | API giữ frame không gắn | `dec==2` chết |
| Key `(epoch, datagram_id, bond_seq)` | Không u16 global | Wrap u32 / worker |
| Probe 8 + evict oldest | Không chain | Đầy cửa sổ 8 → loss nửa |
| Timeout 200ms | GC orphan join | Không phải cửa sổ §16.9 |
| Join xong `set_rx_meta` | Đưa seq cho reorder | Không TX LAN tại chỗ này |
| `opt_clear_entry` metadata | Không memset 3248B | |
| GC slice 256, `create=0` | Không calloc idle | |
| 2 mảnh cùng WAN+slot | TX 0 rồi 1 | Ráp đúng |
| `need_split` +47 | Cắt khi `pkt+47>mtu` | FULL UDP vẫn 0x104B+shim |
| `push_split` fail mảnh 1 | không rollback | orphan 200ms = loss |
| Jumbo / `pkt+47 ≤ mtu` | không vào bảng | FULL vẫn vào reorder |

Bài D: join không phải nguồn OOO hàng loạt. 2 WAN: lệch path sau join là việc **§16.9**, không tăng timeout 200ms.

---

## 16.9 Buffer giảm OOO UDP sau join

Bonding vẫn **per-packet WRR** (§7). Đây không phải sticky WAN. Buffer nằm trên **crypto worker** sticky của flow, **sau** decrypt/join, **trước** FDB/`mid_to_local`.

File: `inc/core/dataplane/udp_reorder.h`, `src/core/dataplane/udp_reorder.c`. Hook: `dataplane_process_wan` (`wan_ingress.c`). Seq TX: `dp_udp_next_tx_seq` (`crypto_route.c`) + TLS `crypto_option_udp_set_tx_seq` / `tx_meta` / `set_rx_meta` / `take_rx_meta` (`crypto_option_router.c`). Test: `tests/test_udp_reorder.c`. Stats: `[DP-STATS] udp_reorder ...` (`stats.c`). Init: `dataplane_udp_reorder_configure()` lúc spawn crypto. Exit worker: `dataplane_udp_reorder_reset`. Cùng tick 2048 với frag GC: `dataplane_udp_reorder_gc`.

### 16.9.1 Ai vào buffer

Chỉ khi **cả** các điều kiện:

1. Frame vừa decrypt thành công (`dec==0`), đã policy_in / MSS clamp.
2. `crypto_option_udp_take_rx_meta(&epoch, &seq)==0` — FULL hoặc vừa join (cùng `seq` hai mảnh).
3. Inner IPv4 UDP parse được 5-tuple (`dp_parse_flow`).

TCP, ARP, bypass, UDP meta fail → `forward_wan_to_local` như cũ. `take_rx_meta` **consume** TLS (một lần / datagram).

`NE_UDP_REORDER=0`: `dp_udp_reorder_submit` emit ngay (`item_emit`), không hold.

### 16.9.2 Seq trên dây — ba số khác nhau

| Số | Nguồn | Việc |
|----|--------|------|
| `seq` (bond seq, u32) | `g_route_table[flow].udp_tx_seq[dir]` atomic `fetch_add` | Thứ tự datagram **một chiều** 5-tuple chuẩn hoá. Reorder so sánh cái này. |
| `datagram_id` | TLS `g_udp_tx_datagram_clock++` trên worker encrypt | Key **join** hai mảnh. Không dùng reorder. |
| `epoch` | atomic process-wide, random lần đầu (≠0) | Đổi epoch → `flow_reset` drop held cũ. |

Chiều: `dp_route_key_parse_direction` chuẩn hoá IP/port; `dir` 0 hoặc 1. Hai chiều cùng 4-tuple có **hai** bộ đếm seq độc lập. `set_tx_seq` gán seq **và** cấp datagram_id mới mỗi datagram (kể cả FULL).

Fallback: route set đầy → TLS `tls_udp_seq_fallback[256][4]` worker-local, không lock. Seq vẫn tăng.

Hai mảnh một datagram: `l2_split` đọc `tx_meta` **một lần** — cùng seq. Reorder chỉ thấy datagram **sau** join.

### 16.9.3 Cấu trúc per crypto worker (không lock)

```
UDP_REORDER_SETS = 128, WAYS = 4  → 512 flow / worker
WINDOW = 256 seq slot / flow
HELD_CAP = 8192 frame / worker
START_BACKTRACK = 32   // flow mới: next_seq = first_seq - min(seq, 32)
FLOW_IDLE = 60s        // GC xóa flow không held
DEFAULT_HOLD = 2ms     // NE_UDP_REORDER_US clamp 100–20000 µs
GC_SLICE = 16 flow / tick
```

`g_flows[W][512]`, `g_slots[W][512][256]` — mỗi slot giữ `ne_packet` (UMEM addr) + profile_pi + ingress_wan_dp.

Hash 4-tuple (src/dst IP/port **không** chuẩn hoá — chiều RX LAN của máy nhận). Lookup: set 4-way, victim stamp LRU-ish; evict đếm `evicted`, `flow_drop_slots`.

Epoch khác trên cùng key → `flow_reset` (drop held epoch cũ — test: seq held epoch cũ bị drop).

### 16.9.4 `dp_udp_reorder_submit` — delta

`seq_delta = (int32_t)(seq - next_seq)` (wrap u32).

Trước so sánh: nếu đang có gap (`held && gap_since_ns`) và `now - gap_since >= hold_ns` → `flow_skip_gap`.

| delta | Việc |
|-------|------|
| `< 0` | late / đã qua `next_seq` → **drop** (`late_or_duplicate`), `ne_frame_free` |
| `== 0` | emit ngay (`udp_reorder_emit` → bind TX slot + `forward_wan_to_local`), `next_seq++`, `flow_flush_contiguous` (slot `next_seq % 256` khớp seq) |
| `> 0` | future: `flow_make_window_room` nếu `delta >= 256`; nếu `held_by_worker >= 8192` skip-gap rồi vẫn đầy → drop `overflow`; store `g_slots[W][flow][seq % 256]`; nếu slot occupied cùng seq → drop dup; occupied seq khác → drop item cũ (`overflow`), ghi đè |

Store lần đầu gap: `gap_since_ns = now`. `held++`. Stat `held`, `high_water`.

`flow_skip_gap`: tìm seq held nhỏ nhất `delta>=0`, nhảy `next_seq` tới đó, cộng `gap_skipped` bằng số seq bỏ, rồi flush contiguous. Datagram thiếu **mất** với iperf (loss); gói tới muộn sau skip → late drop.

`flow_make_window_room`: khi seq quá xa cửa sổ, skip_gap vòng cho tới khi `delta < 256`, hoặc gán `next_seq = seq - 255`.

### 16.9.5 Emit / drop ops

`udp_reorder_emit` (`wan_ingress.c`): `dp_out_ring_bind(dp_flow_pick_tx_slot(...))` rồi `forward_wan_to_local`. Fail emit → drop (free UMEM). `was_held` → stat `released`.

`udp_reorder_drop`: `ne_dp_stats_wan_drop` + `ne_frame_free`. Submit **luôn** lấy ownership item.

### 16.9.6 GC

`dp_udp_reorder_gc`: 16 flow từ `gc_cursor`. Held + gap timeout → skip_gap. Không held + idle 60s → memset flow.

Clock: `CLOCK_MONOTONIC_COARSE` (`dp_udp_reorder_now_ns`).

### 16.9.7 Walk 2 WAN (ý đồ giảm OOO)

```
N.frag0 WAN0  → opt_table pending
N+1 cả hai WAN1 → join N+1, reorder_submit(seq=N+1)
                delta>0, hold N+1 trong window (không TX LAN)
N.frag1 WAN0  → join N, reorder_submit(seq=N)
                delta==0, emit N, flush N+1
→ LAN: N rồi N+1  (iperf in-order)
```

Nếu N mất (mảnh không tới trong 2ms): skip_gap emit N+1, `gap_skipped`. N tới muộn → late drop. Hold 2ms ≪ join timeout 200ms: không chờ mảnh mồ côi 200ms trên LAN path.

1 WAN bài D: join gần in-order, delta==0 hầu hết, hold ~0, OOO 45/71.3M gần như trước.

### 16.9.8 Env và stats

| Env | Ý |
|-----|---|
| `NE_UDP_REORDER=0` | tắt buffer, emit ngay |
| `NE_UDP_REORDER_US` | hold µs, clamp 100–20000; default 2000 |

`[DP-STATS] udp_reorder held= released= late_dup= gap_skip= overflow= evicted= held_high_water=`

`held` đếm lần store (không phải depth hiện tại). `released` lần emit từ slot. `high_water` max `g_held_by_worker`.

### 16.9.9 Việc buffer **không** làm

- Không đổi WRR / không sticky WAN / không pick WAN lần 2.
- Không ráp mảnh (vẫn `opt_table` 200ms).
- Không TCP (không `set_rx_meta`).
- Không lock cross-worker: 1 flow 1 crypto core nên 1 bảng.
- Không chờ vô hạn: 2ms rồi skip-gap.
- Window 256: burst OOO lớn hơn cửa sổ → skip/overflow.

### 16.9.10 Test (`tests/test_udp_reorder.c`)

Ops giả: emit ghi seq, drop đếm. Worker_idx=0.

- Submit 0,2,1 → emit 0,1,2 (hold 2 tới khi 1).
- Submit 1 rồi 0 → emit 0 rồi 1.
- 0,2 rồi 3 sau 3ms (quá hold) → skip gap, emit 0,2,3 (mất 1).
- Dup seq 0 → 1 emit, 1 drop.
- Wrap `UINT32_MAX-1, MAX, 0, 1` + GC sau 3ms → emit 4 seq wrap.
- Epoch đổi: held epoch cũ drop, seq mới emit.

---

## 17. Phân tích: vì sao 2 WAN OOO, 1 WAN thì không

Luồng từng bước: **§18**. Hệ số: WRR 2 path × split ×2. **Đã có** buffer seq UDP sau join (§16.9, hold 2ms). Chưa jumbo. Bài D đo **trước** reorder; số OOO 2 WAN cũ (15–54%) là baseline không buffer.

### 17.1 Đối chứng bài D

Bài D: **cùng** L2 PQC, **cùng** `need_split`, **cùng** 2 AES encrypt + 2 AES decrypt / datagram, **cùng** bảng reasm 200ms — chỉ khác `pool_n==1`. Kết quả 8.38G / 0.16% loss / 45 OOO.

Không phải AES làm hỏng thứ tự, không phải bảng reasm hỏng, không phải TX slot sticky hỏng, không phải “1 connect 1 crypto core” hỏng.

Là `g_pkt_wrr_seq` rải datagram liên tiếp sang 2 NIC trong khi mỗi datagram đã nhân ×2 frame + ×2 crypto. Hai queue độc lập + join-pending (A chờ frag1 WAN0, B đã join trên WAN1) — **trước §16.9** B TX LAN ngay. Sau §16.9 B hold tới A (hoặc 2ms skip-gap). 1 WAN bài D gần in-order sẵn nên buffer gần passthrough.

Công thức nhân (iperf `-l 1470`, MTU 1500):

```
1 datagram UDP gốc
  → 2 wire frames (frag0 + frag1)
  → 2 AES-GCM encrypt (LAN crypto)
  → 2 lần TX WAN  (cùng wan_dp, cùng tx_slot)
  → 2 lần RX WAN  (lệch delay nếu 2 datagram khác WAN)
  → 2 AES-GCM decrypt
  → 1 join
  → take_rx_meta → reorder_submit (§16.9)
  → 1 datagram ra LAN (in-order hoặc skip-gap 2ms)

71.3M datagram bài D  →  ~142.6M frame wire  →  ~142.6M enc + ~142.6M dec
```

1 WAN: 142.6M frame một `mid_to_wan[0][slot]`, TX tuần tự `N.f0, N.f1, N+1.f0, N+1.f1` → join gần như in-order.

2 WAN weight 50/50: datagram chẵn WAN0 (2 frame), lẻ WAN1 (2 frame). Cùng stream, cùng crypto worker, cùng TX **slot** nhưng **hai ring**. Bốn frame của hai datagram cạnh nhau không còn thứ tự trên một NIC.

### 17.2 Các khâu trên đường đi (code hiện tại)

`g_pkt_wrr_seq` một counter toàn cục:

- Không gắn flow — stripe theo nhịp **xong encrypt**, không theo seq UDP.
- Không gắn delay WAN — weight 50/50 kể cả khi một đường chậm hơn.
- UDP 0x104B + shim GCM: `seq` per-flow; máy nhận reorder sau join (§16.9).
- `fwd_wan_has_tx_room` fail thì drop, không thử WAN kia.
- `tx_thread` drain `for wi in wans` — burst WAN0 rồi WAN1.
- Split: pick một lần / datagram (hai mảnh cùng WAN); datagram k và k+1 có thể khác WAN → join-pending rồi reorder.
- Crypto worker pop `wan_to_mid` trước `local_to_mid` — chiều về xen chiều đi trên cùng core.

Chỗ hệ số nằm:

- **Split ×2** (`need_split` khi `pkt_len+47 > 1500`): mỗi datagram 2 AES + 2 frame + 1 join. Jumbo / payload nhỏ thì hết join; UDP FULL vẫn 0x104B+seq → reorder chỉ lệch delay 2 WAN (1 frame).
- **Reorder sau join (§16.9):** hold 2ms / skip-gap; late drop. Tắt `NE_UDP_REORDER=0` = hành vi cũ emit ngay.
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
         UDP: dp_udp_next_tx_seq → set_tx_seq
         need_split?  YES
         split_tail_take → frame UMEM thứ 2
         crypto_option_split → AES frag1 rồi AES frag0 (cùng epoch/seq/datagram_id)
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
[dây WAN 0 hoặc WAN 1]  2 frame 0x104B + marker 5BUD01 + shim (cùng epoch/seq/datagram_id, kind 0 rồi 1)
     │
     ▼
Máy nhận  CPU 11  wan_rx_thread
     đọc worker_idx byte 15 → push wan_to_mid[W]   (cùng W vì TX ghi W)
     │
     ▼
crypto_worker_thread[W]  (máy nhận)
     dataplane_process_wan
     decrypt_wan → wan_try_l2_pqc_udp
       AES decrypt + parse shim
       FULL: set_rx_meta, không opt_table
       FRAG: l2_reassemble g_tables[profile][W]
       mảnh 1/2: pending → free frame, chưa reorder
       đủ 2 mảnh: join → set_rx_meta
     take_rx_meta → dp_udp_reorder_submit   // hold 2ms / emit in-order
       emit → forward_wan_to_local → mid_to_local[li][S']
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

### 18.6 Máy nhận — decrypt ×2, join, rồi reorder

WAN RX **không** pick WAN. `dp_crypto_pick_wan_worker` đọc byte 15 → đúng core W.

`decrypt_wan`:

- `wan_try_l2_pqc_udp` nếu marker 4B: AES + `l2_udp_reasm` (FULL hoặc join).
- `pending==1`: free frame ingress, chưa reorder.
- Join/FULL (`dec==0`): `take_rx_meta` → `dp_udp_reorder_submit` (§16.9).

```
t0  WAN0 RX  N.frag0   → store first, pending
t1  WAN1 RX  N+1.frag0 → store
t2  WAN1 RX  N+1.frag1 → join N+1 → reorder hold (seq N+1)
t3  WAN0 RX  N.frag1   → join N → emit N, flush N+1
```

Trước §16.9 bước t2 TX LAN N+1 = OOO. 1 WAN bài D: N rồi N+1 gần in-order, hold gần 0.

`crypto_worker` pop `wan_to_mid` trước `local_to_mid`. Reorder per-worker, không lock.

### 18.7 Bypass và TCP trên cùng per-packet

Bypass: RX LAN **không** vào crypto 3–8. `dataplane_process_local` trên CPU 0 vẫn `fwd_wan_pick_for_local` + `push_to_wan` — **cùng** `g_pkt_wrr_seq`. 1 datagram = 1 frame, không ×2, **không** shim seq → không vào §16.9. OOO 2 WAN lúc đó chỉ lệch delay path.

TCP: MSS clamp 1500/30 → không split. Vẫn per-packet WRR mỗi segment. TCP stack tự SACK/reorder; iperf TCP không in “datagrams out-of-order”. Một thời kỳ sticky WAN từng đưa cả TCP lên một NIC.

### 18.8 Tóm tắt hành vi pick + split

1. Pick WAN một lần / datagram gốc, trước split. Hai mảnh cùng `wan_dp` + cùng `tx_slot`.
2. Đúng 1 WAN live (`allowed_count==1`): không `fetch_add`, không stripe.
3. Hàm pick live không đọc 5-tuple (tham số `(void)`).
4. `g_pkt_wrr_seq` tăng mỗi datagram khi `n>=2`, mọi flow/worker dùng chung.
5. Crypto worker + TX slot sticky theo flow — không phải gộp kênh.
6. UDP 0x104B shim `seq` + buffer §16.9 trên crypto worker — **không** sticky WAN.
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
| **D. Handshake VPN tunnel** | `pqc_handshake.c`: UDP `:7090` trên IP `pqc_exchange_tunnels` `[PQC-HS-L3]`. Không tunnel → không HS | HS chỉ trao key. Lifetime 30 ngày do **NE** đếm (§19.6). Encrypt dataplane vẫn L2 PQC 0x104A/0x104B |

Tóm tắt live encrypt LAN→WAN:

```
cp->action == BYPASS  → CPU 0 push_to_wan, không AES, không option ops
cp->action != BYPASS  → luôn CRYPTO_OPT_L2_PQC (kể cả DB ghi L3/L4)
                          AES-GCM qua crypto_pqc_encrypt_payload
                          key slots = sig_pqc_get_keys (handshake), không phải cp->key
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
| `keys[3][32]` | PREV/CURRENT/NEXT của ba generation quanh rekey; stage NEXT trước cutover |
| `initialized` | 1 sau init/rebuild |
| `crypto_mode` | Live ctx gán `CRYPTO_MODE_PQC`. Core không đọc CTR/GCM |
| `policy_id` | `cp->db_id` để lấy đúng binding PQC và lifetime per policy |
| `wire_id` | `cp->id` 1..255 ghi byte 14 trên 0x104A |
| `profile_id` | profile id |
| `aes_bits` | ARP 256; policy ctx thường 0 vì không `packet_crypto_init` |
| `pqc_from_handshake` | 1 = refresh từ HS; 0 = ARP static |

Hàm:

- `packet_crypto_init(ctx, master, aes_bits)` — **chỉ ARP** (`arp_bridge.c`). Set mode PQC, `fill_static_slots` HMAC-SHA256(master, epoch=0).
- `packet_crypto_get_key(ctx, slot)` — encrypt/decrypt đọc `KEY_SLOT_CURRENT`.
- `packet_crypto_update_keys` / `packet_crypto_refresh_pqc_keys` — copy đủ ba slot qua `sig_pqc_get_keys(policy_id, ...)`. Fail + CURRENT zero → `pqc_clear_ctx_keys`. Chỉ khi `crypto_mode==PQC && pqc_from_handshake`.

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
| `packet_crypto_ctx.pqc_key_in_use_ms` | CLOCK_MONOTONIC ms lúc **CURRENT được nạp RAM**; thuộc stable DB policy ctx, 0 = chưa có key / chưa start |
| `packet_crypto_ctx.pqc_rekey_sent` | đã gọi `sig_pqc_request_new_session` cho lần hết hạn này; request bị từ chối tạm thời thì re-arm |
| `packet_crypto_ctx.pqc_timed_key[32]` | bản sao CURRENT lúc clock start; CURRENT khác → reset clock |
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

**WAN decrypt** `decrypt_wan` → `wan_try_l2_pqc_udp` (0x104B + marker 4B) hoặc `decrypt_l2` (TCP/ICMP 0x104A). UDP FULL: `l2_udp_decrypt` / `l2_do_decrypt_udp` + `set_rx_meta`.

TLS option: `crypto_option_bind_worker_idx` / `g_worker_idx` — ghi byte 15. UDP: `g_udp_epoch`, TLS `g_udp_tx_seq` / `datagram_id` / `g_udp_rx_*`. `g_opt_frag_mtu` — `need_split`.

**Bypass live:** `dataplane_local_needs_mid` false → RX CPU 0 `dataplane_process_local` → `push_to_wan`. **Không** `crypto_opt_bypass_encrypt`. File `bypass.c` chỉ no-op ops cho registry.

`crypto_option_wire_overhead(L2_PQC)=30` (1+1+12+16). MSS clamp TCP dùng số này.

---

### 19.3 Handshake — key cho L2 PQC (khác encrypt L3)

Key dataplane **không** nằm `cp->key`. Nằm `policy_key_binding_t` (`pqc_handshake.h`).

| Field chính | Việc |
|-------------|------|
| `encrypt_key` / `decrypt_key` / `keys[3]` | master sau ML-KEM; diversify per policy. Slot PREV/CURRENT/NEXT |
| `key_ready` | 0 → ctx all-zero → L2 encrypt **fail** (đúng). Monthly rekey **không** hạ flag này |
| `rekey_requested` | NE hoặc keepalive fingerprint-mismatch xin HS **key mới** trong khi CURRENT vẫn dùng encrypt |
| `is_tunnel` | bắt buộc 1: HS UDP 7090 trên VPN tunnel; không tunnel → không bind |
| `wan_ifname`, `peer_ip` | tên interface tunnel + IP peer tunnel; `wan_ifname` để ioctl IP local khi DYNAMIC |
| `role_mode` | DYNAMIC so IP trên tunnel (IP nhỏ hơn = initiator) |
| `hs_cache[]` | idempotent HELLO trên tunnel |

`struct pqc_hs_msg`: magic `PQCH`, HELLO/RESP/KEEPALIVE/POKE/READY/COMMIT. Payload KEM và mọi control cutover đều được ML-DSA xác thực. **Chỉ** đi UDP `:7090` trên IP `pqc_exchange_tunnels`. Không đi Ethernet 0x88B5/0x88B6. Không tunnel → `sig_pqc_load_and_bind_policy` **không** bind worker, log ERROR.

Hàm bind/key: `sig_pqc_bind_policy`, `sig_pqc_get_keys`, `sig_pqc_load_and_bind_policy` (DB). `pqc_handshake_start_all_profiles` spawn worker per binding tunnel.

**Phân vai cố ý (đừng gộp):**

| Việc | Ai làm | Ai **không** làm |
|------|--------|------------------|
| ML-KEM HELLO/RESP, nạp master vào RAM | PQC worker | NE không gửi UDP 7090 |
| Keepalive 15s, POKE khi responder cần initiator HELLO | PQC | NE không đọc keepalive |
| Đếm 30 ngày, start clock, hết hạn | **NE** `crypto_runtime.c` | PQC không còn field/timer lifetime |
| Drop key vì miss keepalive / “active TX no RX” | **Không ai** | PQC chỉ log miss; key NE giữ |
| Xin HS key mới khi hết hạn | NE gọi `sig_pqc_request_new_session(policy_id)` | Không rotate cả profile |
| Xóa key cũ | Keepalive xác nhận peer fingerprint=CURRENT, chờ grace 90s rồi wipe PREV cả NE/PQC | Không xóa vì một lần encrypt local |

HS lần đầu vẫn nạp CURRENT sau HELLO/RESP. Khi **rekey**, responder và initiator stage master mới vào NEXT; initiator gửi READY sau khi NEXT đã vào dataplane, responder mới promote và gửi COMMIT, initiator nhận COMMIT mới promote. Trong cửa sổ này decrypt thử CURRENT → NEXT → PREV, nên responder chuyển trước vẫn không làm rớt traffic. Encrypt dataplane vẫn **L2 PQC**. Chi tiết đồng hồ / CLI: **§19.6**.

`trf_kem_*`, `trf_dsa_*`, `trf_derive_session_keys`, `trf_calculate_hmac` — KEM/DSA/HMAC của handshake, không phải AES-CTR dataplane.

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

File `*.orig` (`forwarder.c`, `crypto_route`, `flow_table`) không compile. `inc/crypto/pqc_*.h` phần lớn là stub `#include` bản `src/crypto/pqc/include/`. Marker encrypt: 0x104A/0x104B (`crypto_eth_l2_has_marker`).

`bypass.c`: năm export (`tcp/udp/icmp/ospf/other`) trỏ cùng `bypass_ops`. Dataplane bypass không gọi các hàm này — policy BYPASS đi RX thread.

`OPT_AES_BITS` trong `pqc_l2_option.c`: GCM dùng key 32B.

---

### 19.5 File crypto dataplane

Mã hóa traffic: `pqc_l2_option.c`. Dispatch: `crypto_option_router.c`, `crypto_option_registry.c`. Wire: `eth_parse.c`. Key slot: `packet_crypto.c`. AEAD: `crypto_pqc_layer.h` → `trf_*_gcm`. Handshake: `pqc_handshake.c` (UDP :7090 trên tunnel). Lifetime clock + `-tk`: `crypto_runtime.c`, `pqc_ipc.c`. Dataplane: `local_egress.c`, `wan_ingress.c`, `arp_bridge.c`. Bypass registry: `bypass.c` + `opt_no_frag_ops.c`.

Không có `src/crypto/options/l3*.c`, `l4*.c`, `ctr*.c`.

---

### 19.6 Lifetime session key PQC — NE đếm, PQC chỉ trao key

Mục này là nguồn sự thật cho **key usage clock**, **rekey 30 ngày**, và CLI **`network-encryptor -tk <policy_id>`**. Dataplane encrypt không đổi: vẫn L2 PQC 0x104A/0x104B, key từ handshake.

#### 19.6.1 Rule đồng hồ

Cùng interval **30 ngày** (`NE_PQC_KEY_LIFETIME_MS`) cho mọi policy PQC. Wall-clock hết hạn **khác nhau** vì mỗi policy start clock riêng.

Clock **start** khi **cả hai** đúng:

1. Session key đã nằm RAM NE (`policy_crypto_ctx[].keys[CURRENT]` nonzero, `pqc_from_handshake=1`).
2. CURRENT **khác** `pqc_timed_key` (key generation mới vừa nạp) — `ne_pqc_on_key_material` ghi `pqc_key_in_use_ms = monotonic_ms()` ngay lúc đó.

Clock **không** start / **không** reset vì:

- Keepalive TX/RX, miss 3 interval (45 s).
- Encrypt hay decrypt dataplane (không còn `l2_note_key_used`).
- CLI `-tk` (chỉ đọc).
- `-r` retry HS (đó là recovery HS fail, khác monthly rekey).

Đồng hồ nằm trực tiếp trong `packet_crypto_ctx` của **DB policy**. Hot reload chỉ reuse ctx nếu `db_id` trùng, rồi mới cập nhật `wire_id`; đổi/reuse wire không làm timer hoặc key chạy sang policy khác. Query CLI dùng `policy_id = cp->db_id` (cùng ID với `-r`).

#### 19.6.2 Cấu trúc NE (`crypto_runtime.c`)

Ba field trong từng `packet_crypto_ctx`:

```
ctx->pqc_key_in_use_ms    CLOCK_MONOTONIC ms lúc CURRENT được nạp RAM
ctx->pqc_rekey_sent       0/1 — đã xin HS cho lần hết hạn này chưa
ctx->pqc_timed_key[32]    bản sao CURRENT lúc start clock
```

`ne_pqc_on_key_material(ctx)` (gọi khi HS publish slot / rebuild / sync):

- CURRENT zero → xóa clock, `rekey_sent`, wipe `pqc_timed_key`.
- CURRENT **trùng** `pqc_timed_key` → no-op (cùng key đang đếm).
- CURRENT **khác** `pqc_timed_key` → **start clock = now** (key mới vừa nạp RAM). `rekey_sent=0`. Copy CURRENT → `pqc_timed_key`.

Như vậy HS key mới **không** thừa kế thời gian còn lại của key cũ. 30 ngày tính từ lúc **key mới nằm RAM**, kể cả khi chưa có traffic.

`fwd_crypto_pqc_key_lifetime_tick`: nếu CURRENT nonzero mà `pqc_key_in_use_ms==0` (key cũ trước khi đổi rule, hoặc load lệch path), start clock tại tick đó rồi skip expire.

#### 19.6.3 Dataplane encrypt không đụng clock

Encrypt/decrypt (`pqc_l2_option.c`) **không** start hay reset lifetime. Hàm start clock **không xóa PREV**. Xóa PREV thuộc protocol xác nhận peer tại §19.6.5–19.6.6.

#### 19.6.4 Tick hết hạn — từng policy, không cả profile

TX thread slot 0, khoảng mỗi 1024 vòng (`tx_maint_tick & 1023`), `dp_maint_tick` → `fwd_crypto_pqc_key_lifetime_tick`.

```
lock
với mỗi active policy PQC handshake-ready:
  started = ctx->pqc_key_in_use_ms
  nếu started==0 và CURRENT nonzero → start clock = now, skip expire
  nếu started==0 hoặc (now - started) < 30 ngày → skip
  nếu ctx->pqc_rekey_sent đã 1 → skip
  ctx->pqc_rekey_sent = 1
  queue policy_id (db_id)
unlock
với mỗi policy_id: sig_pqc_request_new_session(policy_id)
nếu binding đang transient/not-ready → re-arm cờ cho cùng key generation
```

Log: `[NE-PQC] Policy %d session key lifetime expired; requesting PQC handshake for a new key.`

`sig_pqc_request_new_session`:

- Không tìm thấy binding / `rekey_requested` đã 1 → no-op.
- `key_ready==false` (đang HS lần đầu / `-r`) → **bỏ qua**, log “already handshaking”; **không** hạ key đang dùng vì lúc này không có CURRENT usable.
- Còn lại: `rekey_requested=true`, **giữ** `key_ready=true`, CURRENT không đụng. Log: current key stays in RAM until the new key is loaded.

Khác `-r` / `sig_pqc_trigger_retry`: retry **hạ** `key_ready=false` → encrypt fail cho đến khi HS xong. Monthly rekey **không** đi path đó.

#### 19.6.5 Rekey trong khi giữ key cũ

Worker PQC, khi `key_ready && rekey_requested`:

- **Initiator:** gửi HELLO, nhận RESP, stage key vào NEXT, gửi READY lặp lại đến khi nhận COMMIT hợp lệ.
- **Responder:** `send_poke=true`, gửi POKE (signed request) để initiator HELLO; khi nhận HELLO xử như HS thường.

Rekey cutover:

```
HELLO / RESP
  cả hai: NEXT = master KEM mới; CURRENT cũ tiếp tục encrypt
initiator: READY có chữ ký
responder nhận READY:
  PREV = CURRENT cũ; CURRENT = NEXT; gửi COMMIT có chữ ký
initiator đã có NEXT nên decrypt được traffic CURRENT mới của responder
initiator nhận COMMIT:
  PREV = CURRENT cũ; CURRENT = NEXT
```

Decrypt thử `CURRENT → NEXT → PREV`. Vì vậy responder chuyển trước vẫn đọc được gói cũ từ initiator bằng PREV, còn initiator chưa nhận COMMIT vẫn đọc được gói mới bằng NEXT. Khi CURRENT đổi, lifetime start đủ 30 ngày mới ngay lúc key nạp RAM.

#### 19.6.6 Keepalive = liveness, không phải lifetime

UDP keepalive 15 s, timeout 3 interval = 45 s. Payload có state + fingerprint CURRENT; receive chấp nhận CURRENT/NEXT/PREV trong cửa sổ cutover.

- Miss timeout trên worker: **chỉ log** `[PQC-HS-L3] Policy %d missed 3 keepalive intervals; current session key stays in NE RAM.` Reset mốc monitor. **Không** `key_ready=false`, **không** `rekey_requested`, **không** đụng `pqc_key_in_use_ms`.
- Fingerprint mismatch / peer FAILED khi **đã có** `key_ready`: set `rekey_requested` (xin HS mới), CURRENT giữ. Cùng path “giữ key NE” như monthly expire.
- Fingerprint mismatch khi **chưa** `key_ready`: recovery HS như trước (`key_ready=false`) vì chưa có session để giữ.
- Khi fingerprint peer trùng **CURRENT local**, hai phía đã active cùng key. Nếu PREV tồn tại, đặt deadline grace 90 giây; hết grace gọi `fwd_crypto_discard_pqc_prev_key` rồi `sig_pqc_discard_prev_key`.

#### 19.6.7 CLI `-tk <policy_id>`

Daemon **phải chạy**. Client không đọc RAM trực tiếp.

```
network-encryptor -tk <policy_id>
```

`main` → `sig_pqc_handle_ipc_cli` (trước `-gi`/`-id`). Unix socket `/var/run/test_network-encryptor.sock`. Client gửi `TIMEKEY <policy_id>\n`. Daemon `fwd_crypto_format_pqc_key_times(buf, n, policy_id)`.

`policy_id` = `crypto_policy.db_id` (cùng `-r`). Thiếu argv / id ≤ 0 → usage / invalid, không query.

Logic in:

| Điều kiện | stdout |
|-----------|--------|
| Không tìm policy trên daemon | `POLICY-NOT-FOUND` |
| `action==BYPASS`, hoặc `crypto_mode != PQC` | `NO-ENCRYPT` |
| Policy PQC nhưng chưa có CURRENT / ctx chưa ready / không `pqc_from_handshake` | `no session key` |
| Có CURRENT, `ctx->pqc_key_in_use_ms==0` (hiếm; tick sẽ start) | `unused (timer not started)` |
| Đã quá 30 ngày (đang xin key mới) | `expired (requesting new key)` |
| Còn hạn | `29 days 12 hours 42 minutes` (singular/plural tiếng Anh) |

Không dump cả profile. Một lệnh = một policy.

`-r <policy_id>` khác: `RETRY %d` → `sig_pqc_trigger_retry_with_info` (HS lại, `key_ready=false`). Không in lifetime.

#### 19.6.8 Chuỗi sự kiện (một policy)

```
HS lần đầu HELLO/RESP
  → CURRENT nạp RAM, key_ready=1, clock = now     "-tk" ra remaining ~30 days
  → gói LAN encrypt (nếu có) không đụng clock
  → 30 ngày sau, TX tick
  → sig_pqc_request_new_session                    key cũ vẫn encrypt
  → initiator HELLO / responder POKE
  → RESP → cả hai stage NEXT=mới, CURRENT=cũ vẫn chạy
  → READY → responder promote, gửi COMMIT
  → initiator promote khi nhận COMMIT
  → clock start đủ 30 ngày ngay lúc CURRENT mới nạp RAM
  → keepalive hai phía xác nhận CURRENT mới
  → grace 90 giây → wipe PREV
```

Policy 75 handshake hôm nay, policy 80 handshake tuần sau → hết hạn lệch đúng khoảng đó. Cùng rule 30 ngày, khác wall-clock. Traffic idle không kéo dài lifetime.

#### 19.6.9 File / symbol cần nhớ

| Symbol | File |
|--------|------|
| `NE_PQC_KEY_LIFETIME_MS` | `crypto_runtime.c` |
| `ne_pqc_on_key_material` | `crypto_runtime.c`; caller HS publish / rebuild / sync |
| `fwd_crypto_pqc_key_lifetime_tick` | `crypto_runtime.c`; caller `dp_maint_tick` (`forwarder.c` TX slot 0) |
| `fwd_crypto_format_pqc_key_times` | `crypto_runtime.c` |
| `sig_pqc_request_new_session` | `pqc_handshake.c` |
| `sig_pqc_discard_prev_key` | `pqc_handshake.c` |
| `pqc_hs_stage_next_key` / READY / COMMIT | `pqc_handshake.c` |
| `rekey_requested` | `policy_key_binding_t` |
| `TIMEKEY` / `-tk` | `pqc_ipc.c` + usage `main.c` |

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

- Ra WAN MTU 1500: `need_split` (`pkt_len+47 > 1500`). UDP không cắt vẫn 0x104B+shim FULL.
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
