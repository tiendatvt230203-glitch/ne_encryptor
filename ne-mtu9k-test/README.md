# MTU / jumbo feasibility test (L2 PQC pure)

AF_XDP forwarder: **1 LAN + 1 WAN**, **all HW RX queues mapped** (like production), **1 core**.
Goal: see if ~8K–9K frames pass with **pure PQC traffic crypto** (no wire metadata).

Does **not** force `ethtool -L … 1` (often `device resource busy`). Reads queue
count from `/sys/class/net/<if>/queues`, binds one XSK per queue, BPF redirects
with `ctx->rx_queue_index`.

## Hard limit (important)

Kernel UMEM `chunk_size` **cannot exceed `PAGE_SIZE` (4096)** — even with
`XDP_UMEM_UNALIGNED_CHUNK_FLAG` (that flag only lifts the power-of-two rule).

Jumbo is done via **multi-buffer**:
- `NE_FRAME=4096` UMEM chunks
- socket bind `XDP_USE_SG`
- RX/TX chain with `XDP_PKT_CONTD`
- assemble into `NE_PKT_MAX` (16 KiB) for encrypt/decrypt, then scatter TX

## Crypto

- Encrypt/decrypt IPv4 payload in place via production `trf_*`
- **Fake ethertype `0x104A`**; restore `0x0800` after decrypt
- **No** policy_id / core_id / nonce in the frame (fixed `HARD_NONCE`)
- Only +16 B GCM tag
- ARP: `XDP_PASS`

## Configure (`config.h`)

| Macro | Meaning |
|-------|---------|
| `IF_LAN` / `IF_WAN` | Interface names |
| `MODE_L2_PQC` | `1` crypto, `0` bypass (MACs never rewritten) |
| `NE_FRAME` | **4096** (PAGE_SIZE ceiling) |
| `NE_PKT_MAX` | 16384 contiguous packet buffer |
| `NE_N_FRAMES` | 65536 (~256 MiB UMEM) |

## Build / run

```bash
cd ne-mtu9k-test && make
sudo ip link set eno1 mtu 9000
sudo ip link set eno3 mtu 9000
sudo ./mtu9k-test
```

Watch `[stats] len_max=...` — values >4096 mean multi-buffer jumbo reached userspace.

Needs kernel with AF_XDP multi-buffer (`XDP_USE_SG`, typically 6.6+) and a driver that
can hand jumbo to XDP frags / copy-SG. If socket create fails on `XDP_USE_SG`, kernel
is too old for this path.
