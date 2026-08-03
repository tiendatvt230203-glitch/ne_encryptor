# MTU / jumbo feasibility test (L2 PQC pure)

AF_XDP forwarder: **1 LAN + 1 WAN**, **1 queue**, **1 core**.
Goal: see if ~8K–9K frames pass the kernel/NIC path with **pure PQC traffic crypto** (no wire metadata).

## Crypto

- Encrypt/decrypt IPv4 payload in place via production `trf_*`
- **Fake ethertype `0x104A`** (required L2 encrypt marker); restore `0x0800` after decrypt
- **No** policy_id / core_id / nonce in the frame (fixed `HARD_NONCE`)
- Only +16 B GCM tag
- ARP: `XDP_PASS`; no RSS / UDP frag yet

## Configure (`config.h`)

| Macro | Meaning |
|-------|---------|
| `IF_LAN` / `IF_WAN` | Interface names |
| `REMOTE_MAC` | Far-end MAC |
| `MODE_L2_PQC` | `1` crypto, `0` bypass |
| `HARD_KEY` / `HARD_NONCE` | Shared secrets for the test |
| `NE_FRAME` | 16384 |
| `NE_N_FRAMES` | 1572864 (~24 GiB) |

## Build / run

```bash
cd ne-mtu9k-test && make
sudo ip link set eth0 mtu 9000   # or leave default; send ~8K probes
sudo ip link set eth1 mtu 9000
sudo ./mtu9k-test
```

Watch `[stats] len_max=...` — if jumbo reaches AF_XDP, kernel did not drop them earlier.
