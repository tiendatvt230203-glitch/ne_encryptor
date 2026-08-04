# ne-mtu9k-test (AF_XDP jumbo / ice xdp.frags)

**Do not confuse with production** `../bpf/lan.c` (`SEC("xdp")` linear — ice rejects jumbo).

This tree builds **only**:

- `bpf/lan.c` / `bpf/wan.c` → `lib/mtu9k_lan.o` / `lib/mtu9k_wan.o`
- `SEC("xdp.frags")` + attach `XDP_FLAGS_DRV_MODE`
- `make verify-bpf` fails if `.o` lacks `xdp.frags`

```bash
cd ne-mtu9k-test
make clean && make
# must print: OK: ... have xdp.frags
llvm-objdump -h lib/mtu9k_lan.o | grep xdp
sudo ip link set enp1s0f0np0 mtu 9000
sudo ip link set enp2s0f0np0 mtu 9000
sudo ./mtu9k-test   # run from THIS directory so lib/mtu9k_*.o resolve
```

Edit `IF_LAN` / `IF_WAN` in `config.h` before run.
