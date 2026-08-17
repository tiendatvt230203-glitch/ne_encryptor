#!/bin/bash
# Collect diagnostics when network-encryptor shutdown hangs or times out.
# Run on the affected appliance (as root): bash tools/diag_shutdown_hang.sh

set -euo pipefail

OUT="${1:-/tmp/ne-shutdown-diag-$(date +%Y%m%d-%H%M%S).txt}"
UNIT="${NE_DIAG_UNIT:-network-encryptor.service}"

exec > >(tee "$OUT") 2>&1

echo "=== network-encryptor shutdown hang diagnostics ==="
echo "timestamp: $(date -Is)"
echo "host: $(hostname -f 2>/dev/null || hostname)"
echo "kernel: $(uname -r)"
echo "output: $OUT"
echo

section() { echo; echo "--- $* ---"; }

section "systemd unit"
systemctl show "$UNIT" -p TimeoutStopUSec -p Restart -p RestartUSec -p KillMode -p ActiveState -p SubState 2>/dev/null || true
systemctl status "$UNIT" --no-pager -l 2>/dev/null || true

section "network-encryptor processes"
ps aux | grep -E '[n]etwork-encrypt|[v]ault' || true
for pid in $(pgrep -f network-encryptor 2>/dev/null || true); do
    echo "pid $pid state=$(awk '/State:/ {print $2}' /proc/$pid/status 2>/dev/null) wchan=$(cat /proc/$pid/wchan 2>/dev/null)"
    cat /proc/$pid/stack 2>/dev/null || true
done

section "recent journal (this boot)"
journalctl -u "$UNIT" -b --no-pager -n 200 2>/dev/null || true

section "XDP on interfaces"
ip -d link show 2>/dev/null | grep -E '^[0-9]+:|xdp' || true

section "NIC drivers (ethtool -i)"
for iface in $(ls /sys/class/net 2>/dev/null | grep -vE '^(lo|docker|veth|br-|virbr)'); do
    echo "[$iface]"
    ethtool -i "$iface" 2>/dev/null || true
done

section "Vault CLI latency (5s timeout each)"
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
if command -v vault >/dev/null 2>&1; then
    timeout 5 vault status 2>&1 || echo "vault status: failed or timed out"
else
    echo "vault CLI not found in PATH"
fi

section "Vault HTTP seal-status"
if command -v curl >/dev/null 2>&1; then
    timeout 5 curl -sS "${VAULT_ADDR}/v1/sys/seal-status" 2>&1 || echo "curl seal-status: failed or timed out"
else
    echo "curl not found"
fi

echo
echo "=== done; save this file: $OUT ==="
