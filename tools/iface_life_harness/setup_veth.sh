#!/bin/sh
set -e

LAN0=ne_lan0
LAN0_PEER=ne_lan0p
LAN1=ne_lan1
LAN1_PEER=ne_lan1p
WAN0=ne_wan0
WAN0_PEER=ne_wan0p
WAN1=ne_wan1
WAN1_PEER=ne_wan1p

ensure_pair() {
	name="$1"
	peer="$2"
	if ip link show "$name" >/dev/null 2>&1; then
		ip link set dev "$name" up || true
		ip link set dev "$peer" up 2>/dev/null || true
		return 0
	fi
	ip link add "$name" type veth peer name "$peer"
	ip link set dev "$name" up
	ip link set dev "$peer" up
}

destroy_dev() {
	name="$1"
	if ip link show "$name" >/dev/null 2>&1; then
		ip link set dev "$name" xdp off 2>/dev/null || true
		ip link set dev "$name" xdpgeneric off 2>/dev/null || true
		ip link delete "$name" 2>/dev/null || true
	fi
}

cmd="${1:-up}"

case "$cmd" in
up)
	ensure_pair "$LAN0" "$LAN0_PEER"
	ensure_pair "$LAN1" "$LAN1_PEER"
	ensure_pair "$WAN0" "$WAN0_PEER"
	ensure_pair "$WAN1" "$WAN1_PEER"
	echo "[veth] up: $LAN0 $LAN1 $WAN0 $WAN1"
	;;
down)
	destroy_dev "$LAN0"
	destroy_dev "$LAN1"
	destroy_dev "$WAN0"
	destroy_dev "$WAN1"
	destroy_dev "$LAN0_PEER"
	destroy_dev "$LAN1_PEER"
	destroy_dev "$WAN0_PEER"
	destroy_dev "$WAN1_PEER"
	echo "[veth] down"
	;;
*)
	echo "usage: $0 {up|down}" >&2
	exit 2
	;;
esac
