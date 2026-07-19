#!/usr/bin/env python3
"""Offline evidence for L4 TCP bugs fixed in options/l4/*/tcp.c.

1) Old detector rejected tunnels when nonce[0] & 0x80 (random salt ~50%).
2) Growing frame without updating IP.totlen leaves frame_len > eth+totlen.
"""
from __future__ import annotations

import os
import random
import sys

L4_TUNNEL_MAGIC = 0xA5
NONCE_SIZE = 12
L4_TUNNEL_HDR_SIZE = NONCE_SIZE + 3  # nonce|core|policy|magic
AES_GCM_TAG = 16
ETH = 14
IP_HDR = 20
TCP_PORTS = 4


def old_is_tunnel(buf: bytes) -> bool:
    if buf[NONCE_SIZE + 2] != L4_TUNNEL_MAGIC:
        return False
    if (buf[0] & 0x80) != 0:
        return False
    return True


def new_is_tunnel(buf: bytes) -> bool:
    return buf[NONCE_SIZE + 2] == L4_TUNNEL_MAGIC


def make_tunnel_hdr(nonce0: int, policy: int = 1, core: int = 0) -> bytes:
    nonce = bytes([nonce0]) + os.urandom(NONCE_SIZE - 1)
    return nonce + bytes([core, policy, L4_TUNNEL_MAGIC])


def main() -> int:
    n = 10000
    old_reject = 0
    new_reject = 0
    for _ in range(n):
        hdr = make_tunnel_hdr(random.randrange(256))
        if not old_is_tunnel(hdr):
            old_reject += 1
        if not new_is_tunnel(hdr):
            new_reject += 1

    print(f"=== tunnel detect on {n} random nonces (all with magic 0xA5) ===")
    print(f"old (magic + nonce[0]&0x80): reject={old_reject} ({100.0 * old_reject / n:.1f}%)")
    print(f"new (magic only):            reject={new_reject} ({100.0 * new_reject / n:.1f}%)")
    if not (4500 <= old_reject <= 5500 and new_reject == 0):
        print("FAIL: expected ~50% old rejects and 0 new rejects", file=sys.stderr)
        return 1

    # Synthetic TCP: eth+ip+ports+payload, then insert overhead like encrypt
    plain_len = 1000
    pkt_len = ETH + IP_HDR + TCP_PORTS + plain_len
    ip_totlen = IP_HDR + TCP_PORTS + plain_len
    for name, overhead in (("CTR", L4_TUNNEL_HDR_SIZE), ("GCM", L4_TUNNEL_HDR_SIZE + AES_GCM_TAG)):
        frame_after = pkt_len + overhead
        stale_totlen_expected = ETH + ip_totlen  # if totlen not patched
        fixed_totlen = IP_HDR + TCP_PORTS + overhead + plain_len
        fixed_frame_match = ETH + fixed_totlen
        print(f"\n=== length math after L4 TCP {name} encrypt (plain_len={plain_len}) ===")
        print(f"frame_len after grow:          {frame_after}")
        print(f"eth+stale_IP.totlen (bug):      {stale_totlen_expected}  delta={frame_after - stale_totlen_expected}")
        print(f"eth+patched_IP.totlen (fix):  {fixed_frame_match}  delta={frame_after - fixed_frame_match}")
        if frame_after == stale_totlen_expected:
            print("FAIL: bug should leave a positive delta", file=sys.stderr)
            return 1
        if frame_after != fixed_frame_match:
            print("FAIL: fixed totlen must match frame", file=sys.stderr)
            return 1

    print("\nOK: evidence matches plan (old detector ~50% drop; totlen patch required).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
