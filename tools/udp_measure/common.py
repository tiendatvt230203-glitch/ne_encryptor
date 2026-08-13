"""Shared packet format and helpers for UDP measure toolkit."""

from __future__ import annotations

import re
import struct
import time
from dataclasses import dataclass
from typing import Optional

# NEUD magic: 0x4E455544
MAGIC = 0x4E455544
VERSION = 1

# flags
FLAG_DATA = 0x00
FLAG_END = 0x01

# ! = network (big-endian)
# I = magic (u32)
# B = version (u8)
# B = flags (u8)
# H = flow_id (u16)
# Q = seq (u64)
# Q = send_ts_ns (u64)
HEADER_FMT = "!IBBHQQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 24 bytes

_BANDWIDTH_RE = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*([KMG]?)(?:bit|bits|b|/s|bps)?\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PacketHeader:
    magic: int
    version: int
    flags: int
    flow_id: int
    seq: int
    send_ts_ns: int

    @property
    def is_end(self) -> bool:
        return bool(self.flags & FLAG_END)


def pack_header(
    flow_id: int,
    seq: int,
    send_ts_ns: Optional[int] = None,
    flags: int = FLAG_DATA,
) -> bytes:
    if send_ts_ns is None:
        send_ts_ns = time.time_ns()
    return struct.pack(
        HEADER_FMT,
        MAGIC,
        VERSION,
        flags & 0xFF,
        flow_id & 0xFFFF,
        seq & 0xFFFFFFFFFFFFFFFF,
        send_ts_ns & 0xFFFFFFFFFFFFFFFF,
    )


def unpack_header(data: bytes) -> Optional[PacketHeader]:
    if len(data) < HEADER_SIZE:
        return None
    magic, version, flags, flow_id, seq, send_ts_ns = struct.unpack(
        HEADER_FMT, data[:HEADER_SIZE]
    )
    if magic != MAGIC or version != VERSION:
        return None
    return PacketHeader(
        magic=magic,
        version=version,
        flags=flags,
        flow_id=flow_id,
        seq=seq,
        send_ts_ns=send_ts_ns,
    )


def build_packet(
    flow_id: int,
    seq: int,
    packet_size: int,
    flags: int = FLAG_DATA,
    send_ts_ns: Optional[int] = None,
    pad_byte: int = 0x00,
) -> bytes:
    """Build a full UDP payload of exactly packet_size bytes."""
    if packet_size < HEADER_SIZE:
        raise ValueError(f"packet_size must be >= {HEADER_SIZE}")
    hdr = pack_header(flow_id, seq, send_ts_ns=send_ts_ns, flags=flags)
    pad_len = packet_size - HEADER_SIZE
    if pad_len == 0:
        return hdr
    return hdr + bytes([pad_byte & 0xFF]) * pad_len


def parse_bandwidth(s: str) -> float:
    """
    Parse an iPerf-like bandwidth string into bits per second.

    Examples: 100M, 1G, 500K, 1000000, 10Mbps
    """
    m = _BANDWIDTH_RE.match(s.strip())
    if not m:
        raise ValueError(
            f"invalid bandwidth '{s}' (examples: 100M, 1G, 500K, 1000000)"
        )
    value = float(m.group(1))
    unit = (m.group(2) or "").upper()
    mult = {"": 1.0, "K": 1e3, "M": 1e6, "G": 1e9}[unit]
    return value * mult


def format_bps(bps: float) -> str:
    if bps >= 1e9:
        return f"{bps / 1e9:.3f} Gbps"
    if bps >= 1e6:
        return f"{bps / 1e6:.3f} Mbps"
    if bps >= 1e3:
        return f"{bps / 1e3:.3f} Kbps"
    return f"{bps:.0f} bps"


def format_pps(pps: float) -> str:
    if pps >= 1e6:
        return f"{pps / 1e6:.3f} Mpps"
    if pps >= 1e3:
        return f"{pps / 1e3:.3f} Kpps"
    return f"{pps:.1f} pps"
