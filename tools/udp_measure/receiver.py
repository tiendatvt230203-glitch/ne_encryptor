#!/usr/bin/env python3
"""UDP measure receiver: per-connect loss/reorder, then test aggregate on stop."""

from __future__ import annotations

import argparse
import json
import select
import signal
import socket
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from common import format_bps, format_pps, unpack_header

# Cap how many seq numbers to print/store in JSON detail lists
SEQ_DETAIL_CAP = 64


def _cap_sorted(seqs: Set[int], cap: int = SEQ_DETAIL_CAP) -> List[int]:
    if not seqs:
        return []
    ordered = sorted(seqs)
    if len(ordered) <= cap:
        return ordered
    return ordered[: cap - 1] + [ordered[-1]]


@dataclass
class ConnectStats:
    """One UDP connect (flow_id). Seq space is independent: 0,1,2,..."""

    connect_id: int
    received: int = 0  # data packets (incl. duplicates)
    unique_received: int = 0
    bytes_received: int = 0
    reorder: int = 0
    duplicates: int = 0
    max_seq: int = -1
    next_expected: int = 0
    received_seqs: Set[int] = field(default_factory=set)
    reordered_seqs: Set[int] = field(default_factory=set)
    lost_seqs: Set[int] = field(default_factory=set)
    loss: int = 0
    ended: bool = False
    end_seq: Optional[int] = None  # packets sent on this connect (= next seq after last data)

    def expected(self) -> int:
        if self.end_seq is not None:
            return self.end_seq
        if self.max_seq < 0:
            return 0
        return self.max_seq + 1

    def loss_pct(self) -> float:
        exp = self.expected()
        if exp <= 0:
            return 0.0
        return 100.0 * self.loss / exp

    def note_reorder(self, seq: int) -> None:
        self.reorder += 1
        self.reordered_seqs.add(seq)


class Receiver:
    def __init__(self) -> None:
        self.connects: Dict[int, ConnectStats] = {}
        self.total_invalid = 0
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def get_connect(self, connect_id: int) -> ConnectStats:
        cs = self.connects.get(connect_id)
        if cs is None:
            cs = ConnectStats(connect_id=connect_id)
            self.connects[connect_id] = cs
        return cs

    def handle_packet(self, data: bytes) -> None:
        hdr = unpack_header(data)
        if hdr is None:
            self.total_invalid += 1
            return

        cs = self.get_connect(hdr.flow_id)

        if hdr.is_end:
            cs.ended = True
            if cs.end_seq is None or hdr.seq > cs.end_seq:
                cs.end_seq = hdr.seq
            return

        cs.received += 1
        cs.bytes_received += len(data)
        seq = hdr.seq
        if seq > cs.max_seq:
            cs.max_seq = seq

        if seq in cs.received_seqs:
            cs.duplicates += 1
            return

        cs.received_seqs.add(seq)
        cs.unique_received += 1

        # Reorder: anything not exactly next_expected
        if seq == cs.next_expected:
            cs.next_expected += 1
            while cs.next_expected in cs.received_seqs:
                cs.next_expected += 1
            return

        if seq < cs.next_expected:
            # Late fill of an earlier hole, or duplicate past window
            cs.note_reorder(seq)
            return

        # seq > next_expected: arrived early / out of order
        cs.note_reorder(seq)

    def finalize_connect(self, cs: ConnectStats) -> None:
        """After dump stops: loss = expected seqs that never arrived."""
        exp = cs.expected()
        lost: Set[int] = set()
        for seq in range(exp):
            if seq not in cs.received_seqs:
                lost.add(seq)
        cs.lost_seqs = lost
        cs.loss = len(lost)

    def finalize_all(self) -> None:
        for cs in self.connects.values():
            self.finalize_connect(cs)

    def all_ended(self) -> bool:
        if not self.connects:
            return False
        return all(cs.ended for cs in self.connects.values())

    def ended_count(self) -> int:
        return sum(1 for cs in self.connects.values() if cs.ended)

    def report_dict(self) -> dict:
        connects_out = []
        agg = {
            "connects": 0,
            "expected": 0,
            "received": 0,
            "unique_received": 0,
            "bytes_received": 0,
            "loss": 0,
            "reorder": 0,
            "duplicates": 0,
        }
        for cid in sorted(self.connects):
            cs = self.connects[cid]
            entry = {
                "connect": cs.connect_id,
                "expected": cs.expected(),
                "received": cs.received,
                "unique_received": cs.unique_received,
                "bytes_received": cs.bytes_received,
                "loss": cs.loss,
                "reorder": cs.reorder,
                "duplicates": cs.duplicates,
                "loss_pct": round(cs.loss_pct(), 4),
                "ended": cs.ended,
                "lost_seq": _cap_sorted(cs.lost_seqs),
                "lost_seq_total": cs.loss,
                "reordered_seq": _cap_sorted(cs.reordered_seqs),
                "reordered_seq_total": len(cs.reordered_seqs),
            }
            connects_out.append(entry)
            agg["connects"] += 1
            agg["expected"] += cs.expected()
            agg["received"] += cs.received
            agg["unique_received"] += cs.unique_received
            agg["bytes_received"] += cs.bytes_received
            agg["loss"] += cs.loss
            agg["reorder"] += cs.reorder
            agg["duplicates"] += cs.duplicates
        exp = agg["expected"]
        agg["loss_pct"] = round(100.0 * agg["loss"] / exp, 4) if exp else 0.0
        return {
            "connects": connects_out,
            "aggregate": agg,
            "invalid_packets": self.total_invalid,
        }

    def print_report(self) -> None:
        data = self.report_dict()
        print("")
        print("========== KET QUA TUNG CONNECT ==========")
        for f in data["connects"]:
            print(
                f"connect {f['connect']}: "
                f"gui_ky_vong={f['expected']} nhan={f['received']} "
                f"loss={f['loss']} goi  reorder={f['reorder']} goi  "
                f"dup={f['duplicates']}  loss%={f['loss_pct']}"
            )
            if f["loss"]:
                shown = f["lost_seq"]
                extra = (
                    f" (hien {len(shown)}/{f['lost_seq_total']})"
                    if f["lost_seq_total"] > len(shown)
                    else ""
                )
                print(f"  lost_seq{extra}: {shown}")
            if f["reorder"]:
                shown = f["reordered_seq"]
                extra = (
                    f" (hien {len(shown)}/{f['reordered_seq_total']})"
                    if f["reordered_seq_total"] > len(shown)
                    else ""
                )
                print(f"  reordered_seq{extra}: {shown}")
        a = data["aggregate"]
        print("========== TONG HOP LAN TEST ==========")
        print(
            f"so_connect={a['connects']}  "
            f"gui_ky_vong={a['expected']}  nhan={a['received']}  "
            f"loss={a['loss']} goi  reorder={a['reorder']} goi  "
            f"dup={a['duplicates']}  loss%={a['loss_pct']}  "
            f"invalid={data['invalid_packets']}"
        )
        print("========================================")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "UDP measure receiver. Chay den khi sender gui END (het duration) "
            "hoac Ctrl+C, roi in loss/reorder tung connect va tong hop."
        )
    )
    p.add_argument("--bind-ip", default="0.0.0.0", help="IP bind (default: 0.0.0.0)")
    p.add_argument("--port", type=int, required=True, help="UDP listen port")
    p.add_argument(
        "--expect-connects",
        type=int,
        default=0,
        help="Neu >0: dung khi du so connect nay da gui END",
    )
    p.add_argument(
        "--report-interval",
        type=float,
        default=1.0,
        help="In tien do moi N giay (default: 1)",
    )
    p.add_argument("--json-out", default=None, help="Ghi bao cao JSON")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.port < 1 or args.port > 65535:
        print("error: invalid --port", file=sys.stderr)
        return 2

    recv = Receiver()

    def _on_signal(signum, frame):  # noqa: ARG001
        print("\n[receiver] dung — dang tinh loss/reorder...")
        recv.stop()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        except OSError:
            pass
        sock.bind((args.bind_ip, args.port))
        sock.setblocking(False)
    except OSError as e:
        print(f"error: bind failed: {e}", file=sys.stderr)
        return 1

    print(
        f"receiver {args.bind_ip}:{args.port} — "
        f"cho sender het duration (END) hoac Ctrl+C de chot ket qua"
    )

    last_report = time.perf_counter()
    last_pkt = time.perf_counter()
    saw_traffic = False
    interval_pkts = 0
    interval_bytes = 0

    try:
        while not recv._stop:
            rlist, _, _ = select.select([sock], [], [], 0.1)
            now = time.perf_counter()

            if rlist:
                for _ in range(512):
                    try:
                        data, _addr = sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    recv.handle_packet(data)
                    interval_pkts += 1
                    interval_bytes += len(data)
                    last_pkt = now
                    saw_traffic = True

            if now - last_report >= args.report_interval:
                dt = now - last_report
                pps = interval_pkts / dt if dt > 0 else 0.0
                bps = (interval_bytes * 8.0) / dt if dt > 0 else 0.0
                reo = sum(cs.reorder for cs in recv.connects.values())
                print(
                    f"  [live] connects={len(recv.connects)} "
                    f"ended={recv.ended_count()} "
                    f"{format_pps(pps)} {format_bps(bps)} reorder={reo}"
                )
                interval_pkts = 0
                interval_bytes = 0
                last_report = now

            # Sender het duration → gui END → chot sau grace ngan (goi con treo)
            if saw_traffic and recv.all_ended() and (now - last_pkt) >= 0.3:
                break
            if (
                args.expect_connects > 0
                and recv.ended_count() >= args.expect_connects
                and (now - last_pkt) >= 0.3
            ):
                break
    finally:
        sock.close()

    recv.finalize_all()
    recv.print_report()

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(recv.report_dict(), f, indent=2)
            f.write("\n")
        print(f"wrote {args.json_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
