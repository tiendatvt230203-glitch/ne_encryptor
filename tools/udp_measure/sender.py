#!/usr/bin/env python3
"""UDP measure sender: multi-connect, per-connect bandwidth, sequenced payloads."""

from __future__ import annotations

import argparse
import multiprocessing as mp
import signal
import sys
import time
from typing import List, Optional, Tuple

from common import (
    FLAG_DATA,
    FLAG_END,
    HEADER_SIZE,
    build_packet,
    format_bps,
    format_pps,
    parse_bandwidth,
)


def _worker(
    flow_id: int,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    packet_size: int,
    bits_per_sec: float,
    duration: Optional[float],
    count: Optional[int],
    end_repeats: int,
    progress_queue: mp.Queue,
    stop_event: mp.Event,
) -> None:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Larger send buffer helps sustain rate
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        sock.bind((src_ip, src_port))
        dst = (dst_ip, dst_port)

        bytes_per_sec = bits_per_sec / 8.0
        # Pre-allocate mutable payload; only rewrite header fields each send
        payload = bytearray(build_packet(flow_id, 0, packet_size, flags=FLAG_DATA))

        seq = 0
        sent = 0
        sent_bytes = 0
        t0 = time.perf_counter()
        last_report = t0
        report_sent = 0
        report_bytes = 0

        # Token bucket
        tokens = bytes_per_sec  # start with 1s worth
        last_refill = t0

        def refill(now: float) -> None:
            nonlocal tokens, last_refill
            elapsed = now - last_refill
            if elapsed > 0:
                tokens = min(bytes_per_sec * 2.0, tokens + elapsed * bytes_per_sec)
                last_refill = now

        while not stop_event.is_set():
            now = time.perf_counter()
            if duration is not None and (now - t0) >= duration:
                break
            if count is not None and sent >= count:
                break

            refill(now)
            if tokens < packet_size:
                # Sleep just enough to accumulate one packet
                need = packet_size - tokens
                sleep_s = need / bytes_per_sec if bytes_per_sec > 0 else 0.001
                if sleep_s > 0:
                    time.sleep(min(sleep_s, 0.01))
                continue

            # Update seq + timestamp in-place (offsets after magic/ver/flags/flow)
            # HEADER: !IBBHQQ -> seq at offset 8, ts at offset 16
            ts = time.time_ns()
            payload[8:16] = seq.to_bytes(8, "big")
            payload[16:24] = ts.to_bytes(8, "big")
            # Ensure flags = DATA
            payload[5] = FLAG_DATA

            try:
                sock.sendto(payload, dst)
            except OSError:
                if stop_event.is_set():
                    break
                time.sleep(0.001)
                continue

            tokens -= packet_size
            seq += 1
            sent += 1
            sent_bytes += packet_size
            report_sent += 1
            report_bytes += packet_size

            now = time.perf_counter()
            if now - last_report >= 1.0:
                dt = now - last_report
                progress_queue.put(
                    (
                        flow_id,
                        report_sent / dt,
                        (report_bytes * 8.0) / dt,
                        sent,
                        sent_bytes,
                        False,
                    )
                )
                last_report = now
                report_sent = 0
                report_bytes = 0

        # END markers so receiver can finalize
        end_payload = build_packet(
            flow_id, seq, max(packet_size, HEADER_SIZE), flags=FLAG_END
        )
        for _ in range(max(1, end_repeats)):
            try:
                sock.sendto(end_payload, dst)
            except OSError:
                break
            time.sleep(0.002)

        progress_queue.put((flow_id, 0.0, 0.0, sent, sent_bytes, True))
    finally:
        sock.close()


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="UDP measure sender (per-connect bandwidth, sequenced packets)"
    )
    p.add_argument("--src-ip", required=True, help="Source IP to bind")
    p.add_argument("--dst-ip", required=True, help="Destination IP")
    p.add_argument("--dst-port", type=int, required=True, help="Destination UDP port")
    p.add_argument(
        "-c",
        "--connects",
        type=int,
        default=1,
        help="Number of parallel UDP flows (default: 1)",
    )
    p.add_argument(
        "-b",
        "--bandwidth",
        default="10M",
        help="Bandwidth PER connect, bits/s (e.g. 100M, 1G). Total = connects * bandwidth",
    )
    p.add_argument(
        "-l",
        "--packet-size",
        type=int,
        default=1200,
        help=f"UDP payload size in bytes (>= {HEADER_SIZE}, default: 1200)",
    )
    p.add_argument(
        "-t",
        "--duration",
        type=float,
        default=60.0,
        help="Thoi gian do (giay), vd 60: chay 60s roi dung va gui END (default: 60)",
    )
    p.add_argument(
        "-n",
        "--count",
        type=int,
        default=None,
        help="Packets per connect (optional). Stops when count OR duration is hit.",
    )
    p.add_argument(
        "--src-port-base",
        type=int,
        default=10000,
        help="Base source port; flow i uses src-port-base + i",
    )
    p.add_argument(
        "--end-repeats",
        type=int,
        default=5,
        help="How many END marker packets to send per flow (default: 5)",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.connects < 1:
        print("error: --connects must be >= 1", file=sys.stderr)
        return 2
    if args.packet_size < HEADER_SIZE:
        print(f"error: --packet-size must be >= {HEADER_SIZE}", file=sys.stderr)
        return 2
    if args.dst_port < 1 or args.dst_port > 65535:
        print("error: invalid --dst-port", file=sys.stderr)
        return 2

    try:
        bps = parse_bandwidth(args.bandwidth)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if bps <= 0:
        print("error: bandwidth must be > 0", file=sys.stderr)
        return 2

    duration = args.duration
    count = args.count
    if count is None and (duration is None or duration <= 0):
        duration = 60.0

    total_bps = bps * args.connects
    print(
        f"sender: {args.connects} connect(s) x {format_bps(bps)} "
        f"= {format_bps(total_bps)} aggregate"
    )
    print(
        f"  src={args.src_ip}:{args.src_port_base}+ "
        f"dst={args.dst_ip}:{args.dst_port} "
        f"pkt={args.packet_size}B duration={duration}s count/flow={count}"
    )

    ctx = mp.get_context("fork") if sys.platform.startswith("linux") else mp.get_context("spawn")
    progress_queue: mp.Queue = ctx.Queue()
    stop_event: mp.Event = ctx.Event()

    def _on_signal(signum, frame):  # noqa: ARG001
        stop_event.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    procs: List[mp.Process] = []
    for i in range(args.connects):
        proc = ctx.Process(
            target=_worker,
            args=(
                i,
                args.src_ip,
                args.src_port_base + i,
                args.dst_ip,
                args.dst_port,
                args.packet_size,
                bps,
                duration,
                count,
                args.end_repeats,
                progress_queue,
                stop_event,
            ),
            daemon=True,
        )
        procs.append(proc)
        proc.start()

    done = 0
    # latest totals per flow for aggregate report
    totals: dict = {}
    live_pps: dict = {}
    live_bps: dict = {}

    try:
        while done < args.connects:
            try:
                item: Tuple = progress_queue.get(timeout=0.5)
            except Exception:
                # Check if all procs died unexpectedly
                alive = sum(1 for p in procs if p.is_alive())
                if alive == 0 and done < args.connects:
                    # Drain remaining
                    while True:
                        try:
                            item = progress_queue.get_nowait()
                        except Exception:
                            break
                        flow_id, pps, fbps, sent, sent_bytes, finished = item
                        totals[flow_id] = (sent, sent_bytes)
                        if finished:
                            done += 1
                    break
                continue

            flow_id, pps, fbps, sent, sent_bytes, finished = item
            totals[flow_id] = (sent, sent_bytes)
            if finished:
                done += 1
                print(
                    f"  flow {flow_id}: done sent={sent} bytes={sent_bytes}"
                )
            else:
                live_pps[flow_id] = pps
                live_bps[flow_id] = fbps
                agg_pps = sum(live_pps.values())
                agg_bps = sum(live_bps.values())
                print(
                    f"  [live] flow {flow_id}: {format_pps(pps)} {format_bps(fbps)} | "
                    f"agg {format_pps(agg_pps)} {format_bps(agg_bps)}"
                )
    except KeyboardInterrupt:
        stop_event.set()

    stop_event.set()
    for proc in procs:
        proc.join(timeout=5.0)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=2.0)

    total_pkts = sum(v[0] for v in totals.values())
    total_bytes = sum(v[1] for v in totals.values())
    print(
        f"sender finished: flows={len(totals)} packets={total_pkts} "
        f"bytes={total_bytes} (~{format_bps(total_bytes * 8)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
