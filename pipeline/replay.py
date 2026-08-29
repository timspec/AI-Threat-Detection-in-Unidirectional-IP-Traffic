"""
pipeline/replay.py — CLI entry-point for PCAP replay.

Usage:
    python -m pipeline.replay --pcap samples/sample.pcap --rate 10

Replays the given PCAP file at the specified rate (in Mbps) and prints
a summary of total packets and elapsed wall-clock time.
No detection is wired yet — this just proves the replay pipeline works.

⚠️  This module reads a local file and prints to stdout.
    It does NOT open any network socket or send any data.
"""

from __future__ import annotations

import argparse
import sys
import time

from pipeline.ingest.pcap_replay import replay_pcap, ReplayStats


def _parse_rate(rate_str: str) -> float:
    """Parse a rate string like '10', '10mbps', '10Mbps' → float Mbps."""
    cleaned = rate_str.strip().lower()
    # Strip common suffixes
    for suffix in ("mbps", "mb/s", "mbit/s", "mbit"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)].strip()
            break
    try:
        return float(cleaned)
    except ValueError:
        print(f"ERROR: Cannot parse rate '{rate_str}'. Use a number like '10' or '10mbps'.",
              file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pipeline.replay",
        description="Replay a PCAP file at a controlled rate.",
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to .pcap or .pcapng file",
    )
    parser.add_argument(
        "--rate",
        default="0",
        help="Replay rate in Mbps (e.g. '10' or '10mbps'). 0 = unlimited.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Stop after N packets (0 = replay all).",
    )

    args = parser.parse_args()
    rate_mbps = _parse_rate(args.rate)

    print(f"\n{'='*60}")
    print(f" PCAP Replay")
    print(f"{'='*60}")
    print(f" File : {args.pcap}")
    print(f" Rate : {rate_mbps:.2f} Mbps {'(unlimited)' if rate_mbps == 0 else ''}")
    if args.max_packets:
        print(f" Max  : {args.max_packets} packets")
    print(f"{'='*60}\n")

    packet_count = 0

    def _on_packet(pkt) -> None:
        nonlocal packet_count
        packet_count += 1
        if packet_count % 1000 == 0:
            print(f"  ... {packet_count} packets replayed", end="\r")

    stats: ReplayStats = replay_pcap(
        path=args.pcap,
        rate_mbps=rate_mbps,
        on_packet=_on_packet,
        max_packets=args.max_packets,
    )

    print(f"\n{'='*60}")
    print(f" Replay Complete")
    print(f"{'='*60}")
    print(f" Total packets : {stats.total_packets:,}")
    print(f" Total bytes   : {stats.total_bytes:,}")
    print(f" Elapsed time  : {stats.elapsed_seconds:.3f} s")
    print(f" Effective rate : {stats.effective_mbps:.2f} Mbps")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
