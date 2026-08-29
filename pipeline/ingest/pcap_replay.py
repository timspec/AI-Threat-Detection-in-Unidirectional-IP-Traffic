"""
pipeline/ingest/pcap_replay.py — Replay packets from a PCAP file on disk.

╔════════════════════════════════════════════════════════════════════════╗
║                    ⚠️  ONE-WAY GUARANTEE ⚠️                            ║
║                                                                        ║
║  This module is STRICTLY LOCAL / READ-ONLY.                            ║
║  It reads a .pcap/.pcapng file from the local filesystem and calls     ║
║  a Python callback for each packet. It does NOT open any network       ║
║  socket, does NOT send packets onto a wire, and does NOT make any      ║
║  outbound connection.                                                  ║
║                                                                        ║
║  FORBIDDEN calls (must NEVER appear in this file):                     ║
║    • sendp(), send(), sr(), sr1(), srp(), srp1()                       ║
║    • socket.send(), socket.sendto(), socket.connect()                  ║
║    • requests.get/post or any outbound HTTP                            ║
║                                                                        ║
║  CODE REVIEW RULE: reject any PR that adds a send-capable call here.   ║
╚════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from scapy.utils import PcapReader  # memory-efficient, streams one pkt at a time

logger = logging.getLogger(__name__)


@dataclass
class ReplayStats:
    """Statistics returned after a replay run completes."""
    total_packets: int = 0
    total_bytes: int = 0
    elapsed_seconds: float = 0.0
    effective_mbps: float = 0.0


def replay_pcap(
    path: str,
    rate_mbps: float,
    on_packet: Callable,
    max_packets: int = 0,
) -> ReplayStats:
    """Replay packets from a PCAP file, calling *on_packet* for each one.

    Packets are read **one at a time** via ``PcapReader`` (streaming),
    so even multi-GB captures won't exhaust memory.

    Rate-limiting
    -------------
    Packets are paced so the average throughput approximates *rate_mbps*.
    After delivering each packet we check:

        expected_time = total_bits_sent / (rate_mbps × 1 000 000)

    If wall-clock time is behind ``expected_time``, we ``time.sleep()``
    the difference.  If *rate_mbps* ≤ 0, packets are delivered as fast
    as Python can iterate (no throttling).

    Parameters
    ----------
    path : str
        Filesystem path to a ``.pcap`` or ``.pcapng`` file.
    rate_mbps : float
        Target replay rate in megabits per second.  ``0`` = unlimited.
    on_packet : Callable
        Callback invoked with each ``scapy.packet.Packet``.
    max_packets : int
        Stop after this many packets.  ``0`` = replay entire file.

    Returns
    -------
    ReplayStats
        Packet count, byte count, wall-clock time, and effective Mbps.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    logger.info(
        "Replaying %s at %.2f Mbps (max_packets=%s)",
        filepath.name,
        rate_mbps,
        max_packets or "all",
    )

    stats = ReplayStats()
    throttle = rate_mbps > 0
    rate_bps = rate_mbps * 1_000_000  # bits per second

    start_time = time.monotonic()

    # ── READ-ONLY — PcapReader streams from disk, one packet at a time ──
    # This never opens a network socket.  It is a pure file reader.
    with PcapReader(str(filepath)) as reader:
        for pkt in reader:
            stats.total_packets += 1
            pkt_len = len(bytes(pkt))
            stats.total_bytes += pkt_len

            # Deliver to callback (local Python call, no network)
            on_packet(pkt)

            # ── Rate limiting ─────────────────────────────────────
            if throttle:
                total_bits = stats.total_bytes * 8
                expected_time = total_bits / rate_bps
                actual_elapsed = time.monotonic() - start_time
                sleep_for = expected_time - actual_elapsed
                if sleep_for > 0:
                    time.sleep(sleep_for)

            # ── Packet cap ────────────────────────────────────────
            if 0 < max_packets <= stats.total_packets:
                logger.info("Reached max_packets=%d, stopping.", max_packets)
                break

    stats.elapsed_seconds = time.monotonic() - start_time
    if stats.elapsed_seconds > 0:
        stats.effective_mbps = (stats.total_bytes * 8) / (
            stats.elapsed_seconds * 1_000_000
        )
    else:
        stats.effective_mbps = 0.0

    logger.info(
        "Replay complete: %d packets, %d bytes, %.2fs, %.2f Mbps effective",
        stats.total_packets,
        stats.total_bytes,
        stats.elapsed_seconds,
        stats.effective_mbps,
    )

    return stats
