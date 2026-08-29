"""
pipeline/ingest/live_capture.py — Passive live packet capture via Scapy.

╔════════════════════════════════════════════════════════════════════════╗
║                    ⚠️  ONE-WAY GUARANTEE ⚠️                            ║
║                                                                        ║
║  This module is STRICTLY RECEIVE-ONLY.                                 ║
║                                                                        ║
║  FORBIDDEN calls (must NEVER appear in this file):                     ║
║    • sendp(), send(), sr(), sr1(), srp(), srp1()                       ║
║    • socket.send(), socket.sendto(), socket.connect()                  ║
║    • requests.get/post/put/delete or any outbound HTTP                 ║
║    • urllib.request.urlopen or any outbound URL fetch                   ║
║                                                                        ║
║  CODE REVIEW RULE: Any pull request that adds a send-capable call      ║
║  to this file MUST be rejected. The automated test in                  ║
║  tests/test_live_capture.py enforces this via AST scanning.            ║
╚════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from scapy.sendrecv import AsyncSniffer  # receive-only primitive

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module state — one sniffer instance at a time
# ---------------------------------------------------------------------------
_sniffer: Optional[AsyncSniffer] = None


def capture_live(
    interface: str,
    on_packet: Callable,
    bpf_filter: Optional[str] = None,
    packet_count: int = 0,
) -> AsyncSniffer:
    """Start asynchronous live capture on *interface*.

    For every packet received, *on_packet(packet)* is called.
    Packets are NOT stored in memory (``store=False``).

    Parameters
    ----------
    interface : str
        Name of the network interface (as shown by ``tools/check_capture.py``).
    on_packet : Callable
        Callback invoked with each captured ``scapy.packet.Packet``.
    bpf_filter : str, optional
        Berkeley Packet Filter expression (e.g. ``"tcp port 443"``).
    packet_count : int
        Stop after this many packets. ``0`` means capture indefinitely.

    Returns
    -------
    AsyncSniffer
        The running sniffer instance (also stored at module level so
        ``stop_capture()`` can halt it).

    Raises
    ------
    RuntimeError
        If a capture is already running.

    Notes
    -----
    ⚠️  This function uses ONLY ``AsyncSniffer`` in receive mode.
    It does NOT open any send-capable socket.  ``store=False`` ensures
    packets are handed to the callback and then discarded, keeping
    memory usage constant regardless of capture duration.
    """
    global _sniffer

    if _sniffer is not None and _sniffer.running:
        raise RuntimeError(
            "A capture session is already running. "
            "Call stop_capture() before starting a new one."
        )

    logger.info(
        "Starting live capture on interface=%s  bpf_filter=%s  count=%s",
        interface,
        bpf_filter or "(none)",
        packet_count or "unlimited",
    )

    # ── RECEIVE-ONLY — AsyncSniffer with store=False ──────────────────
    # This is the ONLY Scapy primitive we use.  It opens the interface
    # in read-only / promiscuous mode and never transmits.
    _sniffer = AsyncSniffer(
        iface=interface,
        prn=on_packet,        # callback per packet
        store=False,          # don't accumulate packets in memory
        filter=bpf_filter,    # optional BPF
        count=packet_count,   # 0 = unlimited
    )
    _sniffer.start()
    return _sniffer


def stop_capture() -> int:
    """Stop the currently running capture session.

    Returns
    -------
    int
        Number of packets captured before stopping, or 0 if no session
        was active.
    """
    global _sniffer

    if _sniffer is None:
        logger.warning("stop_capture() called but no session is active.")
        return 0

    if _sniffer.running:
        _sniffer.stop()
        logger.info("Capture stopped.")

    # AsyncSniffer keeps a count even with store=False
    count = len(_sniffer.results) if _sniffer.results else 0
    _sniffer = None
    return count


def is_capturing() -> bool:
    """Return True if a capture session is currently running."""
    return _sniffer is not None and _sniffer.running
