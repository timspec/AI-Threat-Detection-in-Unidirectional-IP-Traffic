"""
pipeline/flow/flow_builder.py — Bidirectional 5-tuple flow aggregation.

Groups raw packets into flows identified by a canonical 5-tuple
(ip_a, ip_b, port_a, port_b, protocol).  Direction is tracked
relative to the first packet seen for each flow.

Two event types are emitted via the ``on_flow_event`` callback:

  • **"tick"** — once per second for every active flow older than 1 s.
    This lets DDoS / beaconing / exfiltration detectors see a flow
    in progress before it ends.

  • **"expired"** — when a flow expires due to idle timeout (no packets
    for ``idle_timeout`` seconds) or active timeout (flow has been alive
    for ``active_timeout`` seconds regardless of activity).

All timestamps come from packet metadata (not wall-clock time),
so the same code works for both live capture and PCAP replay.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class FlowKey:
    """Canonical bidirectional flow key.

    ``ip_a / port_a`` is always the lexicographically smaller
    (ip, port) pair so that packets in *either* direction hash
    to the same key.
    """
    ip_a: str
    ip_b: str
    port_a: int
    port_b: int
    protocol: int


@dataclass
class FlowRecord:
    """Mutable state for a single tracked flow."""

    # ── Identity (set once, from the first packet) ────────────────────
    key: FlowKey
    flow_id: str                # deterministic hash of the key
    src_ip: str                 # IP that sent the *first* packet (forward dir)
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # ── Counters ──────────────────────────────────────────────────────
    packets_fwd: int = 0
    packets_bwd: int = 0
    bytes_fwd: int = 0
    bytes_bwd: int = 0

    # ── Timing ────────────────────────────────────────────────────────
    start_time: float = 0.0     # timestamp of the first packet
    end_time: float = 0.0       # timestamp of the most recent packet
    last_seen: float = 0.0      # same as end_time (used for idle check)
    last_tick: float = 0.0      # timestamp of the last tick event emitted

    # ── State ─────────────────────────────────────────────────────────
    state: str = "active"       # "active" | "expired_idle" | "expired_active"


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def make_flow_key(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    protocol: int,
) -> FlowKey:
    """Create a canonical (bidirectional) flow key.

    The (ip, port) pair that sorts first becomes ``(ip_a, port_a)``.
    This ensures packets going A→B and B→A produce the same key.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
    else:
        return FlowKey(dst_ip, src_ip, dst_port, src_port, protocol)


def _flow_id_from_key(key: FlowKey) -> str:
    """Deterministic short hash for a flow key."""
    raw = f"{key.ip_a}:{key.port_a}-{key.ip_b}:{key.port_b}-{key.protocol}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _is_forward(key: FlowKey, src_ip: str, src_port: int) -> bool:
    """Return True if the packet is in the 'forward' direction."""
    return src_ip == key.ip_a and src_port == key.port_a


# ═══════════════════════════════════════════════════════════════════════════
# FlowBuilder
# ═══════════════════════════════════════════════════════════════════════════

class FlowBuilder:
    """Aggregate raw packets into bidirectional 5-tuple flows.

    Parameters
    ----------
    idle_timeout : float
        Seconds of inactivity before a flow is expired (default 15).
    active_timeout : float
        Maximum lifetime of a flow in seconds (default 300).
    tick_interval : float
        Emit a ``"tick"`` event for each active flow this often (default 1 s).
    on_flow_event : Callable[[dict], None] | None
        Callback receiving flow-event dicts.
    """

    def __init__(
        self,
        idle_timeout: float = 15.0,
        active_timeout: float = 300.0,
        tick_interval: float = 1.0,
        on_flow_event: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._idle_timeout = idle_timeout
        self._active_timeout = active_timeout
        self._tick_interval = tick_interval
        self._on_flow_event = on_flow_event

        self._flows: dict[FlowKey, FlowRecord] = {}
        self._latest_time: float = 0.0  # high-water mark of packet timestamps

        # Lifetime stats
        self.total_packets: int = 0
        self.total_flows_created: int = 0
        self.total_flows_expired: int = 0

    # ── Properties ────────────────────────────────────────────────────

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    # ── Packet ingestion ──────────────────────────────────────────────

    def ingest_packet(self, pkt_info: dict) -> None:
        """Process one packet and update flow state.

        Parameters
        ----------
        pkt_info : dict
            Must contain at minimum::

                {
                    "src_ip":    str,
                    "dst_ip":    str,
                    "src_port":  int,
                    "dst_port":  int,
                    "protocol":  int,    # 6=TCP, 17=UDP, 1=ICMP, ...
                    "length":    int,    # packet size in bytes
                    "timestamp": float,  # epoch seconds
                }
        """
        src_ip = pkt_info["src_ip"]
        dst_ip = pkt_info["dst_ip"]
        src_port = pkt_info["src_port"]
        dst_port = pkt_info["dst_port"]
        protocol = pkt_info["protocol"]
        length = pkt_info["length"]
        ts = pkt_info["timestamp"]

        self.total_packets += 1
        self._latest_time = max(self._latest_time, ts)

        key = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if key in self._flows:
            record = self._flows[key]
        else:
            # New flow — the *first* packet defines the "forward" direction
            record = FlowRecord(
                key=key,
                flow_id=_flow_id_from_key(key),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_time=ts,
                last_tick=ts,  # suppress immediate tick
            )
            self._flows[key] = record
            self.total_flows_created += 1

        # ── Update counters ───────────────────────────────────────
        if _is_forward(key, src_ip, src_port):
            record.packets_fwd += 1
            record.bytes_fwd += length
        else:
            record.packets_bwd += 1
            record.bytes_bwd += length

        record.end_time = ts
        record.last_seen = ts

        # ── Run timeout & tick checks using this packet's time ────
        self._check_timeouts_and_ticks(ts)

    # ── Periodic maintenance ──────────────────────────────────────────

    def tick(self, current_time: float | None = None) -> None:
        """Manually trigger timeout checks and tick events.

        Call this periodically (e.g. every second) to ensure flows
        are expired even when no packets arrive.  In PCAP-replay mode
        you usually don't need to call this — ``ingest_packet`` does it
        automatically using the packet timestamp.
        """
        t = current_time if current_time is not None else self._latest_time
        self._check_timeouts_and_ticks(t)

    def flush_all(self) -> None:
        """Force-expire every active flow and emit final events."""
        keys = list(self._flows.keys())
        for key in keys:
            self._expire_flow(key, "expired_flush")

    # ── Internal ──────────────────────────────────────────────────────

    def _check_timeouts_and_ticks(self, now: float) -> None:
        """Walk all flows, expire timed-out ones, emit ticks for active ones."""
        expired: list[tuple[FlowKey, str]] = []  # (key, reason)

        for key, record in self._flows.items():
            age = now - record.start_time
            idle = now - record.last_seen

            # ── Active timeout (checked first — takes priority) ───
            if age >= self._active_timeout:
                expired.append((key, "expired_active"))
                continue

            # ── Idle timeout ──────────────────────────────────────
            if idle >= self._idle_timeout:
                expired.append((key, "expired_idle"))
                continue

            # ── Tick event (1-second heartbeat for long-lived flows) ─
            since_last_tick = now - record.last_tick
            if age >= self._tick_interval and since_last_tick >= self._tick_interval:
                self._emit_event(record, "tick")
                record.last_tick = now

        for key, reason in expired:
            self._expire_flow(key, reason)

    def _expire_flow(self, key: FlowKey, reason: str) -> None:
        """Remove a flow and emit an expiry event."""
        record = self._flows.pop(key, None)
        if record is None:
            return
        record.state = reason
        self._emit_event(record, "expired")
        self.total_flows_expired += 1

    def _emit_event(self, record: FlowRecord, event_type: str) -> None:
        """Build and emit a flow-event dict."""
        event = self._record_to_dict(record, event_type)
        if self._on_flow_event:
            self._on_flow_event(event)

    @staticmethod
    def _record_to_dict(record: FlowRecord, event_type: str) -> dict[str, Any]:
        """Convert a FlowRecord to a flat dict matching the storage schema."""
        duration = record.end_time - record.start_time
        total_pkts = record.packets_fwd + record.packets_bwd
        total_bytes = record.bytes_fwd + record.bytes_bwd

        return {
            "flow_id": record.flow_id,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "src_port": record.src_port,
            "dst_port": record.dst_port,
            "protocol": record.protocol,
            "packets_fwd": record.packets_fwd,
            "packets_bwd": record.packets_bwd,
            "bytes_fwd": record.bytes_fwd,
            "bytes_bwd": record.bytes_bwd,
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "start_time": record.start_time,
            "end_time": record.end_time,
            "duration": duration,
            "state": record.state,
            "event_type": event_type,
        }
