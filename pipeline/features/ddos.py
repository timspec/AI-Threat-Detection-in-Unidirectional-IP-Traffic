"""
pipeline/features/ddos.py — Feature extraction for volumetric / protocol DDoS.

Pure function ``extract_ddos_features`` takes a *window* of flow dicts
(and optionally raw packet dicts with TCP flags) and returns a flat
feature dict with the following keys:

    packets_per_sec          Total packets / window duration
    bytes_per_sec            Total bytes / window duration
    syn_ack_ratio            SYN packets / ACK packets
    unique_src_count         Distinct source IPs in the window
    unique_src_per_sec       Unique sources / window duration
    src_ip_entropy           Shannon entropy of the source IP distribution
    protocol_mix_ratio       Fraction of the dominant protocol (1.0 = all same)
    half_open_count          Flows with SYN but no matching ACK (incomplete TCP)
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from pipeline.features.common import (
    TCP_SYN,
    TCP_ACK,
    count_tcp_flags,
    safe_ratio,
    shannon_entropy,
)


def extract_ddos_features(
    flows: list[dict],
    packets: list[dict] | None = None,
) -> dict[str, Any]:
    """Extract DDoS indicator features from a window of flows.

    Parameters
    ----------
    flows : list[dict]
        Flow-event dicts produced by ``FlowBuilder`` (tick or expired).
        Must contain at least: ``src_ip``, ``dst_ip``, ``protocol``,
        ``total_packets``, ``total_bytes``, ``start_time``, ``end_time``,
        ``duration``, ``packets_fwd``, ``packets_bwd``.
    packets : list[dict], optional
        Raw packet-level records with ``tcp_flags`` (int bitmask),
        ``src_ip``, ``timestamp``.  Used for SYN/ACK ratio and
        half-open detection.  If ``None``, those features default to 0.

    Returns
    -------
    dict[str, Any]
        Flat feature dict.
    """
    if not flows:
        return _empty_features()

    packets = packets or []

    # ── Window timing ─────────────────────────────────────────────
    window_start = min(f.get("start_time", 0.0) for f in flows)
    window_end = max(f.get("end_time", 0.0) for f in flows)
    window_dur = max(window_end - window_start, 1e-9)  # avoid div-by-zero

    # ── Aggregate counters ────────────────────────────────────────
    total_pkts = sum(f.get("total_packets", 0) for f in flows)
    total_bytes = sum(f.get("total_bytes", 0) for f in flows)

    # ── Source diversity ──────────────────────────────────────────
    src_ips = [f["src_ip"] for f in flows]
    unique_src = set(src_ips)

    # ── Protocol mix ──────────────────────────────────────────────
    proto_counts = Counter(f.get("protocol", 0) for f in flows)
    dominant_proto_count = proto_counts.most_common(1)[0][1] if proto_counts else 0
    total_flows = len(flows)

    # ── TCP flag analysis (from packet history) ───────────────────
    syn_count = count_tcp_flags(packets, TCP_SYN)
    ack_count = count_tcp_flags(packets, TCP_ACK)

    # Half-open: SYN packets whose (src_ip, src_port) → (dst_ip, dst_port)
    # never got an ACK back.  Simplified: count SYN-only packets
    # (SYN set, ACK not set).
    half_open = sum(
        1 for p in packets
        if (p.get("tcp_flags", 0) & TCP_SYN)
        and not (p.get("tcp_flags", 0) & TCP_ACK)
    )
    # Subtract those that later got ACK responses (simplistic heuristic:
    # half_open ≈ SYN-only packets minus flows that have backward packets)
    flows_with_response = sum(
        1 for f in flows
        if f.get("protocol", 0) == 6 and f.get("packets_bwd", 0) > 0
    )
    half_open_count = max(half_open - flows_with_response, 0)

    return {
        "packets_per_sec": safe_ratio(total_pkts, window_dur),
        "bytes_per_sec": safe_ratio(total_bytes, window_dur),
        "syn_ack_ratio": safe_ratio(syn_count, ack_count),
        "unique_src_count": len(unique_src),
        "unique_src_per_sec": safe_ratio(len(unique_src), window_dur),
        "src_ip_entropy": shannon_entropy(src_ips),
        "protocol_mix_ratio": safe_ratio(dominant_proto_count, total_flows),
        "half_open_count": half_open_count,
    }


def _empty_features() -> dict[str, Any]:
    """Return zeroed feature dict when no flows are available."""
    return {
        "packets_per_sec": 0.0,
        "bytes_per_sec": 0.0,
        "syn_ack_ratio": 0.0,
        "unique_src_count": 0,
        "unique_src_per_sec": 0.0,
        "src_ip_entropy": 0.0,
        "protocol_mix_ratio": 0.0,
        "half_open_count": 0,
    }
