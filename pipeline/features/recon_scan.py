"""
pipeline/features/recon_scan.py — Feature extraction for reconnaissance / port scanning.

Pure function ``extract_recon_features`` takes a list of flows
originating from a single source (or a small set of sources) and
returns features that characterise scanning behaviour:

    unique_dst_ports         Distinct destination ports seen
    unique_dst_hosts         Distinct destination IPs seen
    syn_no_completion_ratio  SYN-only flows / total TCP flows
    port_sequence_score      0.0 (random) → 1.0 (sequential ports)
    scan_rate                New flows per second
"""

from __future__ import annotations

from typing import Any

from pipeline.features.common import safe_ratio


def extract_recon_features(
    flows: list[dict],
    packets: list[dict] | None = None,
) -> dict[str, Any]:
    """Extract reconnaissance / port-scan indicator features.

    Parameters
    ----------
    flows : list[dict]
        Flow-event dicts, typically filtered to a single ``src_ip``
        before calling.  Must contain: ``src_ip``, ``dst_ip``,
        ``dst_port``, ``protocol``, ``packets_fwd``, ``packets_bwd``,
        ``start_time``, ``end_time``.
    packets : list[dict], optional
        Raw packet dicts with ``tcp_flags``.  If provided, used for
        finer SYN-without-completion analysis.

    Returns
    -------
    dict[str, Any]
        Flat feature dict.
    """
    if not flows:
        return _empty_features()

    # ── Destination diversity ─────────────────────────────────────
    dst_ports = [f["dst_port"] for f in flows]
    dst_hosts = [f["dst_ip"] for f in flows]

    unique_dst_ports = len(set(dst_ports))
    unique_dst_hosts = len(set(dst_hosts))

    # ── SYN-without-completion ratio ──────────────────────────────
    # A "SYN-only" flow is a TCP flow where the source sent packet(s)
    # (packets_fwd > 0) but received nothing back (packets_bwd == 0).
    tcp_flows = [f for f in flows if f.get("protocol", 0) == 6]
    syn_only = sum(
        1 for f in tcp_flows
        if f.get("packets_fwd", 0) > 0 and f.get("packets_bwd", 0) == 0
    )
    syn_no_completion = safe_ratio(syn_only, len(tcp_flows))

    # ── Port sequence score ───────────────────────────────────────
    # Heuristic: sort destination ports, count adjacent pairs where
    # port[i+1] == port[i] + 1.  Score = sequential_pairs / total_pairs.
    # Score ≈ 1.0 for sequential scanning, ≈ 0.0 for random.
    port_seq_score = _port_sequence_score(dst_ports)

    # ── Scan rate (flows per second) ──────────────────────────────
    window_start = min(f.get("start_time", 0.0) for f in flows)
    window_end = max(f.get("end_time", 0.0) for f in flows)
    window_dur = max(window_end - window_start, 1e-9)
    scan_rate = len(flows) / window_dur

    return {
        "unique_dst_ports": unique_dst_ports,
        "unique_dst_hosts": unique_dst_hosts,
        "syn_no_completion_ratio": syn_no_completion,
        "port_sequence_score": port_seq_score,
        "scan_rate": scan_rate,
    }


def _port_sequence_score(ports: list[int]) -> float:
    """Score how sequential a list of ports is.

    Sort the unique ports, count adjacent pairs where
    ``ports[i+1] == ports[i] + 1``.

    Returns
    -------
    float
        0.0 if no sequential pairs or ≤1 port; up to 1.0 if every
        adjacent pair is sequential.
    """
    if len(ports) <= 1:
        return 0.0

    sorted_unique = sorted(set(ports))
    if len(sorted_unique) <= 1:
        return 0.0

    total_pairs = len(sorted_unique) - 1
    sequential_pairs = sum(
        1 for i in range(total_pairs)
        if sorted_unique[i + 1] == sorted_unique[i] + 1
    )

    return sequential_pairs / total_pairs


def _empty_features() -> dict[str, Any]:
    return {
        "unique_dst_ports": 0,
        "unique_dst_hosts": 0,
        "syn_no_completion_ratio": 0.0,
        "port_sequence_score": 0.0,
        "scan_rate": 0.0,
    }
