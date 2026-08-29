"""
pipeline/features/exfiltration.py — Feature extraction for data exfiltration.

``ExfiltrationExtractor`` is a lightweight stateful class that maintains
per-host rolling baselines so it can flag anomalous outbound volumes.

For each flow it produces a flat feature dict:

    outbound_inbound_ratio   bytes_fwd / bytes_bwd
    outbound_volume_zscore   (bytes_fwd - rolling_mean) / rolling_stddev
    duration_bytes_ratio     duration / total_bytes  (low → burst exfil)
    off_hours_flag           1 if flow is outside configurable business hours
    destination_novel        1 if dst_ip has never been seen before by this host

A pure wrapper ``extract_exfil_features`` is also provided for one-shot
(stateless) use in tests or batch processing.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from pipeline.features.common import safe_ratio


class ExfiltrationExtractor:
    """Stateful feature extractor that tracks per-host baselines.

    Parameters
    ----------
    business_hours : tuple[int, int]
        (start_hour, end_hour) in 24-h format, inclusive start, exclusive
        end.  Default ``(9, 17)`` — 09:00 to 17:00.
    baseline_window : int
        Number of recent ``bytes_fwd`` values to keep per source host
        for the rolling mean / stddev.  Default 100.
    """

    def __init__(
        self,
        business_hours: tuple[int, int] = (9, 17),
        baseline_window: int = 100,
    ) -> None:
        self._biz_start, self._biz_end = business_hours
        self._baseline_window = baseline_window

        # Per-source-IP rolling outbound byte history
        self._host_baseline: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=baseline_window)
        )
        # Set of all (src_ip, dst_ip) pairs ever seen
        self._seen_destinations: set[tuple[str, str]] = set()

    def extract(self, flow: dict) -> dict[str, Any]:
        """Extract exfiltration features for a single flow.

        Parameters
        ----------
        flow : dict
            Flow-event dict from ``FlowBuilder``.  Must contain:
            ``src_ip``, ``dst_ip``, ``bytes_fwd``, ``bytes_bwd``,
            ``total_bytes``, ``duration``, ``start_time``.

        Returns
        -------
        dict[str, Any]
            Flat feature dict.
        """
        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]
        bytes_fwd = flow.get("bytes_fwd", 0)
        bytes_bwd = flow.get("bytes_bwd", 0)
        total_bytes = flow.get("total_bytes", 0)
        duration = flow.get("duration", 0.0)
        start_time = flow.get("start_time", 0.0)

        # ── Outbound / inbound ratio ──────────────────────────────
        out_in_ratio = safe_ratio(bytes_fwd, bytes_bwd)

        # ── Outbound volume z-score vs rolling baseline ───────────
        baseline = self._host_baseline[src_ip]
        z_score = _compute_zscore(bytes_fwd, baseline)
        baseline.append(float(bytes_fwd))  # update baseline AFTER scoring

        # ── Duration / bytes ratio ────────────────────────────────
        # A low ratio (lots of bytes in short time) hints at burst exfil.
        dur_bytes_ratio = safe_ratio(duration, total_bytes) if total_bytes > 0 else 0.0

        # ── Off-hours flag ────────────────────────────────────────
        off_hours = _is_off_hours(start_time, self._biz_start, self._biz_end)

        # ── Destination novelty ───────────────────────────────────
        pair = (src_ip, dst_ip)
        novel = 1 if pair not in self._seen_destinations else 0
        self._seen_destinations.add(pair)

        return {
            "outbound_inbound_ratio": out_in_ratio,
            "outbound_volume_zscore": z_score,
            "duration_bytes_ratio": dur_bytes_ratio,
            "off_hours_flag": off_hours,
            "destination_novel": novel,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Pure (stateless) convenience wrapper
# ═══════════════════════════════════════════════════════════════════════════

def extract_exfil_features(
    flow: dict,
    baseline_values: list[float] | None = None,
    seen_destinations: set[tuple[str, str]] | None = None,
    business_hours: tuple[int, int] = (9, 17),
) -> dict[str, Any]:
    """One-shot (stateless) exfiltration feature extraction.

    Useful for tests and batch processing where you don't want to
    instantiate a class.

    Parameters
    ----------
    flow : dict
        Flow-event dict.
    baseline_values : list[float], optional
        Historical ``bytes_fwd`` values for the source host.
    seen_destinations : set, optional
        Already-seen (src_ip, dst_ip) pairs.
    business_hours : tuple
        (start_hour, end_hour).

    Returns
    -------
    dict[str, Any]
    """
    bytes_fwd = flow.get("bytes_fwd", 0)
    bytes_bwd = flow.get("bytes_bwd", 0)
    total_bytes = flow.get("total_bytes", 0)
    duration = flow.get("duration", 0.0)
    start_time = flow.get("start_time", 0.0)
    src_ip = flow.get("src_ip", "")
    dst_ip = flow.get("dst_ip", "")

    baseline = deque(baseline_values) if baseline_values else deque()

    pair = (src_ip, dst_ip)
    seen = seen_destinations or set()

    return {
        "outbound_inbound_ratio": safe_ratio(bytes_fwd, bytes_bwd),
        "outbound_volume_zscore": _compute_zscore(bytes_fwd, baseline),
        "duration_bytes_ratio": safe_ratio(duration, total_bytes) if total_bytes > 0 else 0.0,
        "off_hours_flag": _is_off_hours(start_time, business_hours[0], business_hours[1]),
        "destination_novel": 1 if pair not in seen else 0,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════════

def _compute_zscore(value: float, history: deque[float] | list[float]) -> float:
    """Compute z-score of *value* against a rolling history.

    Returns 0.0 if fewer than 2 historical values exist (not enough
    data for a meaningful standard deviation).
    """
    if len(history) < 2:
        return 0.0

    n = len(history)
    mean = sum(history) / n
    variance = sum((x - mean) ** 2 for x in history) / n
    stddev = math.sqrt(variance)

    if stddev < 1e-9:
        # All historical values are identical
        return 0.0 if abs(value - mean) < 1e-9 else float("inf")

    return (value - mean) / stddev


def _is_off_hours(epoch_time: float, biz_start: int, biz_end: int) -> int:
    """Return 1 if *epoch_time* falls outside business hours (UTC), else 0."""
    if epoch_time <= 0:
        return 0
    dt = datetime.fromtimestamp(epoch_time, tz=timezone.utc)
    hour = dt.hour
    if biz_start <= hour < biz_end:
        return 0
    return 1
