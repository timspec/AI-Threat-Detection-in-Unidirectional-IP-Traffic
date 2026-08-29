"""
pipeline/features/c2_beacon.py — Feature extraction for botnet C2 beaconing.

Detects periodic communication patterns characteristic of command-and-
control beaconing by analysing the *timing* and *size regularity* of
flows or packets between a source and destination.

Key features:

    iat_mean              Mean inter-arrival time (seconds)
    iat_variance          Variance of inter-arrival times
    iat_cv                Coefficient of variation (stddev/mean) of IATs
    periodicity_score     FFT peak-magnitude score (0 → random, 1 → periodic)
    dst_cardinality       Number of unique destination IPs contacted
    session_duration_mean Mean flow/session duration
    session_duration_cv   CV of flow durations
    byte_size_cv          CV of packet/flow byte sizes (low → fixed-size beacons)

The FFT periodicity score works by:
  1. Binning arrival timestamps into a uniform time series.
  2. Computing the real FFT of the (mean-centred) binned signal.
  3. Taking the power spectrum |FFT|².
  4. Returning max(AC power) / sum(AC power).
  A perfectly periodic signal concentrates all AC power at one frequency
  → score ≈ 1.0.  Random arrivals spread power uniformly → score ≈ 0.
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np

from pipeline.features.common import safe_ratio


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def extract_c2_features(
    flows: list[dict],
    packets: list[dict] | None = None,
) -> dict[str, Any]:
    """Extract C2 beaconing indicator features.

    Parameters
    ----------
    flows : list[dict]
        Flow-event dicts.  Must contain at least: ``src_ip``, ``dst_ip``,
        ``start_time``, ``duration``, ``total_bytes``.
    packets : list[dict], optional
        Raw packet-level dicts with ``timestamp`` and ``length``.
        If provided, timing and size analysis uses packet-level granularity
        for higher fidelity.  Otherwise flow ``start_time`` / ``total_bytes``
        are used.

    Returns
    -------
    dict[str, Any]
        Flat feature dict.
    """
    if not flows:
        return _empty_features()

    # ── Derive timestamps & sizes ─────────────────────────────────
    if packets and len(packets) >= 2:
        timestamps = sorted(p["timestamp"] for p in packets)
        sizes = [float(p.get("length", 0)) for p in packets]
    else:
        timestamps = sorted(f["start_time"] for f in flows)
        sizes = [float(f.get("total_bytes", 0)) for f in flows]

    # ── Inter-arrival times ───────────────────────────────────────
    iats = _compute_iats(timestamps)

    iat_mean = _mean(iats)
    iat_var = _variance(iats)
    iat_cv = _cv(iats)

    # ── FFT periodicity score ─────────────────────────────────────
    periodicity = periodicity_score(timestamps)

    # ── Destination cardinality ───────────────────────────────────
    dst_ips = {f.get("dst_ip", "") for f in flows}

    # ── Session-duration distribution ─────────────────────────────
    durations = [f.get("duration", 0.0) for f in flows]
    dur_mean = _mean(durations)
    dur_cv = _cv(durations)

    # ── Byte-size regularity ─────────────────────────────────────
    byte_cv = _cv(sizes)

    return {
        "iat_mean": iat_mean,
        "iat_variance": iat_var,
        "iat_cv": iat_cv,
        "periodicity_score": periodicity,
        "dst_cardinality": len(dst_ips),
        "session_duration_mean": dur_mean,
        "session_duration_cv": dur_cv,
        "byte_size_cv": byte_cv,
    }


# ═══════════════════════════════════════════════════════════════════════════
# FFT periodicity scoring
# ═══════════════════════════════════════════════════════════════════════════

def periodicity_score(
    timestamps: list[float],
    num_bins: int = 256,
) -> float:
    """Compute an FFT-based periodicity score for a series of timestamps.

    Algorithm
    ---------
    1. Sort timestamps and span the full time range.
    2. Divide the range into *num_bins* equal-width bins and count
       arrivals per bin (a sampled arrival-rate signal).
    3. Remove the DC component (subtract the mean).
    4. Compute the real FFT → power spectrum |FFT|².
    5. Return ``peak_ac_power / total_ac_power``.

    A perfectly periodic signal (e.g. beacon every 30 s) will
    concentrate almost all AC power at one frequency → score ≈ 1.0.

    Random / Poisson arrivals spread power across all frequencies →
    score ≈ 1/num_bins ≈ 0.

    Parameters
    ----------
    timestamps : list[float]
        Epoch-second timestamps of events.
    num_bins : int
        Number of time bins for the FFT.  Must be ≥ 8.  Higher values
        give finer frequency resolution but need more data points.

    Returns
    -------
    float
        Score in [0, 1].  Higher → more periodic.
    """
    if len(timestamps) < 4:
        return 0.0

    sorted_ts = sorted(timestamps)
    t_min = sorted_ts[0]
    t_max = sorted_ts[-1]
    duration = t_max - t_min

    if duration < 1e-9:
        # All timestamps identical — no temporal structure to analyse.
        return 0.0

    # ── Bin the arrivals into a uniform time series ───────────────
    bin_width = duration / num_bins
    bins = np.zeros(num_bins, dtype=np.float64)
    for t in sorted_ts:
        idx = int((t - t_min) / bin_width)
        idx = min(idx, num_bins - 1)  # clamp last edge
        bins[idx] += 1.0

    # ── Remove DC (mean-centre) ──────────────────────────────────
    bins -= bins.mean()

    # ── Real FFT → power spectrum ────────────────────────────────
    fft_vals = np.fft.rfft(bins)
    power = np.abs(fft_vals) ** 2

    # Skip index 0 (DC component, which is ~0 after mean-centering)
    if len(power) <= 1:
        return 0.0

    ac_power = power[1:]
    total_ac = ac_power.sum()

    if total_ac < 1e-10:
        return 0.0

    return float(ac_power.max() / total_ac)


# ═══════════════════════════════════════════════════════════════════════════
# Statistical helpers
# ═══════════════════════════════════════════════════════════════════════════

def _compute_iats(timestamps: list[float]) -> list[float]:
    """Compute inter-arrival times from sorted timestamps."""
    if len(timestamps) < 2:
        return []
    s = sorted(timestamps)
    return [s[i + 1] - s[i] for i in range(len(s) - 1)]


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _variance(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return sum((x - m) ** 2 for x in values) / len(values)


def _stddev(values: list[float]) -> float:
    return math.sqrt(_variance(values))


def _cv(values: list[float]) -> float:
    """Coefficient of variation = stddev / mean.  0 if mean is ~0."""
    m = _mean(values)
    if abs(m) < 1e-12:
        return 0.0
    return _stddev(values) / abs(m)


def _empty_features() -> dict[str, Any]:
    return {
        "iat_mean": 0.0,
        "iat_variance": 0.0,
        "iat_cv": 0.0,
        "periodicity_score": 0.0,
        "dst_cardinality": 0,
        "session_duration_mean": 0.0,
        "session_duration_cv": 0.0,
        "byte_size_cv": 0.0,
    }
