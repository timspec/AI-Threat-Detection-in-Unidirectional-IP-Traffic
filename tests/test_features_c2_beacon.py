"""
tests/test_features_c2_beacon.py — Tests for pipeline/features/c2_beacon.py

Core assertion: a synthetic perfectly periodic session must produce a
periodicity_score that is **clearly higher** than a random/irregular
session.  This validates that the FFT approach actually separates
beaconing from normal traffic.

All inputs are deterministic — no randomness in tests.
"""

from __future__ import annotations

import math

import pytest

from pipeline.features.c2_beacon import (
    extract_c2_features,
    periodicity_score,
    _compute_iats,
    _mean,
    _variance,
    _cv,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _flow(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    start_time=0.0,
    duration=1.0,
    total_bytes=200,
) -> dict:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "start_time": start_time,
        "end_time": start_time + duration,
        "duration": duration,
        "total_bytes": total_bytes,
        "bytes_fwd": total_bytes,
        "bytes_bwd": 0,
    }


def _periodic_timestamps(period: float, count: int, start: float = 0.0) -> list[float]:
    """Generate perfectly periodic timestamps: start, start+T, start+2T, ..."""
    return [start + i * period for i in range(count)]


def _irregular_timestamps(count: int, start: float = 0.0) -> list[float]:
    """Generate deterministic but highly irregular timestamps.

    Uses a simple non-linear sequence that looks nothing like a periodic
    signal: t_i = start + i^1.7 (accelerating gaps).
    """
    return [start + (i ** 1.7) for i in range(count)]


# ═══════════════════════════════════════════════════════════════════════════
# IAT helper tests
# ═══════════════════════════════════════════════════════════════════════════

class TestIATHelpers:

    def test_compute_iats_basic(self):
        iats = _compute_iats([0.0, 1.0, 3.0, 6.0])
        assert iats == [1.0, 2.0, 3.0]

    def test_compute_iats_single(self):
        assert _compute_iats([5.0]) == []

    def test_compute_iats_empty(self):
        assert _compute_iats([]) == []

    def test_mean(self):
        assert _mean([2.0, 4.0, 6.0]) == pytest.approx(4.0)

    def test_variance(self):
        # [2, 4, 6]: mean=4, var=((4+0+4)/3)=8/3
        assert _variance([2.0, 4.0, 6.0]) == pytest.approx(8.0 / 3.0)

    def test_cv_uniform(self):
        """All same values → CV = 0."""
        assert _cv([5.0, 5.0, 5.0, 5.0]) == 0.0

    def test_cv_nonzero(self):
        """Known CV."""
        vals = [10.0, 20.0, 30.0]
        m = _mean(vals)
        s = math.sqrt(_variance(vals))
        assert _cv(vals) == pytest.approx(s / m)


# ═══════════════════════════════════════════════════════════════════════════
# Periodicity score tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPeriodicityScore:
    """The FFT periodicity score must clearly separate periodic from random."""

    def test_perfectly_periodic(self):
        """Beacon every 30s for 100 events → score close to 1.0."""
        ts = _periodic_timestamps(period=30.0, count=100)
        score = periodicity_score(ts)
        assert score > 0.5, f"Periodic score too low: {score}"

    def test_irregular_low_score(self):
        """Accelerating gaps (non-periodic) → low score."""
        ts = _irregular_timestamps(count=100)
        score = periodicity_score(ts)
        assert score < 0.3, f"Irregular score too high: {score}"

    def test_periodic_beats_irregular(self):
        """⭐ KEY ASSERTION: periodic score must be clearly higher."""
        periodic_ts = _periodic_timestamps(period=30.0, count=100)
        irregular_ts = _irregular_timestamps(count=100)

        score_periodic = periodicity_score(periodic_ts)
        score_irregular = periodicity_score(irregular_ts)

        assert score_periodic > score_irregular * 2, (
            f"Periodic ({score_periodic:.4f}) should be clearly > "
            f"irregular ({score_irregular:.4f})"
        )

    def test_too_few_timestamps(self):
        """Fewer than 4 timestamps → score 0.0 (not enough data)."""
        assert periodicity_score([1.0, 2.0, 3.0]) == 0.0

    def test_identical_timestamps(self):
        """All same timestamp → score 0.0."""
        assert periodicity_score([5.0] * 50) == 0.0

    def test_two_different_periods_lower_score(self):
        """Mixing two periods → lower score than a single period."""
        pure = _periodic_timestamps(period=10.0, count=50)
        # Interleave a second period
        mixed = pure + _periodic_timestamps(period=17.0, count=50, start=0.5)

        score_pure = periodicity_score(pure)
        score_mixed = periodicity_score(mixed)

        assert score_pure > score_mixed, (
            f"Pure ({score_pure:.4f}) should be > mixed ({score_mixed:.4f})"
        )

    def test_different_periods_detected(self):
        """Beaconing every 10s vs every 60s — both should score high."""
        fast = _periodic_timestamps(period=10.0, count=100)
        slow = _periodic_timestamps(period=60.0, count=100)

        assert periodicity_score(fast) > 0.4
        assert periodicity_score(slow) > 0.4


# ═══════════════════════════════════════════════════════════════════════════
# Full extract_c2_features tests
# ═══════════════════════════════════════════════════════════════════════════

class TestExtractC2Features:

    def test_empty_flows(self):
        result = extract_c2_features([])
        assert result["periodicity_score"] == 0.0
        assert result["iat_mean"] == 0.0
        assert result["dst_cardinality"] == 0

    def test_periodic_beacon_session(self):
        """100 flows at 30s intervals → high periodicity, low IAT CV."""
        flows = [
            _flow(start_time=i * 30.0, total_bytes=200)
            for i in range(100)
        ]
        result = extract_c2_features(flows)

        assert result["periodicity_score"] > 0.4
        assert result["iat_mean"] == pytest.approx(30.0)
        assert result["iat_cv"] == pytest.approx(0.0, abs=0.01)

    def test_irregular_session(self):
        """Non-periodic flows → low periodicity, high IAT CV."""
        ts = _irregular_timestamps(count=100)
        flows = [_flow(start_time=t) for t in ts]
        result = extract_c2_features(flows)

        assert result["periodicity_score"] < 0.3
        assert result["iat_cv"] > 0.3  # high variation

    def test_dst_cardinality(self):
        """5 unique destinations → cardinality = 5."""
        flows = [
            _flow(dst_ip=f"10.0.0.{i}", start_time=float(i))
            for i in range(5)
        ]
        result = extract_c2_features(flows)
        assert result["dst_cardinality"] == 5

    def test_byte_size_regularity_uniform(self):
        """All flows same size → byte_size_cv = 0."""
        flows = [
            _flow(start_time=float(i), total_bytes=200)
            for i in range(20)
        ]
        result = extract_c2_features(flows)
        assert result["byte_size_cv"] == pytest.approx(0.0)

    def test_byte_size_regularity_varied(self):
        """Mixed sizes → byte_size_cv > 0."""
        sizes = [100, 500, 200, 1000, 50, 800, 150, 400, 900, 300]
        flows = [
            _flow(start_time=float(i), total_bytes=s)
            for i, s in enumerate(sizes)
        ]
        result = extract_c2_features(flows)
        assert result["byte_size_cv"] > 0.5

    def test_session_duration_stats(self):
        """Flows with uniform duration → cv ≈ 0."""
        flows = [
            _flow(start_time=float(i) * 10, duration=2.0)
            for i in range(20)
        ]
        result = extract_c2_features(flows)
        assert result["session_duration_mean"] == pytest.approx(2.0)
        assert result["session_duration_cv"] == pytest.approx(0.0)

    def test_packet_level_overrides_flow_level(self):
        """When packets are provided, timing uses packet timestamps."""
        flows = [_flow(start_time=0.0)]

        # Packets with their own timing (10 packets, 5s apart)
        packets = [
            {"timestamp": i * 5.0, "length": 100}
            for i in range(10)
        ]
        result = extract_c2_features(flows, packets=packets)
        assert result["iat_mean"] == pytest.approx(5.0)

    def test_all_feature_keys_present(self):
        """Verify all expected keys exist in the output."""
        flows = [_flow(start_time=float(i)) for i in range(10)]
        result = extract_c2_features(flows)
        expected_keys = {
            "iat_mean", "iat_variance", "iat_cv",
            "periodicity_score",
            "dst_cardinality",
            "session_duration_mean", "session_duration_cv",
            "byte_size_cv",
        }
        assert expected_keys == set(result.keys())
