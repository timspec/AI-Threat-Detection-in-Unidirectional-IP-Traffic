"""
tests/test_features_exfil.py — Tests for pipeline/features/exfiltration.py

All tests use deterministic, hand-crafted flow dicts with known baselines.
"""

from __future__ import annotations

import math

import pytest

from pipeline.features.exfiltration import (
    ExfiltrationExtractor,
    extract_exfil_features,
    _compute_zscore,
    _is_off_hours,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _flow(
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    bytes_fwd=1000, bytes_bwd=500,
    duration=10.0,
    start_time=1700000000.0,  # 2023-11-14T22:13:20 UTC (off-hours)
) -> dict:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "bytes_fwd": bytes_fwd,
        "bytes_bwd": bytes_bwd,
        "total_bytes": bytes_fwd + bytes_bwd,
        "duration": duration,
        "start_time": start_time,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Internal helper tests
# ═══════════════════════════════════════════════════════════════════════════

class TestComputeZScore:

    def test_empty_history(self):
        assert _compute_zscore(100, []) == 0.0

    def test_single_value_history(self):
        assert _compute_zscore(100, [50]) == 0.0

    def test_known_zscore(self):
        """History [100, 100, 100, 100], value=200.
        mean=100, stddev=0 → inf."""
        result = _compute_zscore(200, [100, 100, 100, 100])
        assert result == float("inf")

    def test_normal_zscore(self):
        """History [10, 20, 30, 40], mean=25, stddev≈11.18.
        Value 36.18 → z ≈ 1.0"""
        history = [10, 20, 30, 40]
        mean = 25.0
        stddev = math.sqrt(sum((x - mean) ** 2 for x in history) / 4)
        value = mean + stddev  # z = 1.0
        result = _compute_zscore(value, history)
        assert result == pytest.approx(1.0, abs=0.01)

    def test_value_equal_to_mean(self):
        """Value == mean → z = 0.0."""
        result = _compute_zscore(25, [10, 20, 30, 40])
        assert result == pytest.approx(0.0, abs=0.01)


class TestIsOffHours:

    def test_business_hours(self):
        """10:00 UTC on a weekday → 0 (in hours)."""
        # 2023-11-15 10:00:00 UTC
        ts = 1700042400.0
        assert _is_off_hours(ts, 9, 17) == 0

    def test_off_hours_night(self):
        """22:00 UTC → 1 (off hours)."""
        # 2023-11-14 22:13:20 UTC
        ts = 1700000000.0
        assert _is_off_hours(ts, 9, 17) == 1

    def test_off_hours_early_morning(self):
        """03:00 UTC → 1."""
        # 2023-11-15 03:00:00 UTC
        ts = 1700017200.0
        assert _is_off_hours(ts, 9, 17) == 1

    def test_boundary_start(self):
        """Exactly 09:00 → 0 (start is inclusive)."""
        # 2023-11-15 09:00:00 UTC
        ts = 1700038800.0
        assert _is_off_hours(ts, 9, 17) == 0

    def test_boundary_end(self):
        """Exactly 17:00 → 1 (end is exclusive)."""
        # 2023-11-15 17:00:00 UTC
        ts = 1700067600.0
        assert _is_off_hours(ts, 9, 17) == 1

    def test_zero_timestamp(self):
        """Epoch 0 → 0 (safeguard)."""
        assert _is_off_hours(0, 9, 17) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Stateless extract_exfil_features tests
# ═══════════════════════════════════════════════════════════════════════════

class TestExfilFeaturesStateless:

    def test_outbound_inbound_ratio(self):
        """2000 out / 500 in → ratio 4.0."""
        result = extract_exfil_features(
            _flow(bytes_fwd=2000, bytes_bwd=500)
        )
        assert result["outbound_inbound_ratio"] == pytest.approx(4.0)

    def test_outbound_ratio_no_inbound(self):
        """Zero inbound → ratio defaults to 0.0."""
        result = extract_exfil_features(
            _flow(bytes_fwd=5000, bytes_bwd=0)
        )
        assert result["outbound_inbound_ratio"] == 0.0

    def test_duration_bytes_ratio(self):
        """10s / 1500 bytes."""
        result = extract_exfil_features(
            _flow(bytes_fwd=1000, bytes_bwd=500, duration=10.0)
        )
        expected = 10.0 / 1500.0
        assert result["duration_bytes_ratio"] == pytest.approx(expected)

    def test_off_hours_flag(self):
        """Night-time flow → flag = 1."""
        result = extract_exfil_features(
            _flow(start_time=1700000000.0)  # 22:13 UTC
        )
        assert result["off_hours_flag"] == 1

    def test_business_hours_flag(self):
        """Day-time flow → flag = 0."""
        result = extract_exfil_features(
            _flow(start_time=1700042400.0)  # 10:00 UTC
        )
        assert result["off_hours_flag"] == 0

    def test_destination_novel(self):
        """First time seeing a destination → novel = 1."""
        result = extract_exfil_features(
            _flow(dst_ip="8.8.8.8"),
            seen_destinations=set(),
        )
        assert result["destination_novel"] == 1

    def test_destination_not_novel(self):
        """Already-seen destination → novel = 0."""
        seen = {("10.0.0.1", "8.8.8.8")}
        result = extract_exfil_features(
            _flow(src_ip="10.0.0.1", dst_ip="8.8.8.8"),
            seen_destinations=seen,
        )
        assert result["destination_novel"] == 0

    def test_zscore_with_baseline(self):
        """Anomalous outbound volume → high z-score."""
        # Baseline: 100 bytes ± 0 stddev → value 10000 → very high z
        result = extract_exfil_features(
            _flow(bytes_fwd=10000),
            baseline_values=[100, 100, 100, 100, 100],
        )
        # 10000 is massively above baseline → z should be large
        assert result["outbound_volume_zscore"] == float("inf")

    def test_zscore_normal_volume(self):
        """Normal outbound volume → z-score near 0."""
        result = extract_exfil_features(
            _flow(bytes_fwd=100),
            baseline_values=[90, 100, 110, 95, 105],
        )
        assert abs(result["outbound_volume_zscore"]) < 2.0


# ═══════════════════════════════════════════════════════════════════════════
# Stateful ExfiltrationExtractor tests
# ═══════════════════════════════════════════════════════════════════════════

class TestExfiltrationExtractorStateful:

    def test_first_flow_novel_destination(self):
        """First flow to any destination → novel = 1."""
        ext = ExfiltrationExtractor()
        result = ext.extract(_flow(dst_ip="8.8.8.8"))
        assert result["destination_novel"] == 1

    def test_second_flow_same_destination(self):
        """Second flow to same destination → novel = 0."""
        ext = ExfiltrationExtractor()
        ext.extract(_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8"))
        result = ext.extract(_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8"))
        assert result["destination_novel"] == 0

    def test_baseline_builds_over_time(self):
        """Z-score should become meaningful after enough history."""
        ext = ExfiltrationExtractor()

        # Feed 10 normal flows (100 bytes each)
        for _ in range(10):
            ext.extract(_flow(bytes_fwd=100, dst_ip="8.8.8.8"))

        # Now feed an anomalous flow (10000 bytes)
        result = ext.extract(_flow(bytes_fwd=10000, dst_ip="1.2.3.4"))
        assert result["outbound_volume_zscore"] > 5.0

    def test_different_sources_independent(self):
        """Baselines are per-source-IP."""
        ext = ExfiltrationExtractor()

        # Build baseline for host A
        for _ in range(10):
            ext.extract(_flow(src_ip="10.0.0.1", bytes_fwd=100))

        # Host B's first flow should have z=0 (no baseline yet)
        result = ext.extract(_flow(src_ip="10.0.0.2", bytes_fwd=10000))
        assert result["outbound_volume_zscore"] == 0.0

    def test_custom_business_hours(self):
        """Custom business hours (0-24) → everything is in-hours."""
        ext = ExfiltrationExtractor(business_hours=(0, 24))
        result = ext.extract(_flow(start_time=1700000000.0))  # 22:13 UTC
        assert result["off_hours_flag"] == 0
