"""
tests/test_features_recon.py — Tests for pipeline/features/recon_scan.py

All tests use deterministic, hand-crafted flow dicts.
"""

from __future__ import annotations

import pytest

from pipeline.features.recon_scan import extract_recon_features, _port_sequence_score


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _flow(
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    dst_port=80, protocol=6,
    packets_fwd=1, packets_bwd=0,
    start_time=0.0, end_time=1.0,
) -> dict:
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": 50000, "dst_port": dst_port,
        "protocol": protocol,
        "packets_fwd": packets_fwd, "packets_bwd": packets_bwd,
        "bytes_fwd": 64, "bytes_bwd": 0,
        "total_packets": packets_fwd + packets_bwd,
        "total_bytes": 64,
        "start_time": start_time, "end_time": end_time,
        "duration": end_time - start_time,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Port sequence score tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPortSequenceScore:

    def test_empty_list(self):
        assert _port_sequence_score([]) == 0.0

    def test_single_port(self):
        assert _port_sequence_score([80]) == 0.0

    def test_perfectly_sequential(self):
        """Ports 1,2,3,4,5 → score 1.0."""
        assert _port_sequence_score([1, 2, 3, 4, 5]) == pytest.approx(1.0)

    def test_perfectly_random(self):
        """Widely spaced ports → score 0.0."""
        assert _port_sequence_score([22, 80, 443, 8080]) == pytest.approx(0.0)

    def test_partially_sequential(self):
        """Mix of sequential and non-sequential."""
        # 1→2 (seq), 2→3 (seq), 3→100 (not), 100→101 (seq)
        score = _port_sequence_score([1, 2, 3, 100, 101])
        assert 0.5 <= score <= 0.85  # 3/4 = 0.75

    def test_unsorted_input(self):
        """Score should be the same regardless of input order."""
        s1 = _port_sequence_score([3, 1, 5, 2, 4])
        s2 = _port_sequence_score([1, 2, 3, 4, 5])
        assert s1 == pytest.approx(s2)

    def test_duplicate_ports(self):
        """Duplicates should be collapsed to unique values."""
        # Unique: [1, 2, 3] → 2 pairs, 2 sequential → 1.0
        assert _port_sequence_score([1, 1, 2, 2, 3, 3]) == pytest.approx(1.0)


# ═══════════════════════════════════════════════════════════════════════════
# Recon feature extraction tests
# ═══════════════════════════════════════════════════════════════════════════

class TestReconFeatures:

    def test_empty_flows(self):
        result = extract_recon_features([])
        assert result["unique_dst_ports"] == 0
        assert result["scan_rate"] == 0.0

    def test_port_scan_detected(self):
        """Hitting many distinct ports → high unique_dst_ports."""
        flows = [_flow(dst_port=p) for p in range(20, 120)]  # 100 ports
        result = extract_recon_features(flows)

        assert result["unique_dst_ports"] == 100
        assert result["unique_dst_hosts"] == 1  # all to same host

    def test_host_sweep_detected(self):
        """Hitting many distinct hosts → high unique_dst_hosts."""
        flows = [
            _flow(dst_ip=f"10.0.0.{i}", dst_port=80)
            for i in range(50)
        ]
        result = extract_recon_features(flows)

        assert result["unique_dst_hosts"] == 50
        assert result["unique_dst_ports"] == 1  # all port 80

    def test_syn_no_completion_ratio(self):
        """All TCP flows with no backward packets → ratio 1.0."""
        flows = [_flow(packets_fwd=1, packets_bwd=0) for _ in range(10)]
        result = extract_recon_features(flows)
        assert result["syn_no_completion_ratio"] == pytest.approx(1.0)

    def test_syn_completion_normal(self):
        """All TCP flows get responses → ratio 0.0."""
        flows = [_flow(packets_fwd=5, packets_bwd=3) for _ in range(10)]
        result = extract_recon_features(flows)
        assert result["syn_no_completion_ratio"] == pytest.approx(0.0)

    def test_syn_completion_mixed(self):
        """Half completed, half not → ratio 0.5."""
        flows = (
            [_flow(packets_fwd=5, packets_bwd=3)] * 5  # completed
            + [_flow(packets_fwd=1, packets_bwd=0)] * 5  # SYN-only
        )
        result = extract_recon_features(flows)
        assert result["syn_no_completion_ratio"] == pytest.approx(0.5)

    def test_sequential_scan_score(self):
        """Sequential port scan 1..50 → high score."""
        flows = [
            _flow(dst_port=p, start_time=0.0, end_time=1.0)
            for p in range(1, 51)
        ]
        result = extract_recon_features(flows)
        assert result["port_sequence_score"] > 0.9

    def test_random_ports_low_score(self):
        """Widely spaced random ports → low score."""
        random_ports = [22, 80, 443, 3306, 5432, 8080, 8443, 27017]
        flows = [_flow(dst_port=p) for p in random_ports]
        result = extract_recon_features(flows)
        assert result["port_sequence_score"] < 0.3

    def test_scan_rate(self):
        """10 flows in 2 seconds → 5 flows/sec."""
        flows = [
            _flow(start_time=0.0, end_time=2.0)
            for _ in range(10)
        ]
        result = extract_recon_features(flows)
        assert result["scan_rate"] == pytest.approx(5.0)

    def test_udp_flows_not_in_syn_ratio(self):
        """UDP flows should be excluded from SYN-completion analysis."""
        flows = [
            _flow(protocol=17, packets_bwd=0)  # UDP, no response
            for _ in range(10)
        ]
        result = extract_recon_features(flows)
        # No TCP flows → ratio defaults to 0.0
        assert result["syn_no_completion_ratio"] == 0.0
