"""
tests/test_features_ddos.py — Tests for pipeline/features/ddos.py

All tests use deterministic, hand-crafted flow and packet dicts.
"""

from __future__ import annotations

import pytest

from pipeline.features.common import shannon_entropy, TCP_SYN, TCP_ACK
from pipeline.features.ddos import extract_ddos_features


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _flow(
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    src_port=12345, dst_port=80,
    protocol=6,
    total_packets=10, total_bytes=1000,
    packets_fwd=8, packets_bwd=2,
    bytes_fwd=800, bytes_bwd=200,
    start_time=0.0, end_time=1.0,
) -> dict:
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": protocol,
        "total_packets": total_packets, "total_bytes": total_bytes,
        "packets_fwd": packets_fwd, "packets_bwd": packets_bwd,
        "bytes_fwd": bytes_fwd, "bytes_bwd": bytes_bwd,
        "start_time": start_time, "end_time": end_time,
        "duration": end_time - start_time,
    }


def _pkt(src_ip="10.0.0.1", tcp_flags=0, timestamp=0.0) -> dict:
    return {"src_ip": src_ip, "tcp_flags": tcp_flags, "timestamp": timestamp}


# ═══════════════════════════════════════════════════════════════════════════
# Shannon entropy tests (from common.py)
# ═══════════════════════════════════════════════════════════════════════════

class TestShannonEntropy:

    def test_empty(self):
        assert shannon_entropy([]) == 0.0

    def test_single_value(self):
        assert shannon_entropy(["a"]) == 0.0

    def test_uniform_two(self):
        assert shannon_entropy(["a", "b"]) == pytest.approx(1.0)

    def test_uniform_four(self):
        assert shannon_entropy(["a", "b", "c", "d"]) == pytest.approx(2.0)

    def test_skewed(self):
        # 3 a's, 1 b → lower entropy than uniform
        e = shannon_entropy(["a", "a", "a", "b"])
        assert 0 < e < 1.0

    def test_all_same(self):
        assert shannon_entropy(["x", "x", "x", "x"]) == 0.0


# ═══════════════════════════════════════════════════════════════════════════
# DDoS feature extraction tests
# ═══════════════════════════════════════════════════════════════════════════

class TestDDoSFeatures:

    def test_empty_flows(self):
        """No flows → zeroed features."""
        result = extract_ddos_features([])
        assert result["packets_per_sec"] == 0.0
        assert result["unique_src_count"] == 0
        assert result["src_ip_entropy"] == 0.0

    def test_single_flow_rates(self):
        """Single flow: 10 packets in 1 second → 10 pps."""
        flows = [_flow(total_packets=10, total_bytes=1000,
                       start_time=0.0, end_time=1.0)]
        result = extract_ddos_features(flows)

        assert result["packets_per_sec"] == pytest.approx(10.0)
        assert result["bytes_per_sec"] == pytest.approx(1000.0)
        assert result["unique_src_count"] == 1

    def test_many_sources_high_entropy(self):
        """100 unique sources → high entropy, high unique count."""
        flows = [
            _flow(src_ip=f"10.0.0.{i}", start_time=0.0, end_time=1.0)
            for i in range(100)
        ]
        result = extract_ddos_features(flows)

        assert result["unique_src_count"] == 100
        assert result["src_ip_entropy"] > 5.0  # log2(100) ≈ 6.64
        assert result["unique_src_per_sec"] == pytest.approx(100.0)

    def test_single_source_zero_entropy(self):
        """All flows from same source → zero entropy."""
        flows = [
            _flow(src_ip="10.0.0.1", start_time=0.0, end_time=1.0)
            for _ in range(50)
        ]
        result = extract_ddos_features(flows)
        assert result["src_ip_entropy"] == 0.0
        assert result["unique_src_count"] == 1

    def test_syn_ack_ratio(self):
        """10 SYNs, 2 ACKs → ratio 5.0."""
        packets = (
            [_pkt(tcp_flags=TCP_SYN)] * 10
            + [_pkt(tcp_flags=TCP_ACK)] * 2
        )
        flows = [_flow()]
        result = extract_ddos_features(flows, packets)
        assert result["syn_ack_ratio"] == pytest.approx(5.0)

    def test_syn_ack_ratio_no_acks(self):
        """SYNs with zero ACKs → ratio defaults to 0.0 (safe_ratio)."""
        packets = [_pkt(tcp_flags=TCP_SYN)] * 5
        result = extract_ddos_features([_flow()], packets)
        assert result["syn_ack_ratio"] == 0.0  # safe_ratio default

    def test_protocol_mix_all_tcp(self):
        """All flows TCP → protocol_mix_ratio = 1.0."""
        flows = [_flow(protocol=6) for _ in range(10)]
        result = extract_ddos_features(flows)
        assert result["protocol_mix_ratio"] == pytest.approx(1.0)

    def test_protocol_mix_diverse(self):
        """Mixed protocols → ratio < 1.0."""
        flows = (
            [_flow(protocol=6)] * 5
            + [_flow(protocol=17)] * 3
            + [_flow(protocol=1)] * 2
        )
        result = extract_ddos_features(flows)
        assert result["protocol_mix_ratio"] == pytest.approx(0.5)  # 5/10

    def test_half_open_count(self):
        """SYN-only packets with no backward traffic → half-open."""
        packets = [_pkt(tcp_flags=TCP_SYN)] * 8  # 8 SYN-only
        # All flows have packets_bwd=0 → no responses
        flows = [_flow(packets_bwd=0, protocol=6) for _ in range(3)]
        result = extract_ddos_features(flows, packets)
        # 8 SYN-only − 0 flows with responses = 8, but clamped by flows
        assert result["half_open_count"] >= 5
