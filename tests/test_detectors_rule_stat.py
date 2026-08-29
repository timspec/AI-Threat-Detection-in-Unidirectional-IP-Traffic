"""
tests/test_detectors_rule_stat.py — Unit tests for rule and statistical detectors.

Covers:
  1. DDoS detector (EWMA / rules + IsolationForest)
  2. Recon / scan detector (vertical port scans, horizontal sweeps, benign)
  3. Exfiltration detector (rolling z-score, off-hours, novelty, asymmetric volume)
"""

from __future__ import annotations

import pytest

from pipeline.detectors.ddos import DDoSDetector, score as score_ddos
from pipeline.detectors.recon_scan import ReconScanDetector, score as score_recon
from pipeline.detectors.exfiltration import ExfiltrationDetector, score as score_exfil


# ═══════════════════════════════════════════════════════════════════════════
# 1. DDoS Detector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestDDoSDetector:

    def test_benign_traffic_scores_low(self):
        """Standard low-volume normal traffic should yield low confidence."""
        benign_features = {
            "packets_per_sec": 12.0,
            "bytes_per_sec": 8_500.0,
            "syn_ack_ratio": 1.05,
            "unique_src_count": 2,
            "unique_src_per_sec": 0.8,
            "src_ip_entropy": 0.5,
            "protocol_mix_ratio": 0.7,
            "half_open_count": 0,
        }
        res = score_ddos(benign_features)

        assert "confidence" in res
        assert "evidence" in res
        assert "model_version" in res
        assert 0.0 <= res["confidence"] <= 0.35, f"Expected low confidence, got {res['confidence']}"
        assert len(res["evidence"]["triggers"]) == 0

    def test_syn_flood_scores_high(self):
        """Massive SYN flood with high SYN:ACK and high pps must score high."""
        syn_flood_features = {
            "packets_per_sec": 8_000.0,
            "bytes_per_sec": 4_000_000.0,
            "syn_ack_ratio": 25.0,
            "unique_src_count": 300,
            "unique_src_per_sec": 300.0,
            "src_ip_entropy": 7.5,
            "protocol_mix_ratio": 1.0,
            "half_open_count": 250,
        }
        res = score_ddos(syn_flood_features)

        assert res["confidence"] >= 0.70, f"Expected high confidence, got {res['confidence']}"
        assert len(res["evidence"]["triggers"]) >= 3

    def test_volumetric_udp_flood_scores_high(self):
        """High bandwidth/pps volumetric flood should trigger detection."""
        udp_flood_features = {
            "packets_per_sec": 15_000.0,
            "bytes_per_sec": 18_000_000.0,
            "syn_ack_ratio": 0.0,
            "unique_src_count": 1_000,
            "unique_src_per_sec": 1_000.0,
            "src_ip_entropy": 8.5,
            "protocol_mix_ratio": 1.0,
            "half_open_count": 0,
        }
        detector = DDoSDetector()
        res = detector.score(udp_flood_features)

        assert res["confidence"] >= 0.70
        assert any("High packet rate" in t for t in res["evidence"]["triggers"])
        assert any("High byte volume" in t for t in res["evidence"]["triggers"])

    def test_schema_and_boundaries(self):
        """Detector score should always produce float confidence bounded in [0, 1]."""
        detector = DDoSDetector()
        for pps in [0.0, 100.0, 100_000.0]:
            out = detector.score({"packets_per_sec": pps})
            assert isinstance(out["confidence"], float)
            assert 0.0 <= out["confidence"] <= 1.0


# ═══════════════════════════════════════════════════════════════════════════
# 2. Recon / Scan Detector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestReconScanDetector:

    def test_benign_traffic_scores_low(self):
        """Single destination host and port (normal connection) should score near 0."""
        benign_recon = {
            "unique_dst_ports": 1,
            "unique_dst_hosts": 1,
            "syn_no_completion_ratio": 0.0,
            "port_sequence_score": 0.0,
            "scan_rate": 0.2,
        }
        res = score_recon(benign_recon)

        assert res["confidence"] < 0.20
        assert len(res["evidence"]["triggers"]) == 0

    def test_vertical_port_scan_scores_high(self):
        """Probing 80 distinct sequential ports on a single host must score high."""
        port_scan = {
            "unique_dst_ports": 80,
            "unique_dst_hosts": 1,
            "syn_no_completion_ratio": 0.95,
            "port_sequence_score": 0.92,
            "scan_rate": 25.0,
        }
        res = score_recon(port_scan)

        assert res["confidence"] >= 0.75
        assert any("Vertical port scan" in t for t in res["evidence"]["triggers"])
        assert any("Sequential port probing" in t for t in res["evidence"]["triggers"])

    def test_horizontal_host_sweep_scores_high(self):
        """Sweeping 40 hosts on port 445 (SMB) or 22 (SSH) must score high."""
        host_sweep = {
            "unique_dst_ports": 1,
            "unique_dst_hosts": 40,
            "syn_no_completion_ratio": 0.85,
            "port_sequence_score": 0.0,
            "scan_rate": 18.0,
        }
        res = score_recon(host_sweep)

        assert res["confidence"] >= 0.70
        assert any("Horizontal host sweep" in t for t in res["evidence"]["triggers"])

    def test_custom_thresholds(self):
        """Customized lower thresholds should fire earlier."""
        sensitive_detector = ReconScanDetector(port_threshold=5, host_threshold=3)
        res = sensitive_detector.score({"unique_dst_ports": 6})
        assert res["confidence"] >= 0.40


# ═══════════════════════════════════════════════════════════════════════════
# 3. Exfiltration Detector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestExfiltrationDetector:

    def test_benign_download_scores_low(self):
        """Inbound heavy traffic (downloading, normal web browsing) should score low."""
        benign_exfil = {
            "outbound_inbound_ratio": 0.05,
            "outbound_volume_zscore": 0.3,
            "duration_bytes_ratio": 0.02,
            "off_hours_flag": 0,
            "destination_novel": 0,
        }
        res = score_exfil(benign_exfil)

        assert res["confidence"] < 0.20
        assert len(res["evidence"]["triggers"]) == 0

    def test_massive_off_hours_exfiltration_scores_high(self):
        """Anomalous outbound volume (z=6.5) + off-hours + novel destination must score high."""
        attack_exfil = {
            "outbound_inbound_ratio": 45.0,
            "outbound_volume_zscore": 6.5,
            "duration_bytes_ratio": 0.00005,
            "off_hours_flag": 1,
            "destination_novel": 1,
        }
        res = score_exfil(attack_exfil)

        assert res["confidence"] >= 0.80
        assert any("Statistically anomalous outbound volume" in t for t in res["evidence"]["triggers"])
        assert any("outside standard business hours" in t for t in res["evidence"]["triggers"])
        assert any("not been contacted previously" in t for t in res["evidence"]["triggers"])

    def test_inf_zscore_handling(self):
        """First large burst with std=0 producing float('inf') z-score is safely handled."""
        inf_zscore_features = {
            "outbound_inbound_ratio": 20.0,
            "outbound_volume_zscore": float("inf"),
            "duration_bytes_ratio": 0.0001,
            "off_hours_flag": 0,
            "destination_novel": 1,
        }
        res = score_exfil(inf_zscore_features)

        assert res["confidence"] >= 0.70
        assert 0.0 <= res["confidence"] <= 1.0

    def test_all_detectors_expose_uniform_interface(self):
        """All detectors must return confidence in [0, 1], evidence dict, and model_version str."""
        d_out = score_ddos({})
        r_out = score_recon({})
        e_out = score_exfil({})

        for out in [d_out, r_out, e_out]:
            assert "confidence" in out
            assert isinstance(out["confidence"], float)
            assert 0.0 <= out["confidence"] <= 1.0
            assert "evidence" in out
            assert isinstance(out["evidence"], dict)
            assert "model_version" in out
            assert isinstance(out["model_version"], str)
