"""
tests/test_detectors_ml.py — Unit tests for ML-flavored threat detectors.

Covers:
  1. C2 Beacon Detector (FFT periodicity + RandomForest classifier)
  2. DGA / DNS Tunnelling Detector (Lexical n-grams + RandomForest classifier)
  3. Encrypted Malware Detector (JA3 denylist + Sequence IsolationForest)
  4. Auto-train model persistence verification (.joblib in models/)
  5. Uniform detector interface verification
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from pipeline.detectors.c2_beacon import (
    C2BeaconDetector,
    score as score_c2,
    MODEL_PATH as C2_MODEL_PATH,
)
from pipeline.detectors.dga_dns import (
    DGADNSDetector,
    score as score_dga,
    MODEL_PATH as DGA_MODEL_PATH,
)
from pipeline.detectors.encrypted_malware import (
    EncryptedMalwareDetector,
    score as score_encrypted,
    MODEL_PATH as ENC_MODEL_PATH,
)
from pipeline.features.encrypted_malware import KNOWN_BAD_JA3


# ═══════════════════════════════════════════════════════════════════════════
# 1. C2 Beacon Detector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestC2BeaconDetector:

    def test_benign_irregular_session_scores_low(self):
        """Irregular web surfing or random API calls must produce low confidence."""
        benign_features = {
            "iat_mean": 4.2,
            "iat_variance": 18.5,
            "iat_cv": 1.2,
            "periodicity_score": 0.08,
            "dst_cardinality": 15,
            "session_duration_mean": 2.5,
            "session_duration_cv": 0.95,
            "byte_size_cv": 1.1,
        }
        res = score_c2(benign_features)

        assert "confidence" in res
        assert "evidence" in res
        assert 0.0 <= res["confidence"] <= 0.30, f"Expected low confidence, got {res['confidence']}"

    def test_periodic_c2_beacon_scores_high(self):
        """Fixed 30s interval beacon to single C2 server must produce high confidence."""
        c2_features = {
            "iat_mean": 30.0,
            "iat_variance": 0.1,
            "iat_cv": 0.02,
            "periodicity_score": 0.88,
            "dst_cardinality": 1,
            "session_duration_mean": 0.5,
            "session_duration_cv": 0.05,
            "byte_size_cv": 0.03,
        }
        res = score_c2(c2_features)

        assert res["confidence"] >= 0.75, f"Expected high confidence, got {res['confidence']}"
        assert any("periodicity" in t.lower() for t in res["evidence"]["triggers"])

    def test_model_persistence(self):
        """Model must be saved to disk as a .joblib file."""
        assert C2_MODEL_PATH.exists()


# ═══════════════════════════════════════════════════════════════════════════
# 2. DGA / DNS Tunnelling Detector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestDGADNSDetector:

    def test_benign_domain_scores_low(self):
        """Natural domains like google.com or wikipedia.org must score low."""
        res_google = score_dga("google.com")
        res_wiki = score_dga("wikipedia.org")

        assert res_google["confidence"] <= 0.30, f"Got {res_google['confidence']} for google.com"
        assert res_wiki["confidence"] <= 0.30, f"Got {res_wiki['confidence']} for wikipedia.org"

    def test_dga_domain_scores_high(self):
        """Gibberish / algorithmically generated domains must score high."""
        res_dga1 = score_dga("kq3xzv9f2j.com")
        res_dga2 = score_dga("qzxjvwkrmn78.top")

        assert res_dga1["confidence"] >= 0.70, f"Got {res_dga1['confidence']} for DGA 1"
        assert res_dga2["confidence"] >= 0.70, f"Got {res_dga2['confidence']} for DGA 2"
        assert len(res_dga1["evidence"]["triggers"]) > 0

    def test_dns_tunnel_aggregate_features_score_high(self):
        """Aggregate DNS tunnelling characteristics (high TXT ratio, subdomains) score high."""
        tunnel_features = {
            "mean_entropy": 3.8,
            "mean_ngram_score": -18.5,
            "mean_digit_ratio": 0.35,
            "mean_label_length": 35.0,
            "txt_null_ratio": 0.90,
            "unique_subdomains_per_apex": 45.0,
            "query_rate": 15.0,
        }
        res = score_dga(tunnel_features)

        assert res["confidence"] >= 0.80
        assert any("TXT/NULL" in t for t in res["evidence"]["triggers"])
        assert any("subdomain" in t.lower() for t in res["evidence"]["triggers"])

    def test_model_persistence(self):
        """DGA model must be saved to disk as a .joblib file."""
        assert DGA_MODEL_PATH.exists()


# ═══════════════════════════════════════════════════════════════════════════
# 3. Encrypted Malware Detector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestEncryptedMalwareDetector:

    def test_benign_tls_session_scores_low(self):
        """Standard browser TLS handshake with inlier size/timing must score low."""
        benign_tls = {
            "ja3_hash": "b32309a26951912be7dba376398abcde",
            "sni": "www.cloudflare.com",
            "cipher_suite_count": 22,
            "extension_count": 12,
            "pkt_size_mean": 520.0,
            "pkt_size_std": 220.0,
            "pkt_ipt_mean": 0.08,
            "pkt_ipt_std": 0.05,
        }
        res = score_encrypted(benign_tls)

        assert res["confidence"] <= 0.30, f"Expected low confidence, got {res['confidence']}"
        assert res["evidence"]["ja3_threat_match"] == ""

    def test_known_bad_ja3_scores_instant_high(self):
        """Known malware JA3 hash (e.g. Cobalt Strike) must trigger instant high confidence."""
        cobalt_ja3 = list(KNOWN_BAD_JA3.keys())[1]  # Cobalt Strike profile
        malware_features = {
            "ja3_hash": cobalt_ja3,
            "sni": "c2.evil-corp.net",
            "cipher_suite_count": 8,
            "extension_count": 4,
        }
        res = score_encrypted(malware_features)

        assert res["confidence"] >= 0.95
        assert "Cobalt Strike" in res["evidence"]["ja3_threat_match"]
        assert any("denylist" in t for t in res["evidence"]["triggers"])

    def test_sparse_anomalous_handshake_scores_high(self):
        """Suspiciously minimal TLS handshake (e.g., custom C2 client with 1 cipher) triggers warning."""
        sparse_features = {
            "ja3_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sni": "",
            "cipher_suite_count": 1,
            "extension_count": 0,
            "pkt_size_mean": 2500.0,
            "pkt_size_std": 0.0,
            "pkt_ipt_mean": 1.5,
            "pkt_ipt_std": 0.0,
        }
        res = score_encrypted(sparse_features)

        assert res["confidence"] >= 0.70
        assert any("sparse" in t.lower() or "anomalous" in t.lower() for t in res["evidence"]["triggers"])

    def test_model_persistence(self):
        """Encrypted malware model must be saved to disk as a .joblib file."""
        assert ENC_MODEL_PATH.exists()


# ═══════════════════════════════════════════════════════════════════════════
# 4. Uniform Schema Test Across All ML Detectors
# ═══════════════════════════════════════════════════════════════════════════

class TestMLDetectorsSchema:

    def test_all_ml_detectors_expose_uniform_interface(self):
        """All detectors must return confidence in [0, 1], evidence dict, and model_version str."""
        c2_out = score_c2({})
        dga_out = score_dga({})
        enc_out = score_encrypted({})

        for out in [c2_out, dga_out, enc_out]:
            assert "confidence" in out
            assert isinstance(out["confidence"], float)
            assert 0.0 <= out["confidence"] <= 1.0
            assert "evidence" in out
            assert isinstance(out["evidence"], dict)
            assert "model_version" in out
            assert isinstance(out["model_version"], str)
