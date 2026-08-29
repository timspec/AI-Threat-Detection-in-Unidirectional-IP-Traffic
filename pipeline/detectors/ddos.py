"""
pipeline/detectors/ddos.py — DDoS Threat Detector.

Combines statistical/EWMA thresholding with a scikit-learn IsolationForest anomaly model.
Exposes:
  score(features: dict) -> {'confidence': float (0..1), 'evidence': dict, 'model_version': str}

NOTE: The IsolationForest is pre-fitted on a synthetic benign baseline generated via numpy
(placeholder for retraining on real lab capture datasets in Phase 3.3).
"""

from __future__ import annotations

import math
from typing import Any
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_VERSION = "ddos_hybrid_v1.0"

# Feature order used by the IsolationForest model
_IF_FEATURES = [
    "packets_per_sec",
    "bytes_per_sec",
    "syn_ack_ratio",
    "unique_src_per_sec",
    "src_ip_entropy",
    "protocol_mix_ratio",
    "half_open_count",
]


def _build_synthetic_benign_baseline(n_samples: int = 150, random_state: int = 42) -> np.ndarray:
    """Generate synthetic benign network traffic feature matrix for initial model training."""
    rng = np.random.RandomState(random_state)
    
    # Benign distribution approximations:
    # packets_per_sec: 1 to 100 pps
    pps = rng.uniform(1.0, 100.0, size=(n_samples, 1))
    # bytes_per_sec: 100 to 100,000 B/s
    bps = rng.uniform(100.0, 100_000.0, size=(n_samples, 1))
    # syn_ack_ratio: typically around 0.5 to 2.0
    syn_ack = rng.uniform(0.5, 2.0, size=(n_samples, 1))
    # unique_src_per_sec: 0.1 to 10.0
    unique_src_rate = rng.uniform(0.1, 10.0, size=(n_samples, 1))
    # src_ip_entropy: 0.0 to 3.0 bits
    entropy = rng.uniform(0.0, 3.0, size=(n_samples, 1))
    # protocol_mix_ratio: 0.3 to 1.0
    proto_mix = rng.uniform(0.3, 1.0, size=(n_samples, 1))
    # half_open_count: 0 to 5
    half_open = rng.randint(0, 5, size=(n_samples, 1)).astype(float)
    
    return np.hstack([pps, bps, syn_ack, unique_src_rate, entropy, proto_mix, half_open])


# Cached baseline model fitted once at module level
_baseline_model: IsolationForest | None = None


def _get_baseline_model() -> IsolationForest:
    """Return pre-fitted baseline IsolationForest instance."""
    global _baseline_model
    if _baseline_model is None:
        model = IsolationForest(
            n_estimators=20,
            contamination=0.01,
            random_state=42,
            n_jobs=1,
        )
        baseline_x = _build_synthetic_benign_baseline(n_samples=150)
        model.fit(baseline_x)
        _baseline_model = model
    return _baseline_model


class DDoSDetector:
    """DDoS detector combining rule/EWMA thresholds with IsolationForest anomaly scoring."""

    def __init__(
        self,
        pps_threshold: float = 500.0,
        bps_threshold: float = 1_000_000.0,
        syn_ack_threshold: float = 5.0,
        entropy_threshold: float = 4.0,
        half_open_threshold: int = 20,
        alpha_ewma: float = 0.3,
    ) -> None:
        self.pps_threshold = pps_threshold
        self.bps_threshold = bps_threshold
        self.syn_ack_threshold = syn_ack_threshold
        self.entropy_threshold = entropy_threshold
        self.half_open_threshold = half_open_threshold
        self.alpha_ewma = alpha_ewma
        self.ewma_pps: float | None = None
        self._model: IsolationForest | None = None

    @property
    def model(self) -> IsolationForest:
        if self._model is None:
            self._model = _get_baseline_model()
        return self._model

    def score(self, features: dict[str, Any]) -> dict[str, Any]:
        """Score DDoS likelihood for the given feature dictionary."""
        pps = float(features.get("packets_per_sec", 0.0))
        bps = float(features.get("bytes_per_sec", 0.0))
        syn_ack = float(features.get("syn_ack_ratio", 0.0))
        unique_src = int(features.get("unique_src_count", 0))
        unique_src_rate = float(features.get("unique_src_per_sec", 0.0))
        entropy = float(features.get("src_ip_entropy", 0.0))
        proto_mix = float(features.get("protocol_mix_ratio", 0.0))
        half_open = int(features.get("half_open_count", 0))

        # Update EWMA for packet rate
        if self.ewma_pps is None:
            self.ewma_pps = pps
        else:
            self.ewma_pps = self.alpha_ewma * pps + (1.0 - self.alpha_ewma) * self.ewma_pps

        # ── 1. Statistical & Rule threshold checks ──────────────────────────
        triggers = []
        rule_score = 0.0

        if pps >= self.pps_threshold or self.ewma_pps >= self.pps_threshold:
            ratio = max(pps, self.ewma_pps) / self.pps_threshold
            rule_score += min(0.4 * (ratio / 2.0), 0.4)
            triggers.append(f"High packet rate (pps={pps:.1f}, ewma={self.ewma_pps:.1f})")

        if bps >= self.bps_threshold:
            ratio = bps / self.bps_threshold
            rule_score += min(0.3 * (ratio / 2.0), 0.3)
            triggers.append(f"High byte volume (bps={bps:.0f})")

        if syn_ack >= self.syn_ack_threshold:
            rule_score += 0.25
            triggers.append(f"SYN flood indicator (SYN:ACK={syn_ack:.2f})")

        if entropy >= self.entropy_threshold and unique_src >= 20:
            rule_score += 0.25
            triggers.append(f"High source IP dispersion/entropy ({entropy:.2f} bits, {unique_src} IPs)")

        if half_open >= self.half_open_threshold:
            rule_score += 0.2
            triggers.append(f"High half-open connections count ({half_open})")

        rule_score = min(rule_score, 1.0)

        # ── 2. Isolation Forest Anomaly Score ─────────────────────────────────
        x = np.array([[pps, bps, syn_ack, unique_src_rate, entropy, proto_mix, float(half_open)]])
        # decision_function: positive for inliers (normal), negative for anomalies
        dec = float(self.model.decision_function(x)[0])
        if dec >= 0.0:
            if_confidence = max(0.0, 0.10 - dec * 0.5)
        elif dec >= -0.08:
            # Borderline benign variation
            if_confidence = 0.10 + (abs(dec) / 0.08) * 0.15
        else:
            # Genuine outlier anomaly
            if_confidence = min(0.95, 0.5 + abs(dec) * 1.5)

        # ── 3. Combined Confidence ───────────────────────────────────────────
        if rule_score > 0.0:
            confidence = max(rule_score, 0.7 * rule_score + 0.3 * if_confidence)
        else:
            # When zero rule triggers fired, cap baseline variation to low confidence
            confidence = min(0.20, if_confidence) if if_confidence < 0.50 else if_confidence

        confidence = float(np.clip(confidence, 0.0, 1.0))

        evidence = {
            "triggers": triggers,
            "rule_confidence": round(rule_score, 4),
            "if_anomaly_confidence": round(if_confidence, 4),
            "ewma_pps": round(self.ewma_pps, 2),
            "pps": pps,
            "bps": bps,
            "syn_ack_ratio": syn_ack,
            "src_ip_entropy": entropy,
            "half_open_count": half_open,
        }

        return {
            "confidence": round(confidence, 4),
            "evidence": evidence,
            "model_version": MODEL_VERSION,
        }


def score(features: dict[str, Any]) -> dict[str, Any]:
    """Score DDoS likelihood for features dict using a fresh detector instance."""
    return DDoSDetector().score(features)
