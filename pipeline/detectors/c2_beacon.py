"""
pipeline/detectors/c2_beacon.py — Botnet C2 Beaconing Detector.

Combines FFT periodicity scores and IAT statistical metrics with a scikit-learn
RandomForestClassifier trained on synthetic labeled examples.

Exposes:
  score(features: dict) -> {'confidence': float (0..1), 'evidence': dict, 'model_version': str}

NOTE:
# TRAINED ON SYNTHETIC PLACEHOLDER DATA — replace with real lab captures before reporting final precision/recall numbers.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

MODEL_VERSION = "c2_beacon_rf_v1.0"
MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "c2_beacon.joblib"

_FEATURE_KEYS = [
    "iat_mean",
    "iat_cv",
    "periodicity_score",
    "dst_cardinality",
    "session_duration_cv",
    "byte_size_cv",
]


def _generate_synthetic_c2_training_data(
    n_per_class: int = 150,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic labeled dataset for beaconing vs benign traffic."""
    rng = np.random.RandomState(random_state)

    # ── Class 0: Benign / Normal Irregular Traffic ────────────────────
    b_iat_mean = rng.uniform(0.1, 30.0, size=(n_per_class, 1))
    b_iat_cv = rng.uniform(0.5, 2.5, size=(n_per_class, 1))
    b_periodicity = rng.uniform(0.0, 0.25, size=(n_per_class, 1))
    b_dst_card = rng.uniform(3.0, 40.0, size=(n_per_class, 1))
    b_dur_cv = rng.uniform(0.4, 2.0, size=(n_per_class, 1))
    b_byte_cv = rng.uniform(0.4, 1.8, size=(n_per_class, 1))
    x_benign = np.hstack([b_iat_mean, b_iat_cv, b_periodicity, b_dst_card, b_dur_cv, b_byte_cv])
    y_benign = np.zeros(n_per_class, dtype=int)

    # ── Class 1: C2 Beacon Traffic (Regular timing, low CV, fixed dst) ─
    m_iat_mean = rng.uniform(5.0, 120.0, size=(n_per_class, 1))
    m_iat_cv = rng.uniform(0.0, 0.15, size=(n_per_class, 1))
    m_periodicity = rng.uniform(0.45, 0.98, size=(n_per_class, 1))
    m_dst_card = rng.uniform(1.0, 2.0, size=(n_per_class, 1))
    m_dur_cv = rng.uniform(0.0, 0.15, size=(n_per_class, 1))
    m_byte_cv = rng.uniform(0.0, 0.2, size=(n_per_class, 1))
    x_beacon = np.hstack([m_iat_mean, m_iat_cv, m_periodicity, m_dst_card, m_dur_cv, m_byte_cv])
    y_beacon = np.ones(n_per_class, dtype=int)

    x = np.vstack([x_benign, x_beacon])
    y = np.concatenate([y_benign, y_beacon])
    return x, y


def _get_or_train_model() -> RandomForestClassifier:
    """Load cached model from disk or auto-train and persist on first run."""
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass

    # TRAINED ON SYNTHETIC PLACEHOLDER DATA — replace with real lab captures before reporting final precision/recall numbers.
    x_train, y_train = _generate_synthetic_c2_training_data()
    clf = RandomForestClassifier(
        n_estimators=30,
        max_depth=5,
        random_state=42,
        n_jobs=1,
    )
    clf.fit(x_train, y_train)

    # Persist model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        joblib.dump(clf, MODEL_PATH)
    except Exception:
        pass

    return clf


class C2BeaconDetector:
    """RandomForest + rule-assisted C2 beaconing threat detector."""

    def __init__(self) -> None:
        self.model = _get_or_train_model()

    def score(self, features: dict[str, Any]) -> dict[str, Any]:
        """Score C2 beaconing likelihood from extracted features."""
        iat_mean = float(features.get("iat_mean", 0.0))
        iat_cv = float(features.get("iat_cv", 0.0))
        periodicity = float(features.get("periodicity_score", 0.0))
        dst_card = int(features.get("dst_cardinality", 0))
        dur_cv = float(features.get("session_duration_cv", 0.0))
        byte_cv = float(features.get("byte_size_cv", 0.0))

        # ── 1. Machine Learning Probability ──────────────────────────────────
        x = np.array([[iat_mean, iat_cv, periodicity, float(dst_card), dur_cv, byte_cv]])
        rf_prob = float(self.model.predict_proba(x)[0][1])

        # ── 2. Rule & Heuristic Triggers ─────────────────────────────────────
        triggers = []
        rule_boost = 0.0

        if periodicity >= 0.5:
            triggers.append(f"Strong temporal periodicity detected (score={periodicity:.2f})")
            rule_boost += 0.2

        if iat_cv <= 0.15 and iat_mean >= 1.0:
            triggers.append(f"Fixed inter-arrival timing (CV={iat_cv:.2f}, interval={iat_mean:.1f}s)")
            rule_boost += 0.2

        if dst_card == 1 and (periodicity >= 0.4 or iat_cv <= 0.2):
            triggers.append("Persistent isolated communication to single destination")
            rule_boost += 0.1

        if byte_cv <= 0.1 and (periodicity >= 0.4 or iat_cv <= 0.2):
            triggers.append(f"Highly uniform payload size distribution (byte CV={byte_cv:.2f})")
            rule_boost += 0.1

        # ── 3. Combined Confidence ───────────────────────────────────────────
        confidence = max(rf_prob, 0.7 * rf_prob + 0.3 * rule_boost)
        # Cap confidence low if periodicity is negligible and timing is irregular
        if periodicity < 0.15 and iat_cv > 0.5:
            confidence = min(confidence, 0.25)

        confidence = float(np.clip(confidence, 0.0, 1.0))

        evidence = {
            "triggers": triggers,
            "rf_probability": round(rf_prob, 4),
            "periodicity_score": round(periodicity, 4),
            "iat_mean_seconds": round(iat_mean, 2),
            "iat_cv": round(iat_cv, 4),
            "dst_cardinality": dst_card,
            "byte_size_cv": round(byte_cv, 4),
        }

        return {
            "confidence": round(confidence, 4),
            "evidence": evidence,
            "model_version": MODEL_VERSION,
        }


# Default singleton instance
_default_c2_detector = C2BeaconDetector()


def score(features: dict[str, Any]) -> dict[str, Any]:
    """Score C2 beacon likelihood for features dict."""
    return _default_c2_detector.score(features)
