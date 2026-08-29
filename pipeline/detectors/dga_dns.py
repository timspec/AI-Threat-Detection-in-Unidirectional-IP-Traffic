"""
pipeline/detectors/dga_dns.py — DGA Domain & DNS Tunnelling Detector.

Uses a scikit-learn RandomForestClassifier trained on character n-gram statistics,
Shannon entropy, and lexical composition features of ~200 benign domain labels vs ~200
synthetic DGA-like domains. Also incorporates DNS tunnelling heuristic indicators.

Exposes:
  score(features: dict) -> {'confidence': float (0..1), 'evidence': dict, 'model_version': str}

NOTE:
# TRAINED ON SYNTHETIC PLACEHOLDER DATA — replace with real lab captures before reporting final precision/recall numbers.
"""

from __future__ import annotations

import os
from pathlib import Path
import random
import string
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from pipeline.features.dga_dns import _CORPUS_WORDS, score_domain

MODEL_VERSION = "dga_dns_rf_v1.0"
MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "dga_dns.joblib"


def _generate_synthetic_dga_labels(count: int = 200, seed: int = 42) -> list[str]:
    """Generate algorithmically generated domain (DGA) label strings."""
    rng = random.Random(seed)
    consonants = "bcdfghjklmnpqrstvwxyz"
    alphanumeric = string.ascii_lowercase + string.digits
    dgas = []

    for _ in range(count):
        dga_type = rng.choice(["random_alnum", "consonant_cluster", "hex_hash"])
        length = rng.randint(8, 20)

        if dga_type == "random_alnum":
            label = "".join(rng.choice(alphanumeric) for _ in range(length))
        elif dga_type == "consonant_cluster":
            label = "".join(rng.choice(consonants) for _ in range(length))
        else:  # hex_hash
            label = "".join(rng.choice("0123456789abcdef") for _ in range(length))

        dgas.append(label)

    return dgas


def _extract_feature_vector(domain_or_features: dict | str) -> np.ndarray:
    """Extract numeric feature vector [entropy, ngram_score, digit_ratio, consonant_ratio, label_length]."""
    if isinstance(domain_or_features, str):
        scored = score_domain(domain_or_features)
    elif "entropy" in domain_or_features:
        scored = domain_or_features
    elif "mean_entropy" in domain_or_features:
        # Aggregate DNS features mapped to representative vector
        return np.array([
            float(domain_or_features.get("mean_entropy", 0.0)),
            float(domain_or_features.get("mean_ngram_score", -15.0)),
            float(domain_or_features.get("mean_digit_ratio", 0.0)),
            0.6,
            float(domain_or_features.get("mean_label_length", 10.0)),
        ])
    else:
        scored = score_domain(str(domain_or_features.get("qname", "example.com")))

    return np.array([
        float(scored.get("entropy", 0.0)),
        float(scored.get("ngram_score", 0.0)),
        float(scored.get("digit_ratio", 0.0)),
        float(scored.get("consonant_ratio", 0.0)),
        float(scored.get("label_length", 0)),
    ])


def _build_dga_training_data() -> tuple[np.ndarray, np.ndarray]:
    """Extract features for benign wordlist vs synthetic DGA labels."""
    benign_labels = _CORPUS_WORDS[:200]
    dga_labels = _generate_synthetic_dga_labels(count=200)

    x_benign = np.array([_extract_feature_vector(w) for w in benign_labels])
    y_benign = np.zeros(len(benign_labels), dtype=int)

    x_dga = np.array([_extract_feature_vector(d) for d in dga_labels])
    y_dga = np.ones(len(dga_labels), dtype=int)

    x = np.vstack([x_benign, x_dga])
    y = np.concatenate([y_benign, y_dga])
    return x, y


def _get_or_train_model() -> RandomForestClassifier:
    """Load cached DGA model from disk or train and persist on first run."""
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass

    # TRAINED ON SYNTHETIC PLACEHOLDER DATA — replace with real lab captures before reporting final precision/recall numbers.
    x_train, y_train = _build_dga_training_data()
    clf = RandomForestClassifier(
        n_estimators=30,
        max_depth=5,
        random_state=42,
        n_jobs=1,
    )
    clf.fit(x_train, y_train)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        joblib.dump(clf, MODEL_PATH)
    except Exception:
        pass

    return clf


class DGADNSDetector:
    """RandomForest + heuristic detector for DGA domains and DNS tunnelling."""

    def __init__(self) -> None:
        self.model = _get_or_train_model()

    def score(self, features: dict[str, Any] | str) -> dict[str, Any]:
        """Score DGA / DNS tunnelling likelihood from features dict or domain string."""
        if isinstance(features, str):
            feat_dict = score_domain(features)
        else:
            feat_dict = features

        x = _extract_feature_vector(feat_dict).reshape(1, -1)
        rf_prob = float(self.model.predict_proba(x)[0][1])

        triggers = []
        rule_boost = 0.0

        # Per-domain metrics
        entropy = float(feat_dict.get("entropy", feat_dict.get("mean_entropy", 0.0)))
        ngram = float(feat_dict.get("ngram_score", feat_dict.get("mean_ngram_score", 0.0)))
        digit_ratio = float(feat_dict.get("digit_ratio", feat_dict.get("mean_digit_ratio", 0.0)))

        # Aggregate DNS tunnelling metrics (if present)
        txt_null_ratio = float(feat_dict.get("txt_null_ratio", 0.0))
        subs_per_apex = float(feat_dict.get("unique_subdomains_per_apex", 0.0))
        qrate = float(feat_dict.get("query_rate", 0.0))

        if entropy >= 3.2:
            triggers.append(f"High lexical Shannon entropy ({entropy:.2f} bits)")
            rule_boost += 0.25

        if ngram <= -16.0:
            triggers.append(f"Low natural character n-gram likelihood (score={ngram:.2f})")
            rule_boost += 0.25

        if digit_ratio >= 0.3:
            triggers.append(f"High digit density in domain label ({digit_ratio:.1%})")
            rule_boost += 0.2

        if txt_null_ratio >= 0.5:
            triggers.append(f"High anomalous TXT/NULL query ratio ({txt_null_ratio:.1%})")
            rule_boost += 0.35

        if subs_per_apex >= 10.0:
            triggers.append(f"High subdomain fan-out under single apex ({subs_per_apex:.1f} subdomains)")
            rule_boost += 0.35

        # ── Combined Confidence ───────────────────────────────────────────
        confidence = max(rf_prob, 0.6 * rf_prob + 0.4 * rule_boost)
        if entropy < 2.5 and ngram > -14.0 and txt_null_ratio == 0.0 and subs_per_apex < 2.0:
            confidence = min(confidence, 0.2)

        confidence = float(np.clip(confidence, 0.0, 1.0))

        evidence = {
            "triggers": triggers,
            "rf_probability": round(rf_prob, 4),
            "entropy": round(entropy, 4),
            "ngram_score": round(ngram, 4),
            "digit_ratio": round(digit_ratio, 4),
            "txt_null_ratio": round(txt_null_ratio, 4),
            "subdomains_per_apex": round(subs_per_apex, 2),
            "query_rate": round(qrate, 2),
        }

        return {
            "confidence": round(confidence, 4),
            "evidence": evidence,
            "model_version": MODEL_VERSION,
        }


# Default singleton instance
_default_dga_detector = DGADNSDetector()


def score(features: dict[str, Any] | str) -> dict[str, Any]:
    """Score DGA / DNS tunnelling likelihood."""
    return _default_dga_detector.score(features)
