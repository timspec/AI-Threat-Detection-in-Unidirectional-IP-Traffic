"""
pipeline/detectors/exfiltration.py — Data Exfiltration Threat Detector.

Combines rule thresholds with statistical rolling z-score baseline analysis,
off-hours activity flags, destination novelty, and asymmetric outbound ratios.

Exposes:
  score(features: dict) -> {'confidence': float (0..1), 'evidence': dict, 'model_version': str}
"""

from __future__ import annotations

import math
from typing import Any
import numpy as np

MODEL_VERSION = "exfil_stat_v1.0"


class ExfiltrationDetector:
    """Statistical & rule-based data exfiltration detector."""

    def __init__(
        self,
        zscore_threshold: float = 3.0,
        outbound_ratio_threshold: float = 5.0,
        burst_ratio_threshold: float = 0.001,  # Low duration / high bytes
    ) -> None:
        self.zscore_threshold = zscore_threshold
        self.outbound_ratio_threshold = outbound_ratio_threshold
        self.burst_ratio_threshold = burst_ratio_threshold

    def score(self, features: dict[str, Any]) -> dict[str, Any]:
        """Score exfiltration likelihood from extracted exfil features."""
        out_in_ratio = float(features.get("outbound_inbound_ratio", 0.0))
        zscore = float(features.get("outbound_volume_zscore", 0.0))
        dur_bytes_ratio = float(features.get("duration_bytes_ratio", 0.0))
        off_hours = int(features.get("off_hours_flag", 0))
        dest_novel = int(features.get("destination_novel", 0))

        triggers = []
        confidence_accum = 0.0

        # Handle math.isinf / nan zscore
        if math.isinf(zscore) or zscore > 50.0:
            effective_z = 10.0
        elif math.isnan(zscore):
            effective_z = 0.0
        else:
            effective_z = zscore

        # ── 1. Statistical Volume Outlier (Rolling Z-Score) ───────────────────
        if effective_z >= self.zscore_threshold:
            # Scale from 0.4 at z=3 to 0.8 at z>=8
            z_conf = min(0.4 + 0.08 * (effective_z - self.zscore_threshold), 0.8)
            confidence_accum += z_conf
            triggers.append(f"Statistically anomalous outbound volume (z-score={zscore:.2f})")

        # ── 2. Asymmetric Outbound/Inbound Ratio ──────────────────────────────
        if out_in_ratio >= self.outbound_ratio_threshold:
            ratio_conf = min(0.25 * (out_in_ratio / self.outbound_ratio_threshold), 0.4)
            confidence_accum += ratio_conf
            triggers.append(f"Highly asymmetric outbound ratio (out/in={out_in_ratio:.2f})")

        # ── 3. Off-Hours Activity Multiplier ──────────────────────────────────
        if off_hours == 1 and (effective_z >= 2.0 or out_in_ratio >= 3.0):
            confidence_accum += 0.2
            triggers.append("Outbound transfer occurred outside standard business hours")

        # ── 4. Novel Destination Host ─────────────────────────────────────────
        if dest_novel == 1 and (effective_z >= 2.0 or out_in_ratio >= 3.0):
            confidence_accum += 0.15
            triggers.append("Destination endpoint has not been contacted previously by this source")

        # ── 5. High-throughput Burst (Low duration / bytes ratio) ─────────────
        if 0 < dur_bytes_ratio < self.burst_ratio_threshold and out_in_ratio >= 2.0:
            confidence_accum += 0.15
            triggers.append(f"High-throughput burst transfer (dur/bytes={dur_bytes_ratio:.6f})")

        # Clamp confidence to [0.0, 1.0]
        confidence = float(np.clip(confidence_accum, 0.0, 1.0))

        evidence = {
            "triggers": triggers,
            "outbound_volume_zscore": round(effective_z, 4),
            "outbound_inbound_ratio": round(out_in_ratio, 4),
            "duration_bytes_ratio": round(dur_bytes_ratio, 6),
            "off_hours_flag": off_hours,
            "destination_novel": dest_novel,
        }

        return {
            "confidence": round(confidence, 4),
            "evidence": evidence,
            "model_version": MODEL_VERSION,
        }


# Default detector instance
_default_exfil_detector = ExfiltrationDetector()


def score(features: dict[str, Any]) -> dict[str, Any]:
    """Score exfiltration likelihood for features dict using default detector instance."""
    return _default_exfil_detector.score(features)
