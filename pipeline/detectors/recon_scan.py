"""
pipeline/detectors/recon_scan.py — Reconnaissance & Port/Host Scan Detector.

Pure rule-based detector that identifies horizontal host sweeps and vertical port scans.
Confidence scales proportionally with how far fan-out and scan rate exceed configurable thresholds.

Exposes:
  score(features: dict) -> {'confidence': float (0..1), 'evidence': dict, 'model_version': str}
"""

from __future__ import annotations

from typing import Any
import numpy as np

MODEL_VERSION = "recon_rule_v1.0"


class ReconScanDetector:
    """Rule-based reconnaissance scan detector."""

    def __init__(
        self,
        port_threshold: int = 15,
        host_threshold: int = 10,
        scan_rate_threshold: float = 5.0,
        syn_no_completion_threshold: float = 0.7,
        port_seq_threshold: float = 0.5,
    ) -> None:
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.scan_rate_threshold = scan_rate_threshold
        self.syn_no_completion_threshold = syn_no_completion_threshold
        self.port_seq_threshold = port_seq_threshold

    def score(self, features: dict[str, Any]) -> dict[str, Any]:
        """Score scan likelihood from extracted recon features."""
        dst_ports = int(features.get("unique_dst_ports", 0))
        dst_hosts = int(features.get("unique_dst_hosts", 0))
        syn_no_completion = float(features.get("syn_no_completion_ratio", 0.0))
        port_seq_score = float(features.get("port_sequence_score", 0.0))
        scan_rate = float(features.get("scan_rate", 0.0))

        triggers = []
        confidence_accum = 0.0

        # ── 1. Vertical Port Scan (single host, many ports) ──────────────────
        if dst_ports >= self.port_threshold:
            # Scale from 0.4 at threshold to 0.8 at 3x threshold
            ratio = dst_ports / self.port_threshold
            port_conf = min(0.4 + 0.2 * (ratio - 1.0), 0.8)
            confidence_accum = max(confidence_accum, port_conf)
            triggers.append(f"Vertical port scan (target ports={dst_ports}, threshold={self.port_threshold})")

        # ── 2. Horizontal Host Sweep (many hosts) ───────────────────────────
        if dst_hosts >= self.host_threshold:
            ratio = dst_hosts / self.host_threshold
            host_conf = min(0.4 + 0.2 * (ratio - 1.0), 0.8)
            confidence_accum = max(confidence_accum, host_conf)
            triggers.append(f"Horizontal host sweep (target hosts={dst_hosts}, threshold={self.host_threshold})")

        # ── 3. High Scan Rate Multiplier ────────────────────────────────────
        if scan_rate >= self.scan_rate_threshold and (dst_ports > 3 or dst_hosts > 3):
            rate_boost = min(0.15 * (scan_rate / self.scan_rate_threshold), 0.25)
            confidence_accum += rate_boost
            triggers.append(f"High probe rate ({scan_rate:.1f} flows/sec)")

        # ── 4. SYN Without Completion (Stealth/Half-open Scan) ───────────────
        if syn_no_completion >= self.syn_no_completion_threshold and (dst_ports > 5 or dst_hosts > 5):
            syn_boost = 0.2 * syn_no_completion
            confidence_accum += syn_boost
            triggers.append(f"High uncompleted SYN ratio ({syn_no_completion:.1%})")

        # ── 5. Sequential Port Pattern (e.g. Nmap sequential scan) ───────────
        if port_seq_score >= self.port_seq_threshold and dst_ports >= 5:
            seq_boost = 0.15 * port_seq_score
            confidence_accum += seq_boost
            triggers.append(f"Sequential port probing pattern (score={port_seq_score:.2f})")

        # Bound confidence strictly between 0.0 and 1.0
        confidence = float(np.clip(confidence_accum, 0.0, 1.0))

        evidence = {
            "triggers": triggers,
            "unique_dst_ports": dst_ports,
            "unique_dst_hosts": dst_hosts,
            "syn_no_completion_ratio": round(syn_no_completion, 4),
            "port_sequence_score": round(port_seq_score, 4),
            "scan_rate": round(scan_rate, 2),
        }

        return {
            "confidence": round(confidence, 4),
            "evidence": evidence,
            "model_version": MODEL_VERSION,
        }


# Default detector instance
_default_recon_detector = ReconScanDetector()


def score(features: dict[str, Any]) -> dict[str, Any]:
    """Score recon scan likelihood for features dict using the default detector instance."""
    return _default_recon_detector.score(features)
