"""
pipeline/aggregator/aggregator.py — Alert Aggregator & De-duplicator.

Responsibilities:
  1. De-duplicates alerts on the same flow or endpoint within a sliding window (default 30s).
  2. Computes weighted severity score = confidence × threat_class_risk_weight.
  3. Maps continuous severity score to categorical severity (CRITICAL, HIGH, MEDIUM, LOW).
  4. Assembles canonical alert dict with all mandatory fields.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional

# Threat risk weights reflecting asset impact and urgency
DEFAULT_THREAT_WEIGHTS: dict[str, float] = {
    "exfiltration": 1.00,       # Highest risk: sensitive data exiting perimeter
    "c2_beacon": 0.95,          # Active foothold / botnet control
    "encrypted_malware": 0.90,  # Known malware TLS fingerprint
    "ddos": 0.90,               # Availability impact
    "dga_dns": 0.85,            # Covert communication channel
    "recon_scan": 0.65,         # Early reconnaissance / probing
}

# Severity categories by composite score [0.0, 1.0]
SEVERITY_THRESHOLDS = [
    (0.75, "CRITICAL"),
    (0.55, "HIGH"),
    (0.35, "MEDIUM"),
    (0.00, "LOW"),
]


def compute_severity(confidence: float, threat_class: str) -> tuple[str, float]:
    """Compute numeric severity score and categorical severity label."""
    weight = DEFAULT_THREAT_WEIGHTS.get(threat_class.lower(), 0.75)
    score = float(confidence * weight)

    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label, round(score, 4)

    return "LOW", round(score, 4)


class AlertAggregator:
    """Stateful alert de-duplicator and enricher.

    Parameters
    ----------
    dedup_window_seconds : float
        Time window during which duplicate alerts on the same (src_ip, dst_ip, threat_class)
        are suppressed or coalesced (default 30.0s).
    """

    def __init__(self, dedup_window_seconds: float = 30.0) -> None:
        self.dedup_window = dedup_window_seconds
        # key: (src_ip, dst_ip, threat_class) -> (last_alert_timestamp, alert_count)
        self._seen_alerts: OrderedDict[tuple[str, str, str], tuple[float, int]] = OrderedDict()
        self.total_raw_alerts: int = 0
        self.total_deduplicated_alerts: int = 0
        self.total_emitted_alerts: int = 0

    def process(self, raw_candidate: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Process a raw detector score candidate.

        Parameters
        ----------
        raw_candidate : dict
            Must contain at minimum:
              - 'confidence': float (0..1)
              - 'threat_class': str
              - 'flow': dict or flow fields (src_ip, dst_ip, etc.)
              - 'evidence': dict
              - 'model_version': str

        Returns
        -------
        dict or None
            Enriched alert dictionary if emitted, or None if suppressed as duplicate.
        """
        self.total_raw_alerts += 1
        confidence = float(raw_candidate.get("confidence", 0.0))

        # Filter out negligible confidence events (< 0.25)
        if confidence < 0.25:
            return None

        flow = raw_candidate.get("flow", {})
        threat_class = str(raw_candidate.get("threat_class", "unknown")).lower()
        src_ip = str(raw_candidate.get("src_ip", flow.get("src_ip", "0.0.0.0")))
        dst_ip = str(raw_candidate.get("dst_ip", flow.get("dst_ip", "0.0.0.0")))
        src_port = int(raw_candidate.get("src_port", flow.get("src_port", 0)))
        dst_port = int(raw_candidate.get("dst_port", flow.get("dst_port", 0)))
        proto = int(raw_candidate.get("proto", flow.get("protocol", 0)))
        flow_id = str(raw_candidate.get("flow_id", flow.get("flow_id", "unknown")))
        event_ts = float(raw_candidate.get("timestamp", flow.get("end_time", time.time())))

        # ── De-duplication Check ───────────────────────────────────────
        dedup_key = (src_ip, dst_ip, threat_class)
        now = event_ts if event_ts > 0 else time.time()

        if dedup_key in self._seen_alerts:
            last_ts, count = self._seen_alerts[dedup_key]
            if (now - last_ts) < self.dedup_window:
                self._seen_alerts[dedup_key] = (now, count + 1)
                self.total_deduplicated_alerts += 1
                return None  # Suppress duplicate

        # Record fresh alert in de-dup history
        self._seen_alerts[dedup_key] = (now, 1)
        self._cleanup_old_keys(now)

        # ── Compute Severity ───────────────────────────────────────────
        severity_label, severity_score = compute_severity(confidence, threat_class)

        # ── Assemble Canonical Alert Object ────────────────────────────
        alert_id = f"alert-{uuid.uuid4().hex[:12]}"
        alert = {
            "alert_id": alert_id,
            "timestamp": now,
            "flow_id": flow_id,
            "threat_class": threat_class,
            "confidence": round(confidence, 4),
            "severity": severity_label,
            "severity_score": severity_score,
            "evidence": raw_candidate.get("evidence", {}),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "model_version": str(raw_candidate.get("model_version", "v1.0")),
            "status": "NEW",
        }

        self.total_emitted_alerts += 1
        return alert

    def _cleanup_old_keys(self, now: float) -> None:
        """Prune old entries outside the de-duplication sliding window."""
        while self._seen_alerts:
            first_key, (first_ts, _) = next(iter(self._seen_alerts.items()))
            if (now - first_ts) > (self.dedup_window * 2):
                self._seen_alerts.pop(first_key)
            else:
                break
