"""
pipeline/orchestrator.py — Unidirectional End-to-End Pipeline Orchestrator.

Wires the complete passive network security monitoring pipeline:
  1. Ingestion (Live Capture or PCAP Replay)
  2. Bidirectional Flow Builder (5-tuple aggregation with 1s ticks)
  3. Priority Event Queue (buffer with DDoS/scan high-priority retention)
  4. 6 Parallel Threat Detector Workers (asyncio concurrent scoring)
  5. Alert Aggregator (30s window de-duplication & severity ranking)
  6. SQLite Storage (Flows, Features, Alerts)

Enforces the strict ONE-WAY guarantee:
  • All ingest and processing components are purely receive/read-only.
  • Zero feedback or response packets are ever transmitted onto the network.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Callable, Optional

# Suppress harmless scikit-learn thread-pool configuration notices
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="joblib.*")

from pipeline.aggregator import AlertAggregator
from pipeline.features.c2_beacon import extract_c2_features
from pipeline.features.ddos import extract_ddos_features
from pipeline.features.dga_dns import extract_dns_features
from pipeline.features.encrypted_malware import (
    extract_encrypted_features,
    parse_client_hello,
)
from pipeline.features.exfiltration import ExfiltrationExtractor
from pipeline.features.recon_scan import extract_recon_features
from pipeline.flow.flow_builder import FlowBuilder
from pipeline.ingest.pcap_replay import replay_pcap
from pipeline.queue import (
    HIGH_PRIORITY_CLASSES,
    PRIORITY_HIGH,
    PRIORITY_LOW,
    PriorityEventQueue,
)
from storage.db import init_db, save_alert, save_flow

# Threat Detectors
import pipeline.detectors.ddos as ddos_detector
import pipeline.detectors.c2_beacon as c2_detector
import pipeline.detectors.dga_dns as dga_detector
import pipeline.detectors.encrypted_malware as enc_detector
import pipeline.detectors.recon_scan as recon_detector
import pipeline.detectors.exfiltration as exfil_detector

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """Master asynchronous orchestrator coordinating all pipeline stages."""

    def __init__(
        self,
        queue_maxsize: int = 10_000,
        dedup_window_seconds: float = 30.0,
        alert_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        init_db()
        self.queue: PriorityEventQueue[dict[str, Any]] = PriorityEventQueue(maxsize=queue_maxsize)
        self.aggregator = AlertAggregator(dedup_window_seconds=dedup_window_seconds)
        self.exfil_extractor = ExfiltrationExtractor()
        self.alert_callback = alert_callback

        self._running = False
        self._shutdown_event = asyncio.Event()

        # Telemetry metrics
        self.total_packets_seen: int = 0
        self.total_flows_processed: int = 0
        self.total_alerts_emitted: int = 0

        # Flow Builder instance
        self.flow_builder = FlowBuilder(
            idle_timeout=15.0,
            active_timeout=300.0,
            tick_interval=1.0,
            on_flow_event=self._on_flow_event,
        )

        # Recent packet history cache for feature extraction
        self._packet_history: dict[str, list[dict[str, Any]]] = {}

    def _on_flow_event(self, flow_event: dict[str, Any]) -> None:
        """Callback invoked when FlowBuilder emits a tick or expired flow event."""
        self.total_flows_processed += 1
        save_flow(flow_event)

        flow_id = flow_event.get("flow_id", "")
        flow_pkts = self._packet_history.get(flow_id, [])

        # ── Feature Extraction for all 6 Threat Classes ──────────────
        ddos_feats = extract_ddos_features([flow_event], packets=flow_pkts)
        c2_feats = extract_c2_features([flow_event], packets=flow_pkts)
        recon_feats = extract_recon_features([flow_event], packets=flow_pkts)
        exfil_feats = self.exfil_extractor.extract(flow_event)

        dns_queries = [
            {"qname": p["dns_qname"], "qtype": p["dns_qtype"], "timestamp": p["timestamp"]}
            for p in flow_pkts if p.get("dns_qname")
        ]
        dns_feats = extract_dns_features(dns_queries) if dns_queries else {}

        tls_pkts = [p["tls_raw"] for p in flow_pkts if p.get("tls_raw")]
        ch = parse_client_hello(tls_pkts[0]) if tls_pkts else None
        enc_feats = extract_encrypted_features(flow_event, client_hello=ch, packets=flow_pkts)

        event_payload = {
            "flow": flow_event,
            "packets": flow_pkts,
            "ddos_features": ddos_feats,
            "c2_features": c2_feats,
            "recon_features": recon_feats,
            "exfil_features": exfil_feats,
            "dns_features": dns_feats,
            "encrypted_features": enc_feats,
            "timestamp": flow_event.get("end_time", time.time()),
        }

        # Fast DDoS / Recon rate check to assign high queue priority
        priority = PRIORITY_LOW
        if ddos_feats.get("packets_per_sec", 0) > 200.0 or recon_feats.get("scan_rate", 0) > 10.0:
            priority = PRIORITY_HIGH

        self.queue.put_nowait(event_payload, priority=priority, timestamp=flow_event.get("end_time", 0.0))

        # Clear expired packet history to bound memory usage
        if flow_event.get("event_type") == "expired":
            self._packet_history.pop(flow_id, None)

    def ingest_packet(self, pkt_dict: dict[str, Any]) -> None:
        """Feed a single raw packet dictionary into the flow builder."""
        self.total_packets_seen += 1

        # Retain last 30 packets per flow for feature extraction
        key_str = f"{pkt_dict['src_ip']}-{pkt_dict['dst_ip']}"
        if key_str not in self._packet_history:
            self._packet_history[key_str] = []
        if len(self._packet_history[key_str]) < 30:
            self._packet_history[key_str].append(pkt_dict)

        self.flow_builder.ingest_packet(pkt_dict)

    async def _detector_worker(self) -> None:
        """Worker task consuming feature events and running 6 parallel detectors."""
        while self._running or not self.queue.is_empty:
            try:
                event = await self.queue.get(timeout=0.2)
            except asyncio.TimeoutError:
                if not self._running and self.queue.is_empty:
                    break
                continue

            flow = event["flow"]

            # Run 6 detectors concurrently via asyncio.gather in a thread pool
            candidates = await asyncio.gather(
                asyncio.to_thread(self._score_ddos, event["ddos_features"], flow),
                asyncio.to_thread(self._score_c2, event["c2_features"], flow),
                asyncio.to_thread(self._score_recon, event["recon_features"], flow),
                asyncio.to_thread(self._score_exfil, event["exfil_features"], flow),
                asyncio.to_thread(self._score_dns, event["dns_features"], flow),
                asyncio.to_thread(self._score_encrypted, event["encrypted_features"], flow),
            )

            # Process candidates through Aggregator & Storage
            for cand in candidates:
                if cand and cand.get("confidence", 0.0) >= 0.25:
                    alert = self.aggregator.process(cand)
                    if alert:
                        self.total_alerts_emitted += 1
                        save_alert(alert)
                        if self.alert_callback:
                            self.alert_callback(alert)
                        logger.warning(
                            "🚨 [THREAT DETECTED] %s | Severity=%s (score=%.2f) | Conf=%.2f | Flow=%s:%d -> %s:%d",
                            alert["threat_class"].upper(),
                            alert["severity"],
                            alert["severity_score"],
                            alert["confidence"],
                            alert["src_ip"],
                            alert["src_port"],
                            alert["dst_ip"],
                            alert["dst_port"],
                        )

    # ── Detector Invocation Wrappers ───────────────────────────────────

    def _score_ddos(self, features: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
        res = ddos_detector.score(features)
        return {**res, "threat_class": "ddos", "flow": flow}

    def _score_c2(self, features: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
        res = c2_detector.score(features)
        return {**res, "threat_class": "c2_beacon", "flow": flow}

    def _score_recon(self, features: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
        res = recon_detector.score(features)
        return {**res, "threat_class": "recon_scan", "flow": flow}

    def _score_exfil(self, features: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
        res = exfil_detector.score(features)
        return {**res, "threat_class": "exfiltration", "flow": flow}

    def _score_dns(self, features: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
        res = dga_detector.score(features)
        return {**res, "threat_class": "dga_dns", "flow": flow}

    def _score_encrypted(self, features: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
        res = enc_detector.score(features)
        return {**res, "threat_class": "encrypted_malware", "flow": flow}

    async def start(self) -> None:
        """Start the background detector processing workers."""
        self._running = True
        logger.info("Pipeline Orchestrator started with 6 concurrent detector workers.")
        self._worker_task = asyncio.create_task(self._detector_worker())

    async def stop(self) -> None:
        """Flush active flows and gracefully drain detector queue."""
        logger.info("Stopping Pipeline Orchestrator. Flushing active flows...")
        self.flow_builder.flush_all()
        self._running = False
        self.queue.signal_shutdown()
        if hasattr(self, "_worker_task"):
            try:
                await asyncio.wait_for(self._worker_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._worker_task.cancel()
        logger.info(
            "Orchestrator stopped. Processed %d packets, %d flows, emitted %d alerts.",
            self.total_packets_seen,
            self.total_flows_processed,
            self.total_alerts_emitted,
        )


# ═══════════════════════════════════════════════════════════════════════════
# CLI Interface
# ═══════════════════════════════════════════════════════════════════════════

def _scapy_to_dict(pkt) -> dict[str, Any] | None:
    from scapy.layers.inet import IP, TCP, UDP
    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    else:
        raw_bytes = bytes(pkt)
        if len(raw_bytes) >= 20 and (raw_bytes[0] >> 4) == 4:
            try:
                ip_layer = IP(raw_bytes)
            except Exception:
                pass

    if ip_layer is None:
        return None

    proto = int(ip_layer.proto)
    sport, dport, flags = 0, 0, 0
    if proto == 6 and ip_layer.haslayer(TCP):
        sport = int(ip_layer[TCP].sport)
        dport = int(ip_layer[TCP].dport)
        flags = int(ip_layer[TCP].flags)
    elif proto == 17 and ip_layer.haslayer(UDP):
        sport = int(ip_layer[UDP].sport)
        dport = int(ip_layer[UDP].dport)

    if timestamp_override is not None:
        pkt_ts = timestamp_override
    elif hasattr(pkt, "time") and float(pkt.time) > 0:
        pkt_ts = float(pkt.time)
    else:
        pkt_ts = time.time()

    return {
        "src_ip": str(ip_layer.src),
        "dst_ip": str(ip_layer.dst),
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto,
        "length": len(bytes(pkt)),
        "timestamp": pkt_ts,
        "tcp_flags": flags,
    }


async def main_async(args: argparse.Namespace) -> None:
    orchestrator = PipelineOrchestrator()
    await orchestrator.start()

    if args.mode == "replay":
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            logger.error("PCAP file not found: %s", pcap_path)
            await orchestrator.stop()
            return

        logger.info("Replaying PCAP: %s at rate: %s", pcap_path, args.rate)
        rate_val = float(str(args.rate).lower().replace("mbps", "").strip() or 0.0)

        start_wall_time = time.time()
        first_pkt_time: Optional[float] = None

        def on_packet(pkt):
            nonlocal first_pkt_time
            raw_t = float(pkt.time) if hasattr(pkt, "time") else 0.0
            if first_pkt_time is None:
                first_pkt_time = raw_t
            # Map replay timestamp relative to live start wall time
            offset = max(0.0, raw_t - first_pkt_time)
            live_ts = start_wall_time + offset
            p_dict = _scapy_to_dict(pkt, timestamp_override=live_ts)
            if p_dict:
                orchestrator.ingest_packet(p_dict)

        await asyncio.to_thread(replay_pcap, str(pcap_path), rate_val, on_packet)

    await orchestrator.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Unidirectional AI Threat Detection Pipeline Orchestrator")
    parser.add_argument("--mode", choices=["replay", "live"], default="replay", help="Execution mode")
    parser.add_argument("--pcap", type=str, default="samples/sample.pcap", help="Path to PCAP file for replay")
    parser.add_argument("--rate", type=str, default="10mbps", help="Replay rate (e.g. 10mbps or 0 for unlimited)")
    parser.add_argument("--interface", type=str, default=None, help="Network interface for live capture")
    args = parser.parse_args()

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
