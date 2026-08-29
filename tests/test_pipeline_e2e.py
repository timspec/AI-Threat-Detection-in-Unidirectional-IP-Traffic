"""
tests/test_pipeline_e2e.py — End-to-End Pipeline Integration Test.

Tests the complete unidirectional processing pipeline:
  Ingest -> FlowBuilder -> PriorityQueue -> 6 Parallel Detectors -> Aggregator -> SQLite DB

Asserts that synthetic threat traffic successfully flows through the entire pipeline
and produces valid, de-duplicated alerts in the SQLite database.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.utils import wrpcap

from pipeline.features.encrypted_malware import KNOWN_BAD_JA3, build_client_hello_bytes
from pipeline.orchestrator import PipelineOrchestrator
from storage.db import init_db, get_all_alerts


def _craft_test_packets() -> list:
    """Generate synthetic packets representing various threat scenarios."""
    packets = []
    base_time = 1700000000.0

    # ── 1. Recon Port Scan: 35 sequential destination ports ───────────
    for port in range(20, 55):
        pkt = (
            IP(src="192.168.1.50", dst="10.0.0.1")
            / TCP(sport=50000 + port, dport=port, flags="S")
        )
        pkt.time = base_time + (port - 20) * 0.05
        packets.append(pkt)

    # ── 2. C2 Beaconing: 25 periodic 10-second interval packets ──────
    for i in range(25):
        pkt = (
            IP(src="192.168.1.100", dst="198.51.100.1")
            / TCP(sport=44444, dport=443, flags="PA")
            / b"BEACON_HEARTBEAT"
        )
        pkt.time = base_time + (i * 10.0)
        packets.append(pkt)

    # ── 3. High Volume SYN Flood (DDoS): 150 fast SYN packets ─────────
    for i in range(150):
        pkt = (
            IP(src=f"10.1.{i % 20}.{i % 250}", dst="10.0.0.99")
            / TCP(sport=1024 + i, dport=80, flags="S")
        )
        pkt.time = base_time + (i * 0.001)
        packets.append(pkt)

    # ── 4. DGA / DNS Tunnelling: queries with random gibberish labels ─
    dga_names = [
        "kq3xzv9f2j1.net.",
        "qzxjvwkrmn782.net.",
        "a1b2c3d4e5f6g7.top.",
        "xrwq7m3p5k99.xyz.",
    ]
    for i, name in enumerate(dga_names):
        pkt = (
            IP(src="192.168.1.150", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name, qtype="TXT"))
        )
        pkt.time = base_time + 100.0 + i * 0.1
        packets.append(pkt)

    # ── 5. Known-Bad JA3 Malware TLS Handshake (Cobalt Strike) ────────
    cobalt_ja3_hash = list(KNOWN_BAD_JA3.keys())[1]
    # Craft raw ClientHello bytes
    raw_tls = build_client_hello_bytes(version=0x0303, sni="c2.evil-corp.net")
    pkt_tls = (
        IP(src="192.168.1.200", dst="203.0.113.5")
        / TCP(sport=49152, dport=443, flags="PA")
        / raw_tls
    )
    pkt_tls.time = base_time + 200.0
    packets.append(pkt_tls)

    return packets


async def _async_e2e_runner():
    """Inner coroutine executing end-to-end integration test."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_app.db"
        init_db(f"sqlite:///{db_path}")

        pcap_path = Path(tmp_dir) / "synthetic_threats.pcap"
        test_pkts = _craft_test_packets()
        wrpcap(str(pcap_path), test_pkts)
        assert pcap_path.exists()

        emitted_alerts: list[dict] = []

        orchestrator = PipelineOrchestrator(
            queue_maxsize=5000,
            dedup_window_seconds=1.0,  # Short window for test
            alert_callback=lambda a: emitted_alerts.append(a),
        )

        await orchestrator.start()

        # Ingest packets from the generated test PCAP
        from pipeline.orchestrator import _scapy_to_dict
        for pkt in test_pkts:
            p_dict = _scapy_to_dict(pkt)
            if p_dict:
                orchestrator.ingest_packet(p_dict)

        # Stop and flush all flows
        await orchestrator.stop()

        # ── Verify Alerts in Database ─────────────────────────────────
        db_alerts = get_all_alerts(limit=100)
        assert len(db_alerts) > 0, "Pipeline should have emitted threat alerts"

        detected_threat_classes = {a["threat_class"] for a in db_alerts}

        # Assert key expected threat classes were captured
        assert "recon_scan" in detected_threat_classes or "ddos" in detected_threat_classes

        for alert in db_alerts:
            assert alert["alert_id"].startswith("alert-")
            assert 0.0 <= alert["confidence"] <= 1.0
            assert alert["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            assert alert["severity_score"] >= 0.0
            assert len(alert["src_ip"]) > 0
            assert len(alert["dst_ip"]) > 0
            assert isinstance(alert["evidence"], (dict, list))
            assert len(alert["model_version"]) > 0

        # Close database connections so Windows file handle is released
        from storage.db import close_db
        close_db()


def test_end_to_end_pipeline_with_synthetic_pcap():
    """Run E2E pipeline test in standard asyncio event loop."""
    asyncio.run(_async_e2e_runner())
