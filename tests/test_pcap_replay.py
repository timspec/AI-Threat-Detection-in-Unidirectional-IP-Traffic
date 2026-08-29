"""
tests/test_pcap_replay.py — Tests for pipeline/ingest/pcap_replay.py

1. AST directionality guardrail (same pattern as test_live_capture.py).
2. Functional tests using a temporary PCAP created with Scapy's wrpcap.
"""

from __future__ import annotations

import ast
import time
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Raw
from scapy.utils import wrpcap

from pipeline.ingest.pcap_replay import replay_pcap, ReplayStats

# ---------------------------------------------------------------------------
# Path to the module under test
# ---------------------------------------------------------------------------
PCAP_REPLAY_PATH = (
    Path(__file__).resolve().parent.parent / "pipeline" / "ingest" / "pcap_replay.py"
)

# ═══════════════════════════════════════════════════════════════════════════
# 1. AST-based directionality guardrail
# ═══════════════════════════════════════════════════════════════════════════

BANNED_CALLS: set[str] = {
    "send", "sendp", "sr", "sr1", "srp", "srp1",
    "socket.send", "socket.sendto", "socket.sendmsg", "socket.connect",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request",
    "urllib.request.urlopen",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
}


class TestPcapReplayDirectionality:
    """Ensure pcap_replay.py contains no send-capable calls."""

    def test_source_file_exists(self):
        assert PCAP_REPLAY_PATH.exists()

    def test_no_send_calls_in_source(self):
        """Parse pcap_replay.py AST and fail on any banned call."""
        source = PCAP_REPLAY_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(PCAP_REPLAY_PATH))

        violations: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                call_name = func.id
            elif isinstance(func, ast.Attribute):
                parts = [func.attr]
                val = func.value
                while isinstance(val, ast.Attribute):
                    parts.append(val.attr)
                    val = val.value
                if isinstance(val, ast.Name):
                    parts.append(val.id)
                call_name = ".".join(reversed(parts))
            else:
                continue

            if call_name in BANNED_CALLS:
                violations.append(f"  Line {node.lineno}: {call_name}()")

        if violations:
            pytest.fail(
                "🚨 UNIDIRECTIONAL VIOLATION in pcap_replay.py!\n"
                + "\n".join(violations)
            )


# ═══════════════════════════════════════════════════════════════════════════
# 2. Functional tests
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def sample_pcap(tmp_path) -> Path:
    """Create a small temporary PCAP with 50 packets for testing."""
    packets = []
    for i in range(50):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(load=b"X" * 100)
        packets.append(pkt)
    pcap_file = tmp_path / "test.pcap"
    wrpcap(str(pcap_file), packets)
    return pcap_file


class TestReplayPcap:
    """Functional tests for replay_pcap()."""

    def test_replays_all_packets(self, sample_pcap):
        """All 50 packets should be delivered to the callback."""
        received = []
        stats = replay_pcap(
            path=str(sample_pcap),
            rate_mbps=0,  # unlimited — run as fast as possible
            on_packet=lambda pkt: received.append(pkt),
        )
        assert stats.total_packets == 50
        assert len(received) == 50

    def test_returns_correct_stats(self, sample_pcap):
        """ReplayStats should have sensible values."""
        stats = replay_pcap(
            path=str(sample_pcap),
            rate_mbps=0,
            on_packet=lambda p: None,
        )
        assert stats.total_packets == 50
        assert stats.total_bytes > 0
        assert stats.elapsed_seconds >= 0
        assert isinstance(stats.effective_mbps, float)

    def test_max_packets(self, sample_pcap):
        """max_packets should stop replay early."""
        stats = replay_pcap(
            path=str(sample_pcap),
            rate_mbps=0,
            on_packet=lambda p: None,
            max_packets=10,
        )
        assert stats.total_packets == 10

    def test_rate_limiting(self, sample_pcap):
        """With rate limiting, replay should take measurably longer."""
        # Unlimited speed
        stats_fast = replay_pcap(
            path=str(sample_pcap),
            rate_mbps=0,
            on_packet=lambda p: None,
        )
        # Very low rate — should be noticeably slower
        # 50 packets × ~154 bytes each ≈ 7700 bytes = 61600 bits
        # At 0.05 Mbps = 50000 bps → should take ~1.2 seconds
        stats_slow = replay_pcap(
            path=str(sample_pcap),
            rate_mbps=0.05,
            on_packet=lambda p: None,
        )
        # The throttled run must be meaningfully slower
        assert stats_slow.elapsed_seconds > stats_fast.elapsed_seconds

    def test_file_not_found(self):
        """Non-existent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            replay_pcap(
                path="/nonexistent/file.pcap",
                rate_mbps=0,
                on_packet=lambda p: None,
            )

    def test_callback_receives_scapy_packets(self, sample_pcap):
        """Callback should receive actual Scapy Packet objects."""
        from scapy.packet import Packet
        received = []
        replay_pcap(
            path=str(sample_pcap),
            rate_mbps=0,
            on_packet=lambda pkt: received.append(pkt),
            max_packets=5,
        )
        for pkt in received:
            assert isinstance(pkt, Packet)
            assert pkt.haslayer(IP)
