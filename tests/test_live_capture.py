"""
tests/test_live_capture.py — Tests for pipeline/ingest/live_capture.py

Two categories of tests:

1. **AST directionality guardrail** (test_no_send_calls_in_source):
   Parses the live_capture.py source code with Python's ``ast`` module and
   walks every node in the abstract syntax tree.  If it finds ANY call to a
   send-capable function (sendp, send, sr, sr1, srp, srp1, socket.send,
   socket.sendto, socket.connect, requests.get/post, etc.) the test FAILS.
   This guarantees that no future edit can accidentally introduce outbound
   traffic in the ingest layer — the CI pipeline will catch it.

2. **Unit tests** for capture_live / stop_capture / is_capturing using
   mock objects (no real interface needed to run the tests).
"""

from __future__ import annotations

import ast
import os
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path to the module under test
# ---------------------------------------------------------------------------
LIVE_CAPTURE_PATH = (
    Path(__file__).resolve().parent.parent / "pipeline" / "ingest" / "live_capture.py"
)


# ═══════════════════════════════════════════════════════════════════════════
# 1. AST-based directionality guardrail
# ═══════════════════════════════════════════════════════════════════════════

# Functions / methods that must NEVER appear in ingest code.
BANNED_CALLS: set[str] = {
    # Scapy send primitives
    "send", "sendp", "sr", "sr1", "srp", "srp1",
    # Raw socket send
    "socket.send", "socket.sendto", "socket.sendmsg", "socket.connect",
    # HTTP client libraries
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request",
    "urllib.request.urlopen",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
}


def _collect_call_names(tree: ast.AST) -> list[str]:
    """Walk an AST and return the full dotted name of every Call node.

    For ``sendp(pkt)``, this returns ``["sendp"]``.
    For ``socket.send(data)``, this returns ``["socket.send"]``.
    """
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        # Simple name:  sendp(...)
        if isinstance(func, ast.Name):
            names.append(func.id)
        # Dotted name:  socket.send(...)
        elif isinstance(func, ast.Attribute):
            parts: list[str] = [func.attr]
            val = func.value
            while isinstance(val, ast.Attribute):
                parts.append(val.attr)
                val = val.value
            if isinstance(val, ast.Name):
                parts.append(val.id)
            names.append(".".join(reversed(parts)))
    return names


class TestDirectionalityGuardrail:
    """AST-based tests that enforce the one-way (receive-only) rule."""

    def test_source_file_exists(self):
        """Sanity check: the source file we're scanning must exist."""
        assert LIVE_CAPTURE_PATH.exists(), (
            f"Cannot find live_capture.py at {LIVE_CAPTURE_PATH}"
        )

    def test_no_send_calls_in_source(self):
        """Parse live_capture.py and FAIL if any banned send-capable call exists.

        HOW IT WORKS
        -------------
        1. Read the raw source of live_capture.py.
        2. Parse it into a Python Abstract Syntax Tree (AST).
        3. Walk every node; collect the fully-qualified name of every
           function/method call.
        4. Check each collected name against BANNED_CALLS.
        5. If ANY match is found → ``pytest.fail()`` with a clear message
           naming the offending call(s) and their line numbers.

        This test runs in CI on every commit, so a developer cannot
        accidentally (or intentionally) add outbound traffic to the
        ingest module without breaking the build.
        """
        source = LIVE_CAPTURE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(LIVE_CAPTURE_PATH))

        violations: list[str] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            # Resolve the call name
            if isinstance(func, ast.Name):
                call_name = func.id
            elif isinstance(func, ast.Attribute):
                parts: list[str] = [func.attr]
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
                violations.append(
                    f"  Line {node.lineno}: {call_name}()"
                )

        if violations:
            pytest.fail(
                "🚨 UNIDIRECTIONAL VIOLATION in live_capture.py!\n"
                "The following send-capable calls were found:\n"
                + "\n".join(violations)
                + "\n\nThis module is RECEIVE-ONLY. Remove these calls."
            )

    def test_no_banned_imports(self):
        """Fail if live_capture.py imports a send-only module outright."""
        source = LIVE_CAPTURE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(LIVE_CAPTURE_PATH))

        banned_modules = {"requests", "httpx", "urllib.request"}
        imported: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned_modules:
                        imported.append(f"  Line {node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module in banned_modules or module.split(".")[0] in banned_modules:
                    imported.append(
                        f"  Line {node.lineno}: from {module} import ..."
                    )

        if imported:
            pytest.fail(
                "🚨 BANNED IMPORT in live_capture.py!\n"
                + "\n".join(imported)
                + "\n\nHTTP client libraries must not be imported in ingest code."
            )


# ═══════════════════════════════════════════════════════════════════════════
# 2. Unit tests for capture_live / stop_capture / is_capturing
# ═══════════════════════════════════════════════════════════════════════════

class TestCaptureLifecycle:
    """Functional tests using a mocked AsyncSniffer (no real NIC needed)."""

    def setup_method(self):
        """Reset module-level sniffer state before each test."""
        import pipeline.ingest.live_capture as lc
        lc._sniffer = None

    @patch("pipeline.ingest.live_capture.AsyncSniffer")
    def test_capture_live_starts_sniffer(self, MockSniffer):
        """capture_live() should create and start an AsyncSniffer."""
        from pipeline.ingest.live_capture import capture_live

        mock_instance = MagicMock()
        mock_instance.running = False  # not yet running before start()
        MockSniffer.return_value = mock_instance

        callback = MagicMock()
        result = capture_live(interface="Ethernet", on_packet=callback)

        # AsyncSniffer was constructed with receive-only args
        MockSniffer.assert_called_once_with(
            iface="Ethernet",
            prn=callback,
            store=False,
            filter=None,
            count=0,
        )
        mock_instance.start.assert_called_once()
        assert result is mock_instance

    @patch("pipeline.ingest.live_capture.AsyncSniffer")
    def test_capture_live_with_bpf_filter(self, MockSniffer):
        """BPF filter and packet_count should be forwarded correctly."""
        from pipeline.ingest.live_capture import capture_live

        mock_instance = MagicMock()
        mock_instance.running = False
        MockSniffer.return_value = mock_instance

        capture_live(
            interface="Wi-Fi",
            on_packet=lambda p: None,
            bpf_filter="tcp port 443",
            packet_count=100,
        )

        _, kwargs = MockSniffer.call_args
        assert kwargs["filter"] == "tcp port 443"
        assert kwargs["count"] == 100
        assert kwargs["store"] is False  # always False

    @patch("pipeline.ingest.live_capture.AsyncSniffer")
    def test_double_start_raises(self, MockSniffer):
        """Starting capture while one is already running must raise."""
        from pipeline.ingest.live_capture import capture_live

        mock_instance = MagicMock()
        mock_instance.running = True  # simulate running sniffer
        MockSniffer.return_value = mock_instance

        capture_live(interface="Ethernet", on_packet=lambda p: None)

        with pytest.raises(RuntimeError, match="already running"):
            capture_live(interface="Ethernet", on_packet=lambda p: None)

    @patch("pipeline.ingest.live_capture.AsyncSniffer")
    def test_stop_capture(self, MockSniffer):
        """stop_capture() should stop the sniffer and reset state."""
        from pipeline.ingest.live_capture import capture_live, stop_capture, is_capturing
        import pipeline.ingest.live_capture as lc

        mock_instance = MagicMock()
        mock_instance.running = True
        mock_instance.results = []
        MockSniffer.return_value = mock_instance

        capture_live(interface="Ethernet", on_packet=lambda p: None)
        stop_capture()

        mock_instance.stop.assert_called_once()
        assert lc._sniffer is None

    def test_stop_capture_when_idle(self):
        """stop_capture() with no active session should return 0."""
        from pipeline.ingest.live_capture import stop_capture
        assert stop_capture() == 0

    @patch("pipeline.ingest.live_capture.AsyncSniffer")
    def test_is_capturing(self, MockSniffer):
        """is_capturing() should reflect sniffer state."""
        from pipeline.ingest.live_capture import capture_live, is_capturing
        import pipeline.ingest.live_capture as lc

        mock_instance = MagicMock()
        mock_instance.running = True
        MockSniffer.return_value = mock_instance

        assert is_capturing() is False  # nothing started yet

        capture_live(interface="Ethernet", on_packet=lambda p: None)
        assert is_capturing() is True

        # Simulate stop
        mock_instance.running = False
        assert is_capturing() is False
