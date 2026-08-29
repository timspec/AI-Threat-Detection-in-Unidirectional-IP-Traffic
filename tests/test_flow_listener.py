"""
tests/test_flow_listener.py — Tests for pipeline/ingest/flow_listener.py

Three categories:

1. **AST directionality guardrail** — ensures no send-capable calls exist.
2. **Decoder unit tests** — hand-crafted NetFlow v9 and IPFIX binary
   payloads are fed to ``NetFlowDecoder.decode()`` and the output is
   verified against known values.
3. **Protocol tests** — verifies ``FlowListenerProtocol`` dispatches
   decoded records to the callback, without needing a real exporter.

HOW THE HAND-CRAFTED PAYLOADS WORK
-----------------------------------
NetFlow v9 is a binary protocol.  We build valid packets byte-by-byte
using ``struct.pack()``:

1. Construct a 20-byte v9 header (version, count, uptime, time, seq, src_id).
2. Append a Template FlowSet (ID=0) defining which fields are in each
   data record (e.g. src_addr, dst_addr, src_port, dst_port).
3. Append a Data FlowSet (ID=256) containing one or more records whose
   bytes match the template layout.
4. Feed the whole buffer to ``decoder.decode()`` and assert the returned
   dicts contain the expected IP addresses, ports, etc.

This proves the decoder works end-to-end without needing a real router.
"""

from __future__ import annotations

import ast
import asyncio
import struct
import socket
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pipeline.ingest.flow_listener import (
    NetFlowDecoder,
    FlowListenerProtocol,
    decode_field_value,
    FIELD_REGISTRY,
)

# ---------------------------------------------------------------------------
# Path to the module under test
# ---------------------------------------------------------------------------
FLOW_LISTENER_PATH = (
    Path(__file__).resolve().parent.parent / "pipeline" / "ingest" / "flow_listener.py"
)

# ═══════════════════════════════════════════════════════════════════════════
# 1.  AST directionality guardrail
# ═══════════════════════════════════════════════════════════════════════════

BANNED_CALLS: set[str] = {
    "send", "sendp", "sr", "sr1", "srp", "srp1",
    "socket.send", "socket.sendto", "socket.sendmsg", "socket.connect",
    "transport.sendto", "self._transport.sendto",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "urllib.request.urlopen",
    "httpx.get", "httpx.post",
}


class TestFlowListenerDirectionality:
    """Source-code level guarantee: no send calls in flow_listener.py."""

    def test_source_file_exists(self):
        assert FLOW_LISTENER_PATH.exists()

    def test_no_send_calls_in_source(self):
        source = FLOW_LISTENER_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(FLOW_LISTENER_PATH))

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
                "🚨 UNIDIRECTIONAL VIOLATION in flow_listener.py!\n"
                + "\n".join(violations)
            )


# ═══════════════════════════════════════════════════════════════════════════
# 2.  Hand-crafted binary payload helpers
# ═══════════════════════════════════════════════════════════════════════════

def _build_v9_packet(
    source_id: int = 100,
    seq_num: int = 1,
    unix_secs: int = 1_700_000_000,
    sys_uptime: int = 12345678,
    template_id: int = 256,
    fields: list[tuple[int, int]] | None = None,
    data_records: list[bytes] | None = None,
) -> bytes:
    """Build a complete NetFlow v9 binary packet from parts.

    Parameters
    ----------
    fields : list of (field_type, field_length)
        Template definition. If provided, a Template FlowSet is added.
    data_records : list of bytes
        Raw record bytes. If provided, a Data FlowSet is added.

    Returns bytes ready to be fed to ``decoder.decode()``.
    """
    flowsets = b""
    flowset_count = 0

    # ── Template FlowSet (ID=0) ──────────────────────────────────────
    if fields:
        template_body = struct.pack("!HH", template_id, len(fields))
        for ftype, flen in fields:
            template_body += struct.pack("!HH", ftype, flen)

        fs_length = 4 + len(template_body)  # 4 = FlowSet header
        # Pad to 4-byte boundary
        padding = (4 - (fs_length % 4)) % 4
        template_flowset = struct.pack("!HH", 0, fs_length) + template_body + b"\x00" * padding
        flowsets += template_flowset
        flowset_count += 1  # the template itself counts

    # ── Data FlowSet (ID = template_id) ──────────────────────────────
    if data_records:
        data_body = b"".join(data_records)
        fs_length = 4 + len(data_body)
        padding = (4 - (fs_length % 4)) % 4
        data_flowset = struct.pack("!HH", template_id, fs_length) + data_body + b"\x00" * padding
        flowsets += data_flowset
        flowset_count += len(data_records)  # each record counts

    # ── Header (20 bytes) ────────────────────────────────────────────
    header = struct.pack(
        "!HHIIII",
        9,              # version
        flowset_count,  # count
        sys_uptime,
        unix_secs,
        seq_num,
        source_id,
    )

    return header + flowsets


def _build_ipfix_packet(
    obs_domain_id: int = 200,
    seq_num: int = 1,
    export_time: int = 1_700_000_000,
    template_id: int = 300,
    fields: list[tuple[int, int]] | None = None,
    data_records: list[bytes] | None = None,
) -> bytes:
    """Build a complete IPFIX (v10) binary packet."""
    sets = b""

    # ── Template Set (ID=2) ──────────────────────────────────────────
    if fields:
        template_body = struct.pack("!HH", template_id, len(fields))
        for ftype, flen in fields:
            template_body += struct.pack("!HH", ftype, flen)
        set_length = 4 + len(template_body)
        template_set = struct.pack("!HH", 2, set_length) + template_body
        sets += template_set

    # ── Data Set (ID = template_id) ──────────────────────────────────
    if data_records:
        data_body = b"".join(data_records)
        set_length = 4 + len(data_body)
        data_set = struct.pack("!HH", template_id, set_length) + data_body
        sets += data_set

    # ── Header (16 bytes) ────────────────────────────────────────────
    msg_length = 16 + len(sets)
    header = struct.pack(
        "!HHIII",
        10,              # version
        msg_length,
        export_time,
        seq_num,
        obs_domain_id,
    )

    return header + sets


# ═══════════════════════════════════════════════════════════════════════════
# 3.  Decoder unit tests
# ═══════════════════════════════════════════════════════════════════════════

class TestNetFlowDecoder:
    """Unit tests for the pure-Python NetFlow v9 / IPFIX decoder."""

    def setup_method(self):
        self.decoder = NetFlowDecoder()

    # ── Value decoders ────────────────────────────────────────────────

    def test_decode_uint_1byte(self):
        assert decode_field_value(b"\x06", "uint") == 6  # TCP

    def test_decode_uint_2byte(self):
        assert decode_field_value(struct.pack("!H", 443), "uint") == 443

    def test_decode_uint_4byte(self):
        assert decode_field_value(struct.pack("!I", 1_000_000), "uint") == 1_000_000

    def test_decode_ipv4(self):
        raw = socket.inet_aton("192.168.1.10")
        assert decode_field_value(raw, "ipv4") == "192.168.1.10"

    def test_decode_mac(self):
        raw = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        assert decode_field_value(raw, "mac") == "aa:bb:cc:dd:ee:ff"

    # ── NetFlow v9: template + data ──────────────────────────────────

    def test_v9_template_parsing(self):
        """A packet with only a template FlowSet should cache the template."""
        fields = [(8, 4), (12, 4), (7, 2), (11, 2)]  # src, dst, sport, dport
        pkt = _build_v9_packet(source_id=100, fields=fields)

        records = self.decoder.decode(pkt, ("10.0.0.1", 2055))

        # No data records expected — just template caching
        assert records == []
        assert self.decoder.template_count == 1

    def test_v9_data_decoding(self):
        """Template + data in the same packet → decoded flow records."""
        fields = [
            (8,  4),   # src_addr  (IPv4)
            (12, 4),   # dst_addr  (IPv4)
            (7,  2),   # src_port
            (11, 2),   # dst_port
            (4,  1),   # protocol
        ]
        record_len = 4 + 4 + 2 + 2 + 1  # = 13 bytes

        # Build one data record: 192.168.1.10 → 10.0.0.1 : 12345 → 80 TCP(6)
        data_record = (
            socket.inet_aton("192.168.1.10")
            + socket.inet_aton("10.0.0.1")
            + struct.pack("!H", 12345)
            + struct.pack("!H", 80)
            + struct.pack("!B", 6)
        )

        pkt = _build_v9_packet(
            source_id=42,
            fields=fields,
            data_records=[data_record],
        )

        records = self.decoder.decode(pkt, ("router1", 2055))

        assert len(records) == 1
        r = records[0]
        assert r["src_addr"] == "192.168.1.10"
        assert r["dst_addr"] == "10.0.0.1"
        assert r["src_port"] == 12345
        assert r["dst_port"] == 80
        assert r["protocol"] == 6
        assert r["_source_id"] == 42
        assert r["_template_id"] == 256

    def test_v9_multiple_data_records(self):
        """Multiple records in one Data FlowSet should all be decoded."""
        fields = [(8, 4), (12, 4), (7, 2), (11, 2)]

        rec1 = (
            socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2")
            + struct.pack("!HH", 1000, 80)
        )
        rec2 = (
            socket.inet_aton("10.0.0.3") + socket.inet_aton("10.0.0.4")
            + struct.pack("!HH", 2000, 443)
        )

        pkt = _build_v9_packet(fields=fields, data_records=[rec1, rec2])
        records = self.decoder.decode(pkt, ("router", 2055))

        assert len(records) == 2
        assert records[0]["src_addr"] == "10.0.0.1"
        assert records[0]["dst_port"] == 80
        assert records[1]["src_addr"] == "10.0.0.3"
        assert records[1]["dst_port"] == 443

    def test_v9_data_without_template_returns_empty(self):
        """Data FlowSet without a prior template → no decoded records."""
        data_record = b"\x00" * 12
        pkt = _build_v9_packet(
            fields=None,  # no template
            data_records=[data_record],
        )
        records = self.decoder.decode(pkt, ("router", 2055))
        assert records == []

    def test_v9_template_then_data_separate_packets(self):
        """Template in packet 1, data in packet 2 → still works."""
        fields = [(8, 4), (12, 4)]

        # Packet 1: template only
        pkt1 = _build_v9_packet(source_id=1, fields=fields)
        r1 = self.decoder.decode(pkt1, ("r", 2055))
        assert r1 == []

        # Packet 2: data only (template already cached)
        data_record = socket.inet_aton("1.2.3.4") + socket.inet_aton("5.6.7.8")
        pkt2 = _build_v9_packet(source_id=1, fields=None, data_records=[data_record])
        r2 = self.decoder.decode(pkt2, ("r", 2055))

        assert len(r2) == 1
        assert r2[0]["src_addr"] == "1.2.3.4"
        assert r2[0]["dst_addr"] == "5.6.7.8"

    # ── IPFIX (v10) ──────────────────────────────────────────────────

    def test_ipfix_template_and_data(self):
        """IPFIX packet with template + data should decode correctly."""
        fields = [(8, 4), (12, 4), (7, 2), (11, 2)]

        data_record = (
            socket.inet_aton("172.16.0.1") + socket.inet_aton("8.8.8.8")
            + struct.pack("!HH", 54321, 53)
        )

        pkt = _build_ipfix_packet(
            obs_domain_id=200,
            template_id=300,
            fields=fields,
            data_records=[data_record],
        )

        records = self.decoder.decode(pkt, ("exporter", 4739))

        assert len(records) == 1
        r = records[0]
        assert r["src_addr"] == "172.16.0.1"
        assert r["dst_addr"] == "8.8.8.8"
        assert r["src_port"] == 54321
        assert r["dst_port"] == 53

    # ── Edge cases ────────────────────────────────────────────────────

    def test_unsupported_version_returns_empty(self):
        # Version 5 is not supported
        bad_pkt = struct.pack("!H", 5) + b"\x00" * 22
        assert self.decoder.decode(bad_pkt, ("x", 0)) == []

    def test_too_short_payload(self):
        assert self.decoder.decode(b"\x00\x09", ("x", 0)) == []

    def test_empty_payload(self):
        assert self.decoder.decode(b"", ("x", 0)) == []

    def test_field_registry_has_common_fields(self):
        """Spot-check that essential field types are in the registry."""
        for ftype in [1, 2, 4, 7, 8, 11, 12]:
            assert ftype in FIELD_REGISTRY, f"Field type {ftype} missing"


# ═══════════════════════════════════════════════════════════════════════════
# 4.  Protocol tests
# ═══════════════════════════════════════════════════════════════════════════

class TestFlowListenerProtocol:
    """Test the asyncio DatagramProtocol wrapper."""

    def test_datagram_received_calls_callback(self):
        """Protocol should decode and pass records to the callback."""
        received: list[list[dict]] = []
        decoder = NetFlowDecoder()
        protocol = FlowListenerProtocol(
            on_flow_records=lambda recs: received.append(recs),
            decoder=decoder,
        )

        # Simulate connection_made
        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        # Build a v9 packet with template + data
        fields = [(8, 4), (12, 4)]
        data_record = socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2")
        pkt = _build_v9_packet(fields=fields, data_records=[data_record])

        protocol.datagram_received(pkt, ("192.168.1.1", 2055))

        assert protocol.packets_received == 1
        assert protocol.records_decoded == 1
        assert len(received) == 1
        assert received[0][0]["src_addr"] == "10.0.0.1"

    def test_protocol_never_sends(self):
        """Verify that sendto is never called on the transport."""
        decoder = NetFlowDecoder()
        protocol = FlowListenerProtocol(
            on_flow_records=lambda recs: None,
            decoder=decoder,
        )
        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        # Feed multiple packets
        for _ in range(10):
            pkt = _build_v9_packet(fields=[(8, 4)], data_records=[b"\x01\x02\x03\x04"])
            protocol.datagram_received(pkt, ("10.0.0.1", 2055))

        # ⚠️  The transport's sendto must NEVER have been called
        mock_transport.sendto.assert_not_called()

    def test_protocol_handles_bad_packet(self):
        """Malformed packets should not crash the protocol."""
        protocol = FlowListenerProtocol(
            on_flow_records=lambda recs: None,
        )
        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        # Feed garbage
        protocol.datagram_received(b"\xff\xff", ("10.0.0.1", 2055))
        assert protocol.packets_received == 1
        assert protocol.records_decoded == 0
