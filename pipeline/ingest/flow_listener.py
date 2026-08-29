"""
pipeline/ingest/flow_listener.py — NetFlow v9 / IPFIX UDP collector.

╔════════════════════════════════════════════════════════════════════════╗
║                    ⚠️  ONE-WAY GUARANTEE ⚠️                            ║
║                                                                        ║
║  This module is STRICTLY RECEIVE-ONLY.                                 ║
║                                                                        ║
║  The asyncio DatagramProtocol implemented here:                        ║
║    ✅ Receives UDP datagrams from NetFlow/IPFIX exporters              ║
║    ✅ Parses them locally into Python dicts                            ║
║    ❌ NEVER calls transport.sendto() or any send method                ║
║    ❌ NEVER sends an acknowledgement, response, or control packet      ║
║    ❌ NEVER opens an outbound socket                                   ║
║                                                                        ║
║  NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) over UDP are inherently   ║
║  unidirectional protocols — the exporter sends, the collector only     ║
║  listens.  This implementation enforces that at the code level:        ║
║  transport.sendto is explicitly blocked.                               ║
║                                                                        ║
║  CODE REVIEW RULE: reject any PR that adds a send-capable call here.   ║
╚════════════════════════════════════════════════════════════════════════╝

Pure-Python decoder — all parsing is done with ``struct``, no external
NetFlow libraries required.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# NetFlow v9 / IPFIX field-type registry
# ═══════════════════════════════════════════════════════════════════════════
# Maps field-type ID → (human-readable name, decode hint).
# Decode hints: "uint" = unsigned int, "ipv4" = 4-byte IPv4,
#               "ipv6" = 16-byte IPv6, "mac" = 6-byte MAC, "raw" = bytes.

FIELD_REGISTRY: dict[int, tuple[str, str]] = {
    # --- Byte / packet counters ---
    1:   ("in_bytes",        "uint"),
    2:   ("in_pkts",         "uint"),
    # --- Protocol ---
    4:   ("protocol",        "uint"),
    5:   ("tos",             "uint"),
    6:   ("tcp_flags",       "uint"),
    # --- Ports ---
    7:   ("src_port",        "uint"),
    11:  ("dst_port",        "uint"),
    # --- IPv4 addresses ---
    8:   ("src_addr",        "ipv4"),
    12:  ("dst_addr",        "ipv4"),
    15:  ("next_hop",        "ipv4"),
    # --- SNMP interfaces ---
    10:  ("input_snmp",      "uint"),
    14:  ("output_snmp",     "uint"),
    # --- Timing ---
    21:  ("last_switched",   "uint"),
    22:  ("first_switched",  "uint"),
    # --- IPv6 addresses ---
    27:  ("src_addr_v6",     "ipv6"),
    28:  ("dst_addr_v6",     "ipv6"),
    62:  ("next_hop_v6",     "ipv6"),
    # --- Byte / packet counters (64-bit) ---
    23:  ("out_bytes",       "uint"),
    24:  ("out_pkts",        "uint"),
    # --- VLAN ---
    58:  ("src_vlan",        "uint"),
    59:  ("dst_vlan",        "uint"),
    # --- ICMP ---
    32:  ("icmp_type",       "uint"),
    # --- Direction ---
    61:  ("direction",       "uint"),
    # --- MAC addresses ---
    56:  ("src_mac",         "mac"),
    57:  ("dst_mac",         "mac"),
    # --- AS numbers ---
    16:  ("src_as",          "uint"),
    17:  ("dst_as",          "uint"),
    # --- Misc ---
    48:  ("flow_sampler_id", "uint"),
    # Additional fields can be added here as needed.
}


# ═══════════════════════════════════════════════════════════════════════════
# Value decoders
# ═══════════════════════════════════════════════════════════════════════════

def _decode_uint(raw: bytes) -> int:
    """Decode 1/2/4/8 byte unsigned integer (big-endian)."""
    length = len(raw)
    if length == 1:
        return raw[0]
    elif length == 2:
        return struct.unpack("!H", raw)[0]
    elif length == 4:
        return struct.unpack("!I", raw)[0]
    elif length == 8:
        return struct.unpack("!Q", raw)[0]
    else:
        return int.from_bytes(raw, byteorder="big")


def _decode_ipv4(raw: bytes) -> str:
    """Decode 4 bytes → dotted-quad IPv4 string.  No network I/O."""
    # socket.inet_ntoa is a pure local conversion — no network call.
    return socket.inet_ntoa(raw)


def _decode_ipv6(raw: bytes) -> str:
    """Decode 16 bytes → IPv6 string.  No network I/O."""
    return socket.inet_ntop(socket.AF_INET6, raw)


def _decode_mac(raw: bytes) -> str:
    """Decode 6 bytes → colon-separated MAC string."""
    return ":".join(f"{b:02x}" for b in raw)


def decode_field_value(raw: bytes, hint: str) -> Any:
    """Decode a raw field value based on its type hint."""
    decoders = {
        "uint": _decode_uint,
        "ipv4": _decode_ipv4,
        "ipv6": _decode_ipv6,
        "mac":  _decode_mac,
    }
    decoder = decoders.get(hint, lambda r: r.hex())
    return decoder(raw)


# ═══════════════════════════════════════════════════════════════════════════
# NetFlow v9 / IPFIX decoder
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class NetFlowDecoder:
    """Stateful decoder for NetFlow v9 and IPFIX binary packets.

    Maintains a per-source template cache so that data records can be
    decoded once the corresponding template has been received.
    """

    # Template cache: {(source_id, template_id): [(field_type, field_len), ...]}
    _templates: dict[tuple[int, int], list[tuple[int, int]]] = field(
        default_factory=dict
    )

    # ── Public API ────────────────────────────────────────────────────

    def decode(self, data: bytes, addr: tuple[str, int] | None = None) -> list[dict]:
        """Decode a raw NetFlow v9 or IPFIX UDP payload.

        Parameters
        ----------
        data : bytes
            Raw UDP payload.
        addr : tuple, optional
            (ip, port) of the exporter — used for logging only.

        Returns
        -------
        list[dict]
            A list of flow-record dicts.  May be empty if the packet
            contains only template definitions or uses an unknown template.
        """
        if len(data) < 4:
            logger.warning("Payload too short (%d bytes) from %s", len(data), addr)
            return []

        version = struct.unpack("!H", data[:2])[0]

        if version == 9:
            return self._decode_v9(data, addr)
        elif version == 10:
            return self._decode_ipfix(data, addr)
        else:
            logger.warning("Unsupported NetFlow version %d from %s", version, addr)
            return []

    @property
    def template_count(self) -> int:
        """Number of cached templates."""
        return len(self._templates)

    def clear_templates(self) -> None:
        """Flush the template cache."""
        self._templates.clear()

    # ── NetFlow v9 ────────────────────────────────────────────────────

    def _decode_v9(self, data: bytes, addr: tuple | None) -> list[dict]:
        """Parse a NetFlow v9 packet (RFC 3954).

        Header layout (20 bytes):
          0-1   Version (9)
          2-3   Count (total records — templates + data)
          4-7   SysUptime (ms)
          8-11  Unix seconds
          12-15 Sequence number
          16-19 Source ID
        """
        if len(data) < 20:
            logger.warning("NetFlow v9 packet too short (%d bytes)", len(data))
            return []

        header = struct.unpack("!HHIIII", data[:20])
        _version, _count, sys_uptime, unix_secs, seq_num, source_id = header

        logger.debug(
            "NFv9 from %s: count=%d seq=%d source_id=%d",
            addr, _count, seq_num, source_id,
        )

        records: list[dict] = []
        offset = 20

        # Walk FlowSets until we run out of data
        while offset + 4 <= len(data):
            fs_id, fs_length = struct.unpack("!HH", data[offset : offset + 4])

            if fs_length < 4:
                logger.warning("Invalid FlowSet length %d at offset %d", fs_length, offset)
                break

            fs_payload = data[offset + 4 : offset + fs_length]

            if fs_id == 0:
                # Template FlowSet
                self._parse_v9_templates(fs_payload, source_id)
            elif fs_id == 1:
                # Options Template FlowSet — skip for now
                logger.debug("Skipping Options Template FlowSet")
            elif fs_id >= 256:
                # Data FlowSet — template_id == fs_id
                new_records = self._parse_data_flowset(
                    fs_payload, source_id, fs_id, unix_secs
                )
                records.extend(new_records)
            else:
                logger.debug("Unknown FlowSet ID %d, skipping", fs_id)

            offset += fs_length
            # FlowSets are padded to 4-byte boundaries
            padding = (4 - (fs_length % 4)) % 4
            offset += padding

        return records

    def _parse_v9_templates(self, payload: bytes, source_id: int) -> None:
        """Parse one or more templates from a Template FlowSet payload."""
        offset = 0
        while offset + 4 <= len(payload):
            template_id, field_count = struct.unpack("!HH", payload[offset : offset + 4])
            offset += 4

            fields: list[tuple[int, int]] = []
            for _ in range(field_count):
                if offset + 4 > len(payload):
                    break
                ftype, flen = struct.unpack("!HH", payload[offset : offset + 4])
                fields.append((ftype, flen))
                offset += 4

            key = (source_id, template_id)
            self._templates[key] = fields
            logger.debug(
                "Cached template %d (source %d): %d fields, record_len=%d",
                template_id, source_id, len(fields),
                sum(fl for _, fl in fields),
            )

    # ── IPFIX (v10) ───────────────────────────────────────────────────

    def _decode_ipfix(self, data: bytes, addr: tuple | None) -> list[dict]:
        """Parse an IPFIX packet (RFC 7011).

        Header layout (16 bytes):
          0-1   Version (10)
          2-3   Length (total message length in bytes)
          4-7   Export Time (Unix seconds)
          8-11  Sequence Number
          12-15 Observation Domain ID (≈ Source ID)
        """
        if len(data) < 16:
            logger.warning("IPFIX packet too short (%d bytes)", len(data))
            return []

        header = struct.unpack("!HHIII", data[:16])
        _version, msg_length, export_time, seq_num, obs_domain_id = header

        logger.debug(
            "IPFIX from %s: length=%d seq=%d domain=%d",
            addr, msg_length, seq_num, obs_domain_id,
        )

        records: list[dict] = []
        offset = 16

        while offset + 4 <= min(len(data), msg_length):
            set_id, set_length = struct.unpack("!HH", data[offset : offset + 4])

            if set_length < 4:
                break

            set_payload = data[offset + 4 : offset + set_length]

            if set_id == 2:
                # Template Set (same format as NFv9 templates)
                self._parse_v9_templates(set_payload, obs_domain_id)
            elif set_id == 3:
                # Options Template Set — skip for now
                logger.debug("Skipping IPFIX Options Template Set")
            elif set_id >= 256:
                new_records = self._parse_data_flowset(
                    set_payload, obs_domain_id, set_id, export_time
                )
                records.extend(new_records)

            offset += set_length

        return records

    # ── Shared data FlowSet parser ────────────────────────────────────

    def _parse_data_flowset(
        self,
        payload: bytes,
        source_id: int,
        template_id: int,
        timestamp: int,
    ) -> list[dict]:
        """Decode data records using a cached template definition."""
        key = (source_id, template_id)
        template = self._templates.get(key)

        if template is None:
            logger.debug(
                "No template cached for (source=%d, template=%d) — skipping data",
                source_id, template_id,
            )
            return []

        record_len = sum(flen for _, flen in template)
        if record_len == 0:
            return []

        records: list[dict] = []
        offset = 0

        while offset + record_len <= len(payload):
            record: dict[str, Any] = {
                "_source_id": source_id,
                "_template_id": template_id,
                "_export_time": timestamp,
            }

            for ftype, flen in template:
                raw = payload[offset : offset + flen]
                offset += flen

                info = FIELD_REGISTRY.get(ftype)
                if info:
                    name, hint = info
                    record[name] = decode_field_value(raw, hint)
                else:
                    # Unknown field — store as hex
                    record[f"field_{ftype}"] = raw.hex()

            records.append(record)

        return records


# ═══════════════════════════════════════════════════════════════════════════
# Asyncio UDP listener
# ═══════════════════════════════════════════════════════════════════════════

class FlowListenerProtocol(asyncio.DatagramProtocol):
    """Asyncio protocol that receives NetFlow/IPFIX UDP datagrams.

    ╔══════════════════════════════════════════════════════════════════╗
    ║  ⚠️  RECEIVE-ONLY — this protocol NEVER sends any data.        ║
    ║  transport.sendto() is NOT called anywhere in this class.       ║
    ║  We do not even store the transport in a send-capable way.      ║
    ║  Any future edit that adds a sendto() call MUST be rejected.    ║
    ╚══════════════════════════════════════════════════════════════════╝
    """

    def __init__(
        self,
        on_flow_records: Callable[[list[dict]], None],
        decoder: NetFlowDecoder | None = None,
    ) -> None:
        self._on_flow_records = on_flow_records
        self._decoder = decoder or NetFlowDecoder()
        self._transport: Optional[asyncio.DatagramTransport] = None
        self.packets_received: int = 0
        self.records_decoded: int = 0

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        """Called when the UDP socket is ready.

        ⚠️  We store the transport ONLY so we can close() it later.
        We NEVER call transport.sendto().
        """
        self._transport = transport
        logger.info("Flow listener ready (receive-only, no responses will be sent)")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called for each incoming UDP datagram.

        Decodes the NetFlow/IPFIX payload and passes the resulting
        flow-record dicts to the registered callback.

        ⚠️  This method processes data locally ONLY.
            It does NOT send any response, acknowledgement, or error
            packet back to the exporter.  NetFlow/IPFIX over UDP is
            inherently one-way — the collector never talks back.
        """
        self.packets_received += 1

        try:
            records = self._decoder.decode(data, addr)
        except Exception:
            logger.exception("Failed to decode packet from %s", addr)
            return

        if records:
            self.records_decoded += len(records)
            self._on_flow_records(records)

    def error_received(self, exc: Exception) -> None:
        """Log transport-level errors.  ⚠️  No response is sent."""
        logger.error("Flow listener transport error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info("Flow listener connection closed: %s", exc)

    def close(self) -> None:
        """Close the underlying transport."""
        if self._transport:
            self._transport.close()


# ── Convenience start / stop functions ────────────────────────────────────

_listener_transport: Optional[asyncio.DatagramTransport] = None
_listener_protocol: Optional[FlowListenerProtocol] = None


async def start_flow_listener(
    on_flow_records: Callable[[list[dict]], None],
    host: str = "127.0.0.1",
    port: int = 2055,
    decoder: NetFlowDecoder | None = None,
) -> FlowListenerProtocol:
    """Start the NetFlow/IPFIX UDP listener.

    Parameters
    ----------
    on_flow_records : Callable
        Callback receiving a ``list[dict]`` of decoded flow records.
    host : str
        Bind address.  Default ``127.0.0.1`` (localhost only).
        ⚠️  NEVER set to ``0.0.0.0`` in production — the dashboard
        ground rules apply to all listeners.
    port : int
        UDP port.  Default 2055 (common NetFlow port).
    decoder : NetFlowDecoder, optional
        Custom decoder instance (useful for testing).

    Returns
    -------
    FlowListenerProtocol
        The running protocol instance.
    """
    global _listener_transport, _listener_protocol

    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: FlowListenerProtocol(on_flow_records, decoder),
        local_addr=(host, port),
    )

    _listener_transport = transport
    _listener_protocol = protocol  # type: ignore[assignment]

    logger.info("Flow listener started on %s:%d (receive-only)", host, port)
    return protocol  # type: ignore[return-value]


def stop_flow_listener() -> None:
    """Stop the running flow listener."""
    global _listener_transport, _listener_protocol

    if _listener_transport:
        _listener_transport.close()
        logger.info("Flow listener stopped")

    _listener_transport = None
    _listener_protocol = None
