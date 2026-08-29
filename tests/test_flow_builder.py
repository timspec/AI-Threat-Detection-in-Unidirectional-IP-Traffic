"""
tests/test_flow_builder.py — Tests for pipeline/flow/flow_builder.py

All tests use hand-crafted synthetic packet dicts with explicit timestamps.
No real capture or network activity is needed.

Covers:
  1. Basic bidirectional flow grouping
  2. Forward vs backward direction tracking
  3. Idle-timeout expiry
  4. Active-timeout expiry
  5. Mid-life tick events
  6. flush_all()
  7. Edge cases (ICMP port-less, single-packet flows)
"""

from __future__ import annotations

import pytest

from pipeline.flow.flow_builder import FlowBuilder, make_flow_key, FlowKey


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _pkt(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: int = 6,
    length: int = 100,
    timestamp: float = 0.0,
) -> dict:
    """Build a synthetic packet-info dict."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "timestamp": timestamp,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 1.  FlowKey tests
# ═══════════════════════════════════════════════════════════════════════════

class TestFlowKey:
    """Canonical bidirectional key normalization."""

    def test_same_key_both_directions(self):
        """A→B and B→A must produce the same FlowKey."""
        k1 = make_flow_key("10.0.0.1", "10.0.0.2", 1000, 80, 6)
        k2 = make_flow_key("10.0.0.2", "10.0.0.1", 80, 1000, 6)
        assert k1 == k2

    def test_different_protocols_different_keys(self):
        """Same IPs/ports but different protocol → different keys."""
        k_tcp = make_flow_key("10.0.0.1", "10.0.0.2", 1000, 80, 6)
        k_udp = make_flow_key("10.0.0.1", "10.0.0.2", 1000, 80, 17)
        assert k_tcp != k_udp

    def test_key_is_hashable(self):
        """FlowKey must work as a dict key."""
        k = make_flow_key("1.1.1.1", "2.2.2.2", 100, 200, 6)
        d = {k: "value"}
        assert d[k] == "value"


# ═══════════════════════════════════════════════════════════════════════════
# 2.  Basic flow grouping & direction
# ═══════════════════════════════════════════════════════════════════════════

class TestFlowGrouping:
    """Packets grouped correctly into bidirectional flows."""

    def test_single_packet_creates_flow(self):
        events: list[dict] = []
        fb = FlowBuilder(on_flow_event=lambda e: events.append(e))

        fb.ingest_packet(_pkt(timestamp=1.0))

        assert fb.active_flow_count == 1
        assert fb.total_packets == 1
        assert fb.total_flows_created == 1

    def test_bidirectional_same_flow(self):
        """A→B and B→A should land in the same flow."""
        fb = FlowBuilder()

        fb.ingest_packet(_pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                              src_port=1000, dst_port=80, timestamp=1.0))
        fb.ingest_packet(_pkt(src_ip="10.0.0.2", dst_ip="10.0.0.1",
                              src_port=80, dst_port=1000, timestamp=1.1))

        assert fb.active_flow_count == 1
        assert fb.total_flows_created == 1

    def test_forward_backward_counters(self):
        """Forward = direction of first packet; backward = opposite."""
        events: list[dict] = []
        fb = FlowBuilder(on_flow_event=lambda e: events.append(e))

        # Forward: A→B, 200 bytes
        fb.ingest_packet(_pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                              src_port=5000, dst_port=80,
                              length=200, timestamp=1.0))
        # Backward: B→A, 500 bytes
        fb.ingest_packet(_pkt(src_ip="10.0.0.2", dst_ip="10.0.0.1",
                              src_port=80, dst_port=5000,
                              length=500, timestamp=1.5))
        # Forward again: A→B, 100 bytes
        fb.ingest_packet(_pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                              src_port=5000, dst_port=80,
                              length=100, timestamp=2.0))

        # Flush to get the event (ticks may also have fired)
        fb.flush_all()
        expired = [e for e in events if e["event_type"] == "expired"]
        assert len(expired) == 1
        e = expired[0]
        assert e["packets_fwd"] == 2
        assert e["packets_bwd"] == 1
        assert e["bytes_fwd"] == 300
        assert e["bytes_bwd"] == 500

    def test_different_flows_separate(self):
        """Different 5-tuples → separate flows."""
        fb = FlowBuilder()

        fb.ingest_packet(_pkt(src_port=1000, dst_port=80, timestamp=1.0))
        fb.ingest_packet(_pkt(src_port=2000, dst_port=443, timestamp=1.0))

        assert fb.active_flow_count == 2


# ═══════════════════════════════════════════════════════════════════════════
# 3.  Idle-timeout expiry
# ═══════════════════════════════════════════════════════════════════════════

class TestIdleTimeout:
    """Flows must expire after ``idle_timeout`` seconds of inactivity."""

    def test_idle_expiry(self):
        """No packets for idle_timeout → flow is expired."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=5.0,
            active_timeout=300.0,
            on_flow_event=lambda e: events.append(e),
        )

        # Packet at t=0
        fb.ingest_packet(_pkt(timestamp=0.0))
        assert fb.active_flow_count == 1

        # Packet from a *different* flow at t=6 → triggers timeout check
        fb.ingest_packet(_pkt(src_port=9999, dst_port=9999, timestamp=6.0))

        # The first flow should have been expired
        expired = [e for e in events if e["event_type"] == "expired"]
        assert len(expired) == 1
        assert expired[0]["state"] == "expired_idle"
        assert expired[0]["src_ip"] == "10.0.0.1"

    def test_activity_resets_idle_timer(self):
        """Packets within idle_timeout keep the flow alive."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=5.0,
            active_timeout=300.0,
            on_flow_event=lambda e: events.append(e),
        )

        # Keep the flow alive with packets every 3 seconds
        for t in range(0, 20, 3):
            fb.ingest_packet(_pkt(timestamp=float(t)))

        # No expiry should have happened (packets every 3s, idle=5s)
        expired = [e for e in events if e["event_type"] == "expired"]
        assert len(expired) == 0
        assert fb.active_flow_count == 1


# ═══════════════════════════════════════════════════════════════════════════
# 4.  Active-timeout expiry
# ═══════════════════════════════════════════════════════════════════════════

class TestActiveTimeout:
    """Flows must expire after ``active_timeout`` even if still active."""

    def test_active_expiry(self):
        """Flow alive for >= active_timeout → expired even with traffic."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=15.0,
            active_timeout=10.0,  # short for testing
            on_flow_event=lambda e: events.append(e),
        )

        # Send a packet every second for 12 seconds
        for t in range(12):
            fb.ingest_packet(_pkt(timestamp=float(t)))

        # The flow should have been expired at t≈10
        expired = [e for e in events if e["event_type"] == "expired"]
        assert len(expired) >= 1
        assert expired[0]["state"] == "expired_active"

    def test_active_timeout_wins_over_idle(self):
        """If both timeouts are reached, active_timeout reason applies."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=5.0,
            active_timeout=8.0,
            on_flow_event=lambda e: events.append(e),
        )

        # Packets at t=0, t=3 (within idle), then nothing until t=10
        fb.ingest_packet(_pkt(timestamp=0.0))
        fb.ingest_packet(_pkt(timestamp=3.0))

        # New flow at t=10 triggers check — first flow is expired on both
        # idle (10-3=7 > 5) and active (10-0=10 > 8).
        # Active-timeout is checked first in the code.
        fb.ingest_packet(_pkt(src_port=9999, dst_port=9999, timestamp=10.0))

        expired = [e for e in events if e["event_type"] == "expired"]
        assert len(expired) == 1
        # Active timeout was hit (age=10 >= 8)
        assert expired[0]["state"] == "expired_active"


# ═══════════════════════════════════════════════════════════════════════════
# 5.  Mid-life tick events
# ═══════════════════════════════════════════════════════════════════════════

class TestTickEvents:
    """1-second heartbeat ticks for active flows > 1s old."""

    def test_tick_emitted_after_one_second(self):
        """An active flow older than 1s should get a tick event."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=30.0,
            active_timeout=300.0,
            tick_interval=1.0,
            on_flow_event=lambda e: events.append(e),
        )

        fb.ingest_packet(_pkt(timestamp=0.0))
        fb.ingest_packet(_pkt(timestamp=1.5))  # 1.5s later → tick

        ticks = [e for e in events if e["event_type"] == "tick"]
        assert len(ticks) >= 1
        assert ticks[0]["total_packets"] >= 1

    def test_tick_every_second(self):
        """Multiple ticks should be emitted ~1s apart."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=30.0,
            active_timeout=300.0,
            tick_interval=1.0,
            on_flow_event=lambda e: events.append(e),
        )

        # Packets at t=0, 1.5, 2.5, 3.5 → should produce ticks near t≈1.5, 2.5, 3.5
        for t in [0.0, 1.5, 2.5, 3.5]:
            fb.ingest_packet(_pkt(timestamp=t))

        ticks = [e for e in events if e["event_type"] == "tick"]
        assert len(ticks) >= 2  # at least 2 ticks in 3.5 seconds

    def test_no_tick_for_young_flow(self):
        """A flow younger than tick_interval should not get a tick."""
        events: list[dict] = []
        fb = FlowBuilder(
            tick_interval=1.0,
            on_flow_event=lambda e: events.append(e),
        )

        fb.ingest_packet(_pkt(timestamp=0.0))
        fb.ingest_packet(_pkt(timestamp=0.5))  # only 0.5s old

        ticks = [e for e in events if e["event_type"] == "tick"]
        assert len(ticks) == 0

    def test_tick_contains_latest_counters(self):
        """Tick events should reflect the most up-to-date counters."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=30.0,
            active_timeout=300.0,
            tick_interval=1.0,
            on_flow_event=lambda e: events.append(e),
        )

        fb.ingest_packet(_pkt(length=100, timestamp=0.0))
        fb.ingest_packet(_pkt(length=200, timestamp=0.5))
        fb.ingest_packet(_pkt(length=300, timestamp=1.5))  # triggers tick

        ticks = [e for e in events if e["event_type"] == "tick"]
        assert len(ticks) >= 1
        # By the time the tick fires, all 3 packets have been ingested
        assert ticks[0]["total_bytes"] >= 300


# ═══════════════════════════════════════════════════════════════════════════
# 6.  flush_all & manual tick()
# ═══════════════════════════════════════════════════════════════════════════

class TestFlushAndManualTick:

    def test_flush_all_expires_everything(self):
        """flush_all() should expire all active flows."""
        events: list[dict] = []
        fb = FlowBuilder(on_flow_event=lambda e: events.append(e))

        fb.ingest_packet(_pkt(src_port=1000, timestamp=0.0))
        fb.ingest_packet(_pkt(src_port=2000, timestamp=0.0))
        assert fb.active_flow_count == 2

        fb.flush_all()
        assert fb.active_flow_count == 0
        expired = [e for e in events if e["event_type"] == "expired"]
        assert len(expired) == 2

    def test_manual_tick_triggers_expiry(self):
        """Calling tick() with a future time should expire idle flows."""
        events: list[dict] = []
        fb = FlowBuilder(
            idle_timeout=5.0,
            on_flow_event=lambda e: events.append(e),
        )

        fb.ingest_packet(_pkt(timestamp=0.0))
        fb.tick(current_time=10.0)  # 10s idle → expired

        expired = [e for e in events if e["event_type"] == "expired"]
        assert len(expired) == 1


# ═══════════════════════════════════════════════════════════════════════════
# 7.  Edge cases
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_icmp_zero_ports(self):
        """ICMP packets (no ports) should still form flows."""
        fb = FlowBuilder()

        fb.ingest_packet(_pkt(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=0, dst_port=0, protocol=1,  # ICMP
            timestamp=0.0,
        ))
        assert fb.active_flow_count == 1

    def test_event_dict_has_required_fields(self):
        """Every emitted event must have the fields the storage layer needs."""
        events: list[dict] = []
        fb = FlowBuilder(on_flow_event=lambda e: events.append(e))

        fb.ingest_packet(_pkt(timestamp=0.0))
        fb.flush_all()

        required_fields = {
            "flow_id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packets_fwd", "packets_bwd", "bytes_fwd",
            "bytes_bwd", "total_packets", "total_bytes",
            "start_time", "end_time", "duration", "state", "event_type",
        }
        assert len(events) == 1
        assert required_fields.issubset(events[0].keys())

    def test_duration_calculated_correctly(self):
        """duration = end_time - start_time."""
        events: list[dict] = []
        fb = FlowBuilder(on_flow_event=lambda e: events.append(e))

        fb.ingest_packet(_pkt(timestamp=10.0))
        fb.ingest_packet(_pkt(timestamp=15.5))
        fb.flush_all()

        assert events[0]["duration"] == pytest.approx(5.5)
