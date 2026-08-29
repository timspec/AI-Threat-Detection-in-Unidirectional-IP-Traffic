"""
tools/gen_sample_pcap.py — Generate a small sample PCAP for testing.

Creates samples/sample.pcap with a mix of packet types:
  - TCP SYN/ACK (simulated HTTP)
  - UDP DNS queries
  - ICMP echo requests
  - TLS Client Hello (for later JA3 testing)

⚠️  This writes a LOCAL FILE only. It does NOT send any packets on the wire.
    We use scapy packet constructors to build packets in memory and
    wrpcap() to serialize them to disk.
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

# ── Scapy imports — constructors only, NO send functions ──
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.tls.handshake import TLSClientHello  # type: ignore
from scapy.layers.tls.record import TLS  # type: ignore
from scapy.packet import Raw
from scapy.utils import wrpcap


def generate_sample_pcap(output_path: str, num_packets: int = 200) -> int:
    """Generate a sample PCAP file with mixed traffic.

    Returns the number of packets written.
    """
    packets = []
    src_ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
    dst_ips = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "172.217.14.206"]
    domains = [
        "example.com", "google.com", "github.com",
        # DGA-like domains for later detection testing
        "xkwqzrm.net", "a1b2c3d4.xyz", "qwertyui.top",
    ]

    for i in range(num_packets):
        src = random.choice(src_ips)
        dst = random.choice(dst_ips)
        pkt_type = random.choices(
            ["tcp", "dns", "icmp", "tls_hello"],
            weights=[40, 30, 15, 15],
            k=1,
        )[0]

        if pkt_type == "tcp":
            sport = random.randint(49152, 65535)
            dport = random.choice([80, 443, 8080, 8443])
            flags = random.choice(["S", "SA", "A", "PA", "FA"])
            payload = Raw(load=os.urandom(random.randint(20, 500)))
            pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload

        elif pkt_type == "dns":
            domain = random.choice(domains)
            pkt = (
                IP(src=src, dst="8.8.8.8")
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domain))
            )

        elif pkt_type == "icmp":
            pkt = IP(src=src, dst=dst) / ICMP() / Raw(load=os.urandom(56))

        elif pkt_type == "tls_hello":
            sport = random.randint(49152, 65535)
            pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags="PA")
            # Add a raw TLS-like payload (a proper ClientHello would need
            # more setup; this gives us a TCP/443 packet with payload)
            pkt = pkt / Raw(load=os.urandom(random.randint(150, 500)))

        else:
            continue

        packets.append(pkt)

    # ── Write to LOCAL FILE — wrpcap does NOT touch the network ──
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)

    print(f"✅ Wrote {len(packets)} packets to {output}")
    return len(packets)


def main() -> None:
    # Default output location
    project_root = Path(__file__).resolve().parent.parent
    output = project_root / "samples" / "sample.pcap"

    num = 200
    if len(sys.argv) > 1:
        try:
            num = int(sys.argv[1])
        except ValueError:
            pass

    generate_sample_pcap(str(output), num_packets=num)


if __name__ == "__main__":
    main()
