"""
tools/build_demo_pcaps.py — Generate curated demo PCAPs for showcase and packaging.

Outputs:
  1. samples/demo/benign_baseline.pcap  (Clean web browsing, DNS queries, normal handshakes)
  2. samples/demo/mixed_attacks.pcap   (Full multi-stage attack covering all 6 threat classes)
  3. samples/demo/ddos_burst.pcap      (High-volume volumetric SYN & UDP flood for throughput demonstration)
"""

import os
from pathlib import Path
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.utils import wrpcap

from pipeline.features.encrypted_malware import build_client_hello_bytes

DEMO_DIR = Path(__file__).resolve().parent.parent / "samples" / "demo"
DEMO_DIR.mkdir(parents=True, exist_ok=True)


def build_benign_baseline(count: int = 300) -> Path:
    """Generate clean web traffic, standard DNS queries, and completed TCP streams."""
    out_path = DEMO_DIR / "benign_baseline.pcap"
    packets = []
    base_ts = 1700000000.0

    domains = ["google.com.", "github.com.", "microsoft.com.", "cloudflare.com.", "wikipedia.org."]
    client_ips = [f"192.168.1.{i}" for i in range(10, 25)]

    for i in range(count):
        ts = base_ts + (i * 0.05)
        src_ip = client_ips[i % len(client_ips)]
        mod = i % 3

        if mod == 0:
            # Standard DNS query & reply
            d = domains[i % len(domains)]
            pkt = (
                IP(src=src_ip, dst="8.8.8.8")
                / UDP(sport=50000 + (i % 5000), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=d, qtype="A"))
            )
        elif mod == 1:
            # Regular HTTPS GET / TLS traffic
            pkt = (
                IP(src=src_ip, dst="142.250.190.46")
                / TCP(sport=51000 + (i % 5000), dport=443, flags="PA", seq=1000 + i, ack=2000 + i)
                / (b"NORMAL_TLS_PAYLOAD_" + b"X" * 120)
            )
        else:
            # Regular HTTP GET Request
            pkt = (
                IP(src=src_ip, dst="93.184.216.34")
                / TCP(sport=52000 + (i % 5000), dport=80, flags="PA", seq=1000 + i, ack=2000 + i)
                / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            )

        pkt.time = ts
        packets.append(pkt)

    wrpcap(str(out_path), packets)
    print(f"Generated: {out_path} ({len(packets)} packets, {out_path.stat().st_size} bytes)")
    return out_path


def build_mixed_attacks(count: int = 600) -> Path:
    """Generate multi-stage campaign exhibiting all six detectable threat classes."""
    out_path = DEMO_DIR / "mixed_attacks.pcap"
    packets = []
    base_ts = 1700000100.0

    for i in range(count):
        ts = base_ts + (i * 0.02)
        category = (i // 20) % 6  # 20 packets per threat category burst

        if category == 0:
            # 1. Recon / Port Scan: Probing sequential ports on internal target
            port = 20 + (i % 80)
            pkt = (
                IP(src="192.168.1.199", dst="10.0.0.15")
                / TCP(sport=45000 + (i % 1000), dport=port, flags="S", seq=i * 100)
            )
        elif category == 1:
            # 2. DDoS: High-rate SYN flood from spoofed IPs to web server
            spoofed_src = f"172.16.{i % 250}.{(i * 7) % 250}"
            pkt = (
                IP(src=spoofed_src, dst="192.168.1.50")
                / TCP(sport=1024 + (i % 60000), dport=80, flags="S", seq=i * 10)
            )
        elif category == 2:
            # 3. C2 Beaconing: Periodic low-jitter heartbeat check-ins to external C2
            # Use small interval jitter
            pkt = (
                IP(src="192.168.1.105", dst="198.51.100.77")
                / TCP(sport=49152, dport=443, flags="PA", seq=5000 + i * 20, ack=8000 + i)
                / b"HEARTBEAT_AGENT_ID=4402_STATUS=IDLE\r\n"
            )
        elif category == 3:
            # 4. Data Exfiltration: Large asymmetric outbound burst outside office hours
            pkt = (
                IP(src="192.168.1.105", dst="203.0.113.88")
                / TCP(sport=49153, dport=8443, flags="PA", seq=10000 + i * 1400, ack=500)
                / (b"ENCRYPTED_DB_DUMP_CHUNK_" + b"\x90" * 1200)
            )
        elif category == 4:
            # 5. DGA DNS Tunneling: High-entropy algorithmically generated domains
            dga_name = f"xk9q2m{i % 40}v7zb1l0.ru."
            pkt = (
                IP(src="192.168.1.140", dst="8.8.4.4")
                / UDP(sport=53123 + (i % 1000), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=dga_name, qtype="A"))
            )
        else:
            # 6. Encrypted Malware (JA3): Cobalt Strike / Trickbot TLS ClientHello
            raw_tls = build_client_hello_bytes(version=0x0303, sni="c2-controller.darkops-infra.net")
            pkt = (
                IP(src="192.168.1.180", dst="198.51.100.99")
                / TCP(sport=49154 + (i % 10), dport=443, flags="PA", seq=20000 + i * 200, ack=100)
                / raw_tls
            )

        pkt.time = ts
        packets.append(pkt)

    wrpcap(str(out_path), packets)
    print(f"Generated: {out_path} ({len(packets)} packets, {out_path.stat().st_size} bytes)")
    return out_path


def build_ddos_burst(count: int = 1500) -> Path:
    """Generate high-velocity volumetric DDoS burst designed to showcase high-rate pipeline ingestion."""
    out_path = DEMO_DIR / "ddos_burst.pcap"
    packets = []
    base_ts = 1700000200.0

    for i in range(count):
        # 1 millisecond intervals
        ts = base_ts + (i * 0.0005)
        spoofed_src = f"10.200.{(i * 3) % 250}.{(i * 11) % 250}"
        
        if i % 2 == 0:
            # SYN Flood targeting port 443
            pkt = (
                IP(src=spoofed_src, dst="192.168.1.50")
                / TCP(sport=1024 + (i % 64000), dport=443, flags="S", seq=i * 50)
            )
        else:
            # UDP Volumetric Flood targeting port 53/DNS
            pkt = (
                IP(src=spoofed_src, dst="192.168.1.50")
                / UDP(sport=1024 + (i % 64000), dport=53)
                / (b"DNS_AMPLIFICATION_RESPONSE_PADDING_" + b"\x55" * 800)
            )

        pkt.time = ts
        packets.append(pkt)

    wrpcap(str(out_path), packets)
    print(f"Generated: {out_path} ({len(packets)} packets, {out_path.stat().st_size} bytes)")
    return out_path


def main():
    print("=== Generating Curated Demo PCAPs ===")
    build_benign_baseline(300)
    build_mixed_attacks(600)
    build_ddos_burst(1500)
    print("=== Demo PCAP Generation Complete ===")


if __name__ == "__main__":
    main()
