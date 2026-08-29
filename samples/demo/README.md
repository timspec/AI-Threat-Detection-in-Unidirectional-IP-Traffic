# Curated Showcase Demo PCAPs

This directory contains three curated network packet capture files (`.pcap`) representing real-world operational scenarios designed for demonstration, live dashboard streaming, and benchmarking.

---

## 1. `benign_baseline.pcap`
- **Packet Count**: 300 packets
- **Protocols**: DNS (UDP 53), HTTP (TCP 80), TLS/HTTPS (TCP 443)
- **Description**: Clean background traffic representing routine corporate workstations. Contains standard iterative DNS lookups (`google.com`, `github.com`, `cloudflare.com`), full TCP 3-way handshakes, and normal HTTP/HTTPS web transactions.
- **Expected Pipeline Behavior**:
  - Zero alerts emitted (0 false positives).
  - All flows cleanly tracked and aged out.
  - KPI cards reflect active traffic throughput with green health status.

---

## 2. `mixed_attacks.pcap`
- **Packet Count**: 600 packets
- **Description**: Comprehensive multi-stage intrusion campaign designed to exercise all six AI/heuristic detector engines simultaneously.
- **Included Threat Categories**:
  1. **Recon Scan (`recon_scan`)**: Sequential vertical port probing across ports 20–100 on internal target `10.0.0.15`.
  2. **DDoS Flood (`ddos`)**: High-velocity TCP SYN flood with spoofed source IPs directed at web host `192.168.1.50`.
  3. **C2 Beaconing (`c2_beacon`)**: Low-jitter periodic heartbeat poll packets contacting external command-and-control server `198.51.100.77:443`.
  4. **Data Exfiltration (`exfiltration`)**: Large, rapid outbound data burst with high asymmetric bytes-out to bytes-in ratio to `203.0.113.88:8443`.
  5. **DGA DNS Tunneling (`dga_dns`)**: High-entropy pseudo-random algorithmic domain name lookups (`xk9q2m...ru`) targeting recursive resolvers.
  6. **Encrypted Malware (`encrypted_malware`)**: TLS ClientHello handshake matching known hostile JA3 fingerprint (Cobalt Strike / Trickbot) contacting `198.51.100.99:443`.
- **Expected Pipeline Behavior**:
  - Alerts generated across all 6 threat categories.
  - Live alert streaming onto the dashboard with distinct severity chips (`CRITICAL`, `HIGH`, `MEDIUM`).
  - Side-drawer inspection reveals full 5-tuple context and diagnostic evidence.

---

## 3. `ddos_burst.pcap`
- **Packet Count**: 1,500 packets (dense 1ms intervals)
- **Protocols**: TCP SYN, UDP DNS Amplification
- **Description**: Heavy volumetric burst traffic designed to demonstrate bounded queue stability and high-rate throughput handling under stress.
- **Expected Pipeline Behavior**:
  - Immediate DDoS trigger with high packet rate and SYN:ACK anomaly evidence.
  - Zero dropped frames in `PriorityEventQueue` (high-priority DDoS events prioritized).
  - Sub-millisecond alert emission latency.
