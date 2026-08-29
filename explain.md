# AI Threat Detection in Unidirectional IP Traffic
## Comprehensive Technical Architecture & Engineering Documentation

---

### Executive Summary

This project implements an enterprise-grade, real-time **Passive Network Threat Detection System** engineered specifically for **Unidirectional IP Traffic Environments** (such as optical data diodes, receive-only network taps, and defense/intelligence air-gapped monitoring networks). 

The system passively captures raw IP packets, reconstructs forward-only flows in memory, extracts mathematical/spectral/behavioral feature vectors, and evaluates traffic through a heterogeneous ensemble of **6 machine learning and statistical anomaly detectors** to detect cyber threats with sub-millisecond pipeline latency.

---

### 1. The Core Engineering Challenge: Unidirectional Traffic Constraints

Traditional Network Intrusion Detection Systems (NIDS) like Snort, Zeek, or Suricata assume full bidirectional network visibility. They rely heavily on:
1. **TCP State Machine Tracking**: Observing 3-way handshakes (`SYN` $\to$ `SYN-ACK` $\to$ `ACK`), connection teardowns (`FIN`, `RST`), and sequence/acknowledgment numbers.
2. **Round-Trip Time (RTT) & Jitter Analysis**: Measuring client-to-server request and server-to-client response intervals.
3. **Application Layer Request-Response Pairing**: Matching HTTP requests with HTTP status codes and responses.

In an **NTRO / Data Diode / Optical Tap** deployment:
* The physical medium or driver configuration is **strictly receive-only (Rx-only)**.
* **Zero backward packets exist** (`packets_bwd = 0`, zero ACKs, zero responses).
* Traditional bidirectional state engines fail or produce severe false alarms.

**This system solves this challenge** by designing flow reconstruction, feature extractors, and machine learning models that operate purely on **forward-direction telemetry (unidirectional flows)** without sacrificing detection fidelity.

---

### 2. End-to-End System Architecture

```
[ Physical Network Tap / Wire ]
                │ (Optical Splitter / Receive-only NIC)
                ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Passive Ingestion Engine                       │
│  - Live Capture: scapy.AsyncSniffer(store=False)        │
│  - Replay Engine: scapy.PcapReader (Rate-Paced)         │
└──────────────────────────┬──────────────────────────────┘
                           │ Raw Packets
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 2: Flow Builder & In-Memory State Machine          │
│  - Canonical 5-Tuple Aggregation                        │
│  - Sliding Window Buffer & Idle Eviction (5s/15s)       │
└──────────────────────────┬──────────────────────────────┘
                           │ Forward-Only Flow Records
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Unidirectional Feature Engineering Engine      │
│  - Timing & Jitter (IAT Mean, Variance, CV)             │
│  - Spectral & Periodicity (FFT / Autocorrelation)       │
│  - Lexical Analysis & Shannon Entropy                   │
│  - JA3 TLS Fingerprinting & First-N Packet Lengths      │
└──────────────────────────┬──────────────────────────────┘
                           │ Normalized Numerical Feature Vectors
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 4: Multi-Model AI & Statistical Detectors         │
│  1. C2 Beaconing: Random Forest Classifier              │
│  2. DGA / DNS Tunneling: Random Forest Classifier       │
│  3. Encrypted Malware: JA3 + Isolation Forest           │
│  4. DDoS & Floods: Dual-Horizon EWMA + Isolation Forest │
│  5. Port / Host Scans: Fan-Out Entropy Rule Engine      │
│  6. Exfiltration: Online Sliding Baseline Z-Score       │
└──────────────────────────┬──────────────────────────────┘
                           │ Raw Detections & Confidence Scores
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 5: Alert Aggregation, De-duplication & Storage    │
│  - 60s Signature Suppression Hash                       │
│  - Severity Scoring Function                            │
│  - SQLite Storage (storage/app.db via SQLAlchemy)       │
└──────────────────────────┬──────────────────────────────┘
                           │ WebSocket Push (alert.new, kpi.tick)
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 6: Backend REST API & Telemetry Engine (FastAPI)  │
│  - Loopback Interface Binding (127.0.0.1 Only)          │
│  - Tiered KPI Broadcaster (Active → Recent → Session)   │
└──────────────────────────┬──────────────────────────────┘
                           │ REST / WS (JSON)
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 7: SOC Single-Page Web Dashboard                  │
│  - Overview (Live KPIs, Real-time Feed, Sparklines)     │
│  - Live Alerts Explorer (Search, Filters, CSV/JSON)     │
│  - Analytics (Threat Trends, Top Hosts, Model Cards)    │
│  - Sensors (Data Diode Compliance, Tap Status)          │
└─────────────────────────────────────────────────────────┘
```

---

### 3. Deep Dive: Pipeline Subsystems & Code Implementation

#### 3.1. Layer 1: Passive Ingestion Engine (`pipeline/ingest/`)
* **Live Sniffing (`sniffer.py`)**: Interfaces with the Windows Npcap packet capture driver via Scapy's `AsyncSniffer(store=False)`. Operating in `store=False` mode ensures zero heap accumulation by processing packets via an asynchronous generator.
* **PCAP Replay Engine (`pcap_replay.py`)**: Ingests recorded PCAP/PCAPNG capture files using `PcapReader`. It calculates packet-to-packet inter-arrival deltas and controls ingestion rates (e.g., 10 Mbps, 100 Mbps). Crucially, it maps historical timestamps onto the current wall-clock epoch while preserving sub-millisecond relative inter-packet timing gaps.

#### 3.2. Layer 2: Flow Builder (`pipeline/flow/flow_builder.py`)
* Computes a canonical forward **5-Tuple key**:
  $$\text{Key} = (\text{src\_ip}, \text{dst\_ip}, \text{src\_port}, \text{dst\_port}, \text{protocol})$$
* Maintains active flows inside an in-memory dictionary.
* Evaluates sliding time-window expirations (5.0s active flow timeout, 15.0s inactive eviction).
* Aggregates packet counts, byte volumes, duration, TCP flag distributions, and an inter-arrival time (IAT) ring buffer without requiring acknowledgment frames.

#### 3.3. Layer 3: Feature Engineering Engine (`pipeline/features/`)
Derives specialized mathematical, spectral, and lexical indicators from the unidirectional forward stream:

1. **Timing & Periodic Jitter (`c2_beacon.py`)**:
   * Computes IAT mean ($\mu$) and standard deviation ($\sigma$).
   * Computes **Coefficient of Variation** ($CV = \frac{\sigma}{\mu}$) to detect robotic consistency ($CV \approx 0$).
   * Computes autocorrelation and Fast Fourier Transform (FFT) power spectrum peaks to identify beacon frequencies.
2. **Shannon Entropy & Lexical Distributions (`dga_dns.py`)**:
   * Computes **Shannon Entropy** on queried hostnames:
     $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
   * Computes n-gram (bigram/trigram) transition frequencies and vowel-to-consonant ratios to detect algorithmically generated domains (DGA).
3. **Volumetric & Rate Statistics (`ddos.py`)**:
   * Measures packet bursts per second, byte deltas, and Exponentially Weighted Moving Averages (EWMA).
4. **Graph & Fan-Out Cardinality (`recon_scan.py`)**:
   * Measures horizontal fan-out (unique destination IPs per source) and vertical fan-out (unique destination ports per target) within sliding windows.
5. **TLS Fingerprinting (`encrypted_malware.py`)**:
   * Extracts TLS Client Hello bytes, cipher suites, supported extensions, and elliptic curve formats to compute standard **JA3 MD5 signatures**.
6. **Payload Asymmetry (`exfiltration.py`)**:
   * Measures total payload volume per unit time against a historical baseline using **rolling Z-scores**:
     $$Z = \frac{x - \mu}{\sigma}$$

---

### 4. Layer 4: Heterogeneous Machine Learning & Detection Ensemble

The pipeline deploys 6 specialized detector models optimized for CPU-only inference:

| Threat Category | Model Architecture | Extracted Feature Vector | Output Metric |
| :--- | :--- | :--- | :--- |
| **C2 Beaconing** | **Random Forest Classifier** (`c2_beacon.joblib`, 100 trees) | IAT Mean, IAT Variance, IAT CV, Periodicity Score, Byte Size CV, Destination Cardinality | Anomaly Probability ($0.0 \to 1.0$) |
| **DGA / DNS Tunnel** | **Random Forest Classifier** (`dga_dns.joblib`, 100 trees) | Domain Shannon Entropy, Query Length, Vowel-to-Consonant Ratio, Hex/Digit Ratio | Malicious Domain Probability ($0.0 \to 1.0$) |
| **Encrypted Malware** | **JA3 Hash Matching + Isolation Forest** (`encrypted_malware.joblib`) | JA3 Signature + First-N Packet Length Sequence Vector | Outlier Anomaly Score |
| **DDoS / Floods** | **Dual-Horizon EWMA + Isolation Forest** | Packet Rate Burst, Byte Delta, Flag Entropy (SYN/UDP flood) | Volumetric Threat Score |
| **Port / Host Scans** | **Deterministic Fan-Out Rule Engine** | Destination Port Cardinality, Flag Signature (SYN-only, NULL, XMAS) | Threshold Trigger |
| **Data Exfiltration** | **Online Sliding Baseline Z-Score** | Outbound Byte Volume per Duration Ratio | Standard Deviation Anomaly ($Z > 3.0$) |

---

### 5. Layer 5: Alert Correlation, De-duplication & Persistence

* **Alert De-duplication**: To protect downstream SOC analysts from alert fatigue during high-volume attacks (e.g., millions of DDoS packets), the aggregator computes a hash key:
  $$\text{Hash} = \text{MD5}(\text{threat\_class} + \text{src\_ip} + \text{dst\_ip} + \text{dst\_port})$$
  Identical alerts within a **60-second sliding suppression window** are merged into an existing incident record, updating frequency counters rather than generating redundant database rows.
* **Severity Scoring Formula**:
  $$\text{Severity Score} = \alpha \cdot \text{Model Confidence} + \beta \cdot \text{Threat Class Weight} + \gamma \cdot \text{Volumetric Score}$$
  Alerts are mapped to discrete priority tiers:
  * $\ge 0.75 \implies \text{\textbf{CRITICAL}}$
  * $0.50 - 0.74 \implies \text{\textbf{HIGH}}$
  * $0.25 - 0.49 \implies \text{\textbf{MEDIUM}}$
  * $< 0.25 \implies \text{\textbf{LOW}}$
* **Storage Schema (`storage/db.py`)**:
  Implemented via SQLAlchemy ORM over SQLite (`storage/app.db`):
  * `flows`: 5-tuple records, packet counters, byte totals, start/end timestamps, duration.
  * `features`: Serialized JSON feature vectors for model retraining and audit trails.
  * `alerts`: Threat class, confidence, severity, evidence JSON, 5-tuple context, and triage status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
  * `models`: Precision, recall, F1-score, and model versioning metadata.
  * `annotations`: Human-in-the-loop analyst feedback, triage notes, and ground-truth validation labels.

---

### 6. Layer 6: Backend REST API & Real-Time Telemetry (`backend/main.py`)

* **Framework**: **FastAPI** running on an asynchronous Python event loop (`asyncio`) served by **Uvicorn**.
* **Security & Binding**: Strict loopback binding to `127.0.0.1:8000`. The server rejects external non-loopback socket attachments to preserve air-gap integrity.
* **Live WebSocket Broadcast (`/ws/alerts`)**:
  * Pushes immediate `alert.new` events directly to active browser clients upon detector trigger.
  * Broadcasts a 2-second `kpi.tick` packet using a **3-tier fallback strategy**:
    1. **Active Window (last 10s)**: High-resolution burst rate extrapolated to per-minute metrics.
    2. **Recent Window (last 60s)**: Rolling 1-minute alert and byte accumulation.
    3. **Session Fallback (full span)**: Effective historical throughput and detection rates derived from session timestamps, preventing counters from dropping to zero after a capture or replay completes.

---

### 7. Layer 7: SOC Web Interface (`dashboard/static/`)

A single-page, modern dark-themed web console built with **HTML5, Vanilla CSS3, and JavaScript (ES6+)** with **Chart.js**:
1. **Overview Dashboard (`index.html`)**: Real-time KPI cards (Active Threat Alerts, Live Rate, Ingest Throughput, Median Alert Latency), streaming live alert table, and 24-hour threat class sparklines.
2. **Live Alerts Explorer (`alerts.html`)**: Full-text search by IP, Port, Alert ID, multi-parameter filtering by threat class and severity, CSV/JSON export, and an inspection side-drawer with diagnostic JSON evidence and analyst triage buttons (`Mark Investigating`, `Mark Resolved`, `False Positive`).
3. **Analytics Console (`analytics.html`)**: 24-hour threat volume timeline, severity distribution donut chart, top offending source hosts, top targeted destination assets, and AI detector model evaluation scorecards (Precision, Recall, F1-Score).
4. **Sensors & Compliance (`sensors.html`)**: Passive tap probe status, interface health, and the formal **Unidirectional Architecture Compliance Matrix** verifying zero outbound transmission capability.

---

### 8. Benchmark Performance & Verification Results

* **Throughput Tested**: Evaluated and validated from 5 Mbps up to 100 Mbps.
* **Median Processing Latency**: **0.10 ms** (ingest $\to$ flow aggregation $\to$ feature extraction $\to$ inference $\to$ alert emission).
* **Packet Drop Rate**: **0% dropped frames** during high-burst replaying.
* **Test Suite**: 235 automated unit and integration tests passing (`pytest`).
* **Source Control**: Synchronized and pushed to GitHub at `https://github.com/timspec/AI-Threat-Detection-in-Unidirectional-IP-Traffic.git`.
