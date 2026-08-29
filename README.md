# NTRO PS-26145 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](https://microsoft.com/windows)
[![Tests](https://img.shields.io/badge/tests-235%20passed-brightgreen.svg)](#-automated-testing)
[![Latency](https://img.shields.io/badge/alert%20latency-0.10%20ms-success.svg)](#-benchmarked-performance)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 📌 1. What is this Project?

**NTRO PS-26145** is an enterprise-grade, high-throughput network threat detection system developed for the **National Technical Research Organisation (NTRO)**. It is purpose-built for high-security defense networks, critical national infrastructure, and intelligence perimeters where **strict unidirectionality (data diode mode)** is mandatory.

### The Problem It Solves
Traditional Intrusion Detection Systems (IDS) often require active network interactions, bidirectional TCP handshakes, or management interfaces that can reveal the monitor's presence or expose the sensor to counter-exploitation. 

### Our Solution
This system functions in **100% passive, receive-only mode**:
- It taps fiber-optic cables or raw physical network adapters without transmitting a single bit back toward the network.
- It detects advanced, covert cyber attacks in real time using 6 parallel machine learning and statistical detection engines.
- It analyzes encrypted TLS traffic **passively using JA3/JA4 fingerprinting** without decrypting confidential payloads.
- It streams alerts instantly with **sub-millisecond latency (0.10 ms)** to an analyst-focused dark Security Operations Center (SOC) dashboard.

---

## ⚙️ 2. How this Project Works

The monitoring pipeline processes continuous packet streams through 6 pipeline stages:

```
[ Raw Network Traffic ]
          │ (Fiber Tap / Receive-Only NIC)
          ▼
   1. PASSIVE INGEST ────▶ Scapy AsyncSniffer / PcapReader in zero-transmit mode
          │
          ▼
   2. FLOW BUILDER   ────▶ Reconstructs bidirectional flows by canonical 5-tuple
          │
          ▼
   3. FEATURE ENGINE ────▶ Extracts inter-packet timing, entropy, ratios & JA3 hashes
          │
          ▼
   4. 6 AI DETECTORS ────▶ Parallel scikit-learn ML & heuristic models evaluate threat
          │
          ▼
   5. AGGREGATOR     ────▶ 30-second sliding dedup window & severity risk weighting
          │
          ▼
   6. SOC DASHBOARD  ────▶ FastAPI REST API + WebSocket pushes live alerts into browser
```

1. **Passive Packet Ingest**: Receives raw Ethernet/IP frames via Windows Npcap in non-promiscuous or tap mode with zero transmission capability (`send()` and `socket.connect()` are strictly absent).
2. **Bidirectional Flow Assembly**: Groups unidirectional packet streams into canonical 5-tuple network conversations (`(src_ip, dst_ip, src_port, dst_port, protocol)`).
3. **Deep Feature Extraction**: Extracts statistical packet rates, byte volumes, inter-arrival time variance, domain name character entropy, and TLS ClientHello metadata.
4. **Parallel Threat Inference**: Evaluates every flow concurrently across **6 distinct cyber threat categories**.
5. **Alert Aggregation & Risk Scoring**: Deduplicates rapid-fire bursts within a 30-second sliding window and calculates severity:  
   $$\text{Severity Score} = \text{Model Confidence} \times \text{Class Risk Weight}$$
6. **Live SOC Streaming**: Pushes alerts instantly over WebSockets into a dark-themed SOC interface with no manual browser refresh required.

---

## 🧠 3. The Six AI & Heuristic Threat Detectors

| Threat Class | Detection Technique | Primary Indicators / Features |
|---|---|---|
| 🌊 **DDoS Floods** | Hybrid EWMA + Isolation Forest | Exponentially weighted packet rates, SYN:ACK ratio skew, source IP dispersion entropy. |
| 📡 **C2 Beaconing** | Random Forest Classifier | Periodic heartbeat intervals, low inter-arrival jitter, packet size variance. |
| 🕳️ **DGA / DNS Tunnels** | Random Forest + Shannon Entropy | Character randomness in query names, vowel-to-consonant ratios, query burst frequency. |
| 🔒 **Encrypted Malware** | Passive JA3/JA4 Fingerprinting | TLS ClientHello cipher suite order and extension hashes matched against hostile database (e.g. Cobalt Strike). **Zero payload decryption**. |
| 🔍 **Recon / Port Scans** | Statistical State Machine | Vertical single-target port probing, horizontal subnet sweeps, failed SYN handshake ratios. |
| 💾 **Data Exfiltration** | Rolling Z-Score Anomaly Engine | Asymmetric outbound/inbound byte ratios, statistical volume deviations ($z > 3.0$), off-hours transfers. |

---

## 📐 4. System Architecture

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 UNIDIRECTIONAL BOUNDARY                                │
│                                                                                        │
│   [ Physical Network Tap ] ───────── (Optical Diode / Rx-Only NIC)                     │
│                                                   │                                    │
│                                                   ▼                                    │
│                                      pipeline/ingest/capture.py                        │
│                                                   │                                    │
│                                                   ▼                                    │
│                                      pipeline/flow/flow_builder.py                     │
│                                                   │                                    │
│                                                   ▼                                    │
│                                      pipeline/queue.py                                 │
│                                      [ Priority Queue (maxsize=10k) ]                  │
│                                                   │                                    │
│                         ┌─────────────────────────┴─────────────────────────┐          │
│                         ▼                                                   ▼          │
│             pipeline/features/                                 pipeline/detectors/     │
│             • ddos.py         (EWMA / SYN)                     • ddos.py               │
│             • c2_beacon.py    (Jitter / Timing)                • c2_beacon.py          │
│             • dga_dns.py      (Entropy / Ratios)               • dga_dns.py            │
│             • encrypted.py    (JA3 Fingerprint)                • encrypted_malware.py  │
│             • recon_scan.py   (Port Sequencer)                 • recon_scan.py         │
│             • exfiltration.py (Rolling Z-Score)                • exfiltration.py       │
│                         │                                                   │          │
│                         └─────────────────────────┬─────────────────────────┘          │
│                                                   ▼                                    │
│                                      pipeline/aggregator/                              │
│                                      [ 30s Window Deduplication & Risk Weights ]       │
│                                                   │                                    │
│                                                   ▼                                    │
│                                      storage/db.py (SQLite: storage/app.db)            │
│                                                   │                                    │
│                                                   ▼                                    │
│                                      backend/main.py (FastAPI on 127.0.0.1:8000)       │
│                                                   │                                    │
│                                 ┌─────────────────┴─────────────────┐                  │
│                                 ▼                                   ▼                  │
│                       REST API Endpoints                 WebSocket (/ws/alerts)        │
│                       • /api/health                      • Real-time alert push        │
│                       • /api/alerts                      • 2-second live KPI metrics   │
│                       • /api/analytics                   • Zero outbound transmission  │
│                                 │                                   │                  │
│                                 └─────────────────┬─────────────────┘                  │
│                                                   ▼                                    │
│                                      dashboard/static/                                 │
│                                      • index.html     (Overview & KPIs)                │
│                                      • alerts.html    (Live Table & Side Drawer)       │
│                                      • analytics.html (Trend Charts & Top Talkers)     │
│                                      • sensors.html   (One-Way Ingest Matrix)          │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Architectural Ground Rules:
- **Strictly Unidirectional**: Ingest code contains no transmission APIs (`send`, `sendp`, or `connect`).
- **Localhost Binding**: Backend strictly binds to `127.0.0.1`—never exposed to external interfaces (`0.0.0.0`).
- **Zero Decryption**: TLS traffic is analyzed purely through unencrypted handshake headers.
- **CPU-Only ML**: Lightweight models run locally without requiring GPU hardware or cloud API access.

---

## ⚡ 5. Real Benchmarked Performance

Benchmarked using [`tools/benchmark.py`](tools/benchmark.py) replaying multi-vector attack streams across increasing bitrate tiers:

| Target Rate | Sustained Flows/s | Total Alerts | Median Latency | 95th-Percentile Latency | Drops | Target Compliance |
|---|---|---|---|---|---|---|
| **5.0 Mbps** | 29.4 flows/s | 12 | **0.10 ms** | **0.10 ms** | **0** | ✅ **PASS** |
| **20.0 Mbps** | 42.4 flows/s | 24 | **0.10 ms** | **0.10 ms** | **0** | ✅ **PASS** |
| **50.0 Mbps** | 47.3 flows/s | 20 | **0.10 ms** | **0.10 ms** | **0** | ✅ **PASS** |
| **100.0 Mbps** | 41.8 flows/s | 22 | **0.10 ms** | **0.10 ms** | **0** | ✅ **PASS** |

- **Sub-Millisecond Speed**: Median alert latency is **0.10 milliseconds**, dramatically outperforming the operational target threshold of $\le 5.0$ seconds.
- **Zero Packet Loss**: Bounded `PriorityEventQueue` maintained 100% loss-free ingestion with 0 frame drops.

---

## 💻 6. How to Install and Run on Your PC

### Step 1: System Prerequisites (Windows 10 / 11)
1. **Python 3.11+ (64-bit)**:
   - Download from [python.org](https://www.python.org/downloads/).
   - ⚠️ **Important:** During installation, check the box: **"Add python.exe to PATH"**.
2. **Npcap (Packet Capture Driver)**:
   - Download from [npcap.com](https://npcap.com/#download).
   - ⚠️ **Important:** During installation, ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked.
3. **Git**:
   - Download from [git-scm.com](https://git-scm.com/).

---

### Step 2: Clone and Set Up the Project

Open **PowerShell** as an administrator and run:

```powershell
# 1. Clone the repository
git clone https://github.com/<your-username>/ntro-threat-detect.git
cd ntro-threat-detect

# 2. Create Python virtual environment
python -m venv venv

# 3. Activate virtual environment
.\venv\Scripts\Activate.ps1
# If PowerShell blocks script execution, run this once:
# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# 4. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

### Step 3: Verify Your Setup

Check that Npcap and Scapy detect your network adapters:
```powershell
python -m tools.check_capture
```
Run the automated test suite to ensure all 235 tests pass:
```powershell
pytest
```

---

### Step 4: Run the System

#### Option A: One-Click Showcase Demo (Easiest)
Run the included batch script:
```cmd
run_demo.bat
```
What this does automatically:
1. Activates your Python virtual environment.
2. Starts the FastAPI backend server and WebSocket broadcaster in the background.
3. Opens your default web browser to the live SOC dashboard (`http://localhost:8000`).
4. Replays a curated multi-threat attack capture (`samples/demo/mixed_attacks.pcap`) so you can watch live alerts stream in.

---

#### Option B: Run from Source (Manual Commands)

**1. Start Backend API Server:**
```powershell
.\venv\Scripts\uvicorn.exe backend.main:app --host 127.0.0.1 --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser.

**2. In a second PowerShell window, run the detector:**
- **Replay Demo Attacks (Offline PCAP):**
  ```powershell
  python -m pipeline.orchestrator --mode replay --pcap samples/demo/mixed_attacks.pcap --rate 10mbps
  ```
- **Live Physical Network Sniffing (Real Traffic):**
  ```powershell
  # Replace "Wi-Fi" or "Ethernet" with your network interface name
  python -m pipeline.orchestrator --mode live --interface "Wi-Fi"
  ```

---

## 📦 7. Standalone Executable Packaging

To build a standalone Windows single-folder distribution without needing Python installed on target machines:

```powershell
pip install pyinstaller
pyinstaller --clean ntro_threat_detect.spec
```

The output will be created in `dist/ntro_threat_detect/`:
```cmd
# Run complete demo
dist\ntro_threat_detect\ntro_threat_detect.exe demo

# Run backend server
dist\ntro_threat_detect\ntro_threat_detect.exe backend --host 127.0.0.1 --port 8000

# Run PCAP replay
dist\ntro_threat_detect\ntro_threat_detect.exe orchestrator --mode replay --pcap samples\demo\mixed_attacks.pcap
```

---

## 📂 8. Repository Structure

```
ntro-threat-detect/
├── backend/                  # FastAPI REST API & WebSocket event broadcaster
│   ├── main.py               # REST endpoints, WebSocket manager & static file mount
├── pipeline/                 # Core streaming detection pipeline
│   ├── ingest/               # Unidirectional packet capture (receive-only)
│   ├── flow/                 # 5-tuple canonical flow reconstruction
│   ├── features/             # Feature extractors (DDoS, C2, DGA, JA3, Recon, Exfil)
│   ├── detectors/            # 6 parallel AI & heuristic detector engines
│   ├── aggregator/           # Deduplication & severity scoring
│   ├── queue.py              # Bounded priority event queue
│   └── orchestrator.py       # Master pipeline orchestrator
├── dashboard/
│   └── static/               # Dark SOC web dashboard (HTML5, Vanilla CSS, Chart.js)
│       ├── index.html        # Overview screen with KPI cards & live streaming table
│       ├── alerts.html       # Alert explorer with filters & side-drawer triage panel
│       ├── analytics.html    # Threat volume trends, donut charts & model cards
│       ├── sensors.html      # Sensor status & data diode compliance matrix
│       ├── style.css         # SOC theme stylesheet (#0F1620 palette)
│       └── app.js            # WebSocket client & table renderers
├── storage/                  # SQLite database models & SQLAlchemy ORM
├── samples/
│   └── demo/                 # Curated PCAP captures for showcase & testing
│       ├── benign_baseline.pcap
│       ├── mixed_attacks.pcap
│       └── ddos_burst.pcap
├── models/                   # Serialized trained scikit-learn models (.joblib)
├── tools/                    # Benchmarking, dataset generators & diagnostic utilities
│   ├── benchmark.py          # Throughput and latency benchmarking tool
│   ├── build_demo_pcaps.py   # Curated demo PCAP generator
│   └── check_capture.py      # Network interface and Npcap diagnostic tool
├── tests/                    # 235 pytest unit and integration test cases
├── launcher.py               # Unified CLI launcher entry point
├── run_demo.bat              # One-click Windows showcase launch script
├── ntro_threat_detect.spec   # PyInstaller packaging specification
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 🧪 9. Automated Testing

All features, detectors, flow engines, APIs, and pipelines are validated by an automated test suite:
```powershell
pytest -v
```
**Test Results:**
```
tests/test_backend_api.py ............                                   [ 5%]
tests/test_benchmark.py ...                                              [ 6%]
tests/test_build_training_set.py ....                                    [ 8%]
tests/test_check_capture.py ....                                         [ 9%]
tests/test_detectors_ml.py ............                                  [14%]
tests/test_detectors_rule_stat.py ............                           [20%]
tests/test_features_c2_beacon.py .......................                 [29%]
tests/test_features_ddos.py ...............                              [36%]
tests/test_features_dga_dns.py ...........................               [47%]
tests/test_features_encrypted_malware.py .......................         [57%]
tests/test_features_exfil.py .........................                   [68%]
tests/test_features_recon.py .................                           [75%]
tests/test_flow_builder.py ....................                          [83%]
tests/test_flow_listener.py ....................                         [92%]
tests/test_live_capture.py .........                                     [96%]
tests/test_pcap_replay.py ........                                       [99%]
tests/test_pipeline_e2e.py .                                             [100%]

============================= 235 passed in 60.63s =============================
```

---

## 🔒 10. Security & Directionality Guarantee

The system strictly adheres to the **Passive Network Tap Philosophy**:
1. **Zero Outbound Sockets**: Detector code has no socket connection or packet transmission logic.
2. **No Payload Decryption**: Evaluates encrypted communications solely via unencrypted TLS handshake metadata (JA3 hashes, cipher lists, SNI, extensions).
3. **Localhost Isolation**: Web dashboard and REST APIs bind to loopback (`127.0.0.1`) only.
4. **Data Diode Verification**: AST analysis verifies that no transmit APIs are present in the packet ingestion path.
