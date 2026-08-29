"""
launcher.py — Unified Command-Line Entry Point for Packaged Distributable.

Supports:
  • python launcher.py backend [--host 127.0.0.1 --port 8000]
  • python launcher.py orchestrator [--mode replay|live] [--pcap ...] [--interface ...]
  • python launcher.py demo
  • python launcher.py benchmark [--rates 5,20,50,100]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

# Ensure root directory is on sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def run_backend(host: str = "127.0.0.1", port: int = 8000):
    """Run FastAPI / Uvicorn server."""
    import uvicorn
    from backend.main import app

    print(f"[*] Starting NTRO Threat Detection API on http://{host}:{port} ...")
    uvicorn.run(app, host=host, port=port, log_level="info")


def run_orchestrator(args: list[str]):
    """Run streaming pipeline orchestrator."""
    from pipeline.orchestrator import main as orch_main

    sys.argv = [sys.argv[0]] + args
    orch_main()


def run_demo():
    """Launch backend server in background thread, open browser, and replay demo PCAP."""
    import threading
    import uvicorn
    from backend.main import app
    from pipeline.orchestrator import run_pipeline

    demo_pcap = BASE_DIR / "samples" / "demo" / "mixed_attacks.pcap"
    if not demo_pcap.exists():
        demo_pcap = BASE_DIR / "samples" / "sample.pcap"

    server_thread = threading.Thread(
        target=lambda: uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning"),
        daemon=True,
    )
    server_thread.start()
    print("[*] Backend server started on http://127.0.0.1:8000")

    time.sleep(2)
    print("[*] Launching browser to SOC Overview...")
    webbrowser.open("http://127.0.0.1:8000")

    print(f"[*] Starting live replay of curated demo PCAP: {demo_pcap.name} ...")
    import asyncio
    asyncio.run(run_pipeline(mode="replay", pcap_path=str(demo_pcap), rate="10mbps"))
    print("[*] Replay completed. Server running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")


def run_benchmark(args: list[str]):
    """Run throughput/latency benchmark."""
    from tools.benchmark import main as bench_main

    sys.argv = [sys.argv[0]] + args
    bench_main()


def main():
    parser = argparse.ArgumentParser(description="NTRO Cyber Threat Detection System")
    subparsers = parser.add_subparsers(dest="command", help="Operational Mode")

    # Backend subcommand
    p_back = subparsers.add_parser("backend", help="Run REST API and WebSocket server")
    p_back.add_argument("--host", default="127.0.0.1", help="Binding IP (default: 127.0.0.1)")
    p_back.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")

    # Orchestrator subcommand
    subparsers.add_parser("orchestrator", help="Run streaming packet analysis pipeline")

    # Demo subcommand
    subparsers.add_parser("demo", help="Run complete live demo with browser dashboard")

    # Benchmark subcommand
    subparsers.add_parser("benchmark", help="Run throughput and latency benchmark")

    parsed, remaining = parser.parse_known_args()

    if parsed.command == "backend":
        run_backend(parsed.host, parsed.port)
    elif parsed.command == "orchestrator":
        run_orchestrator(remaining)
    elif parsed.command == "demo":
        run_demo()
    elif parsed.command == "benchmark":
        run_benchmark(remaining)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
