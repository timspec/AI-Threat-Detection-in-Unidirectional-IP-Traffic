"""
tests/test_benchmark.py — Unit tests for the pipeline benchmark tool.
"""

import tempfile
from pathlib import Path
import pytest

from tools.benchmark import (
    generate_benchmark_pcap,
    run_single_benchmark_rate,
    generate_markdown_report,
)
from storage.db import init_db, close_db


def test_generate_benchmark_pcap():
    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_path = Path(tmp_dir) / "test_bench.pcap"
        generate_benchmark_pcap(str(pcap_path), num_packets=120)
        assert pcap_path.exists()
        assert pcap_path.stat().st_size > 500


def test_run_single_benchmark_rate():
    with tempfile.TemporaryDirectory() as tmp_dir:
        init_db(f"sqlite:///{Path(tmp_dir) / 'bench_test.db'}")
        pcap_path = Path(tmp_dir) / "test_bench.pcap"
        generate_benchmark_pcap(str(pcap_path), num_packets=100)

        import asyncio
        res = asyncio.run(run_single_benchmark_rate(str(pcap_path), target_rate_mbps=0.0))

        assert res["total_packets"] == 100
        assert res["flows_per_sec"] > 0
        assert res["median_latency_ms"] >= 0
        assert res["drop_count"] == 0
        assert res["compliant"] is True
        close_db()


def test_generate_markdown_report():
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_file = Path(tmp_dir) / "report.md"
        mock_results = [
            {
                "target_mbps": 5.0,
                "effective_mbps": 5.2,
                "packets_per_sec": 1200.0,
                "flows_per_sec": 850.0,
                "total_alerts": 12,
                "median_latency_ms": 1.2,
                "p95_latency_ms": 2.4,
                "drop_count": 0,
                "compliant": True,
            },
            {
                "target_mbps": 50.0,
                "effective_mbps": 48.9,
                "packets_per_sec": 8500.0,
                "flows_per_sec": 5200.0,
                "total_alerts": 45,
                "median_latency_ms": 2.1,
                "p95_latency_ms": 4.5,
                "drop_count": 0,
                "compliant": True,
            },
        ]
        generate_markdown_report(mock_results, report_file)
        assert report_file.exists()
        content = report_file.read_text(encoding="utf-8")
        assert "Benchmark Report" in content
        assert "50.0 Mbps" in content
        assert "PASS" in content
