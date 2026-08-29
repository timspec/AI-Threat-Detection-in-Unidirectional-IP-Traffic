"""
tests/test_build_training_set.py — Tests for tools/build_training_set.py.

Covers:
  1. Stratified session-aware 70/15/15 train/val/test splitting
  2. Prevention of intra-session data leakage
  3. Metric calculation (Precision, Recall, F1, Confusion Matrix)
  4. Model Card Markdown file generation
"""

from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from tools.build_training_set import (
    EXPECTED_PCAPS,
    _compute_metrics,
    generate_model_card,
    split_dataset_by_session,
)


class TestDatasetSplitting:

    def test_expected_pcap_registry(self):
        """Registry must contain all 7 required PCAP filenames."""
        expected_keys = {
            "benign",
            "ddos",
            "c2_beacon",
            "dga_dns",
            "encrypted_malware",
            "recon_scan",
            "exfiltration",
        }
        assert set(EXPECTED_PCAPS.keys()) == expected_keys
        assert EXPECTED_PCAPS["benign"] == "benign_baseline.pcap"

    def test_split_proportions_and_stratification(self):
        """Split must produce ~70% train, ~15% val, ~15% test across multiple sessions."""
        rows = []
        for label in ["benign", "c2_beacon", "ddos"]:
            for sess_id in range(10):  # 10 sessions per label
                for flow_id in range(10):  # 10 flows per session
                    rows.append({
                        "session_id": f"{label}_sess_{sess_id}",
                        "flow_index": flow_id,
                        "label": label,
                        "val": flow_id * 1.5,
                    })

        df = pd.DataFrame(rows)
        train_df, val_df, test_df = split_dataset_by_session(
            df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15
        )

        total_len = len(df)
        assert len(train_df) + len(val_df) + len(test_df) == total_len
        assert 0.60 <= (len(train_df) / total_len) <= 0.80
        assert 0.10 <= (len(val_df) / total_len) <= 0.25
        assert 0.10 <= (len(test_df) / total_len) <= 0.25

        # Check session isolation: no session_id in train appears in test
        train_sessions = set(train_df["session_id"].unique())
        test_sessions = set(test_df["session_id"].unique())
        assert len(train_sessions.intersection(test_sessions)) == 0


class TestMetricsAndModelCards:

    def test_metric_calculations(self):
        """Precision, recall, and F1 calculations must match ground truth."""
        y_true = np.array([0, 0, 0, 1, 1, 1, 1, 1])
        y_pred = np.array([0, 0, 1, 0, 1, 1, 1, 1])

        metrics = _compute_metrics(y_true, y_pred)
        # tp=4, fp=1, fn=1, tn=2
        assert metrics["tp"] == 4
        assert metrics["fp"] == 1
        assert metrics["fn"] == 1
        assert metrics["tn"] == 2
        assert metrics["precision"] == pytest.approx(4 / 5)  # 0.80
        assert metrics["recall"] == pytest.approx(4 / 5)     # 0.80
        assert metrics["f1_score"] == pytest.approx(0.80)

    def test_model_card_generation(self):
        """Model card markdown document must contain key sections and metrics."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            card_path = Path(tmp_dir) / "model_card_test.md"
            dummy_metrics = {
                "precision": 0.9650,
                "recall": 0.9400,
                "f1_score": 0.9524,
                "tp": 94,
                "fp": 3,
                "tn": 97,
                "fn": 6,
            }

            generate_model_card(
                detector_name="TestDetector",
                algorithm="RandomForestClassifier",
                metrics=dummy_metrics,
                train_samples=700,
                test_samples=200,
                output_path=card_path,
            )

            assert card_path.exists()
            content = card_path.read_text(encoding="utf-8")
            assert "# Model Card: TestDetector" in content
            assert "0.9650" in content
            assert "Confusion Matrix" in content
            assert "Held-out TEST set" in content
