"""
tests/test_features_dga_dns.py — Tests for pipeline/features/dga_dns.py

Core assertion: a DGA-like domain (e.g. 'kq3xzv9f2j.com') must have
  • HIGHER entropy than a natural domain (e.g. 'google.com')
  • LOWER  n-gram score (more negative) than a natural domain

This validates that the offline n-gram model actually separates
algorithmically generated names from real-world ones.

All tests are deterministic — no randomness, no internet.
"""

from __future__ import annotations

import pytest

from pipeline.features.dga_dns import (
    score_domain,
    extract_dns_features,
    _extract_label,
    _MODEL,
)


# ═══════════════════════════════════════════════════════════════════════════
# Label extraction tests
# ═══════════════════════════════════════════════════════════════════════════

class TestLabelExtraction:

    def test_simple_domain(self):
        assert _extract_label("example.com") == "example"

    def test_subdomain(self):
        assert _extract_label("www.example.com") == "example"

    def test_deep_subdomain(self):
        assert _extract_label("a.b.c.example.com") == "example"

    def test_co_uk_style(self):
        """'co' is ≤3 chars, so go one level deeper."""
        assert _extract_label("google.co.uk") == "google"

    def test_trailing_dot(self):
        assert _extract_label("example.com.") == "example"

    def test_single_label(self):
        assert _extract_label("localhost") == "localhost"


# ═══════════════════════════════════════════════════════════════════════════
# N-gram model tests
# ═══════════════════════════════════════════════════════════════════════════

class TestNGramModel:

    def test_model_loaded(self):
        """The module-level model should be initialised at import time."""
        assert _MODEL is not None
        assert _MODEL._vocab_size > 0

    def test_natural_text_higher_likelihood(self):
        """'google' should score higher than random gibberish."""
        score_natural = _MODEL.bigram_log_likelihood("google")
        score_gibberish = _MODEL.bigram_log_likelihood("kq3xzv9f2j")
        assert score_natural > score_gibberish

    def test_trigram_natural_higher(self):
        score_natural = _MODEL.trigram_log_likelihood("microsoft")
        score_gibberish = _MODEL.trigram_log_likelihood("xrwq7m3p5k")
        assert score_natural > score_gibberish

    def test_combined_score_direction(self):
        natural = _MODEL.combined_score("facebook")
        dga = _MODEL.combined_score("a1b2c3d4e5")
        assert natural > dga

    def test_very_short_string(self):
        """Single character → 0.0 (not enough data)."""
        assert _MODEL.bigram_log_likelihood("a") == 0.0
        assert _MODEL.trigram_log_likelihood("ab") == 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Per-domain scoring tests
# ═══════════════════════════════════════════════════════════════════════════

class TestScoreDomain:

    def test_dga_vs_normal_entropy(self):
        """⭐ KEY: DGA domain has HIGHER entropy than normal domain."""
        dga = score_domain("kq3xzv9f2j.com")
        normal = score_domain("google.com")

        assert dga["entropy"] > normal["entropy"], (
            f"DGA entropy ({dga['entropy']:.3f}) should be > "
            f"normal entropy ({normal['entropy']:.3f})"
        )

    def test_dga_vs_normal_ngram(self):
        """⭐ KEY: DGA domain has LOWER (more negative) n-gram score."""
        dga = score_domain("kq3xzv9f2j.com")
        normal = score_domain("google.com")

        assert dga["ngram_score"] < normal["ngram_score"], (
            f"DGA ngram ({dga['ngram_score']:.3f}) should be < "
            f"normal ngram ({normal['ngram_score']:.3f})"
        )

    def test_dga_high_digit_ratio(self):
        """DGA with many digits → high digit_ratio."""
        dga = score_domain("a1b2c3d4e5.net")
        assert dga["digit_ratio"] == pytest.approx(0.5)

    def test_normal_low_digit_ratio(self):
        """Normal domain → digit_ratio ≈ 0."""
        normal = score_domain("google.com")
        assert normal["digit_ratio"] == pytest.approx(0.0)

    def test_label_length(self):
        dga = score_domain("kq3xzv9f2j.com")
        assert dga["label_length"] == 10

    def test_num_labels(self):
        assert score_domain("a.b.example.com")["num_labels"] == 4

    def test_multiple_dga_examples(self):
        """Several DGA-like names should all score worse than natural ones."""
        dga_names = [
            "xk7wq3rm5p.com",
            "a1b2c3d4e5.xyz",
            "qzxjvwkrmn.top",
            "9f8e7d6c5b.net",
        ]
        natural_names = [
            "google.com",
            "microsoft.com",
            "stackoverflow.com",
            "wikipedia.org",
        ]

        dga_scores = [score_domain(d)["ngram_score"] for d in dga_names]
        nat_scores = [score_domain(d)["ngram_score"] for d in natural_names]

        avg_dga = sum(dga_scores) / len(dga_scores)
        avg_nat = sum(nat_scores) / len(nat_scores)

        assert avg_nat > avg_dga, (
            f"Natural avg ({avg_nat:.3f}) should be > DGA avg ({avg_dga:.3f})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Aggregate DNS feature tests
# ═══════════════════════════════════════════════════════════════════════════

def _query(qname="example.com", qtype="A", src_ip="10.0.0.1", timestamp=0.0):
    return {"qname": qname, "qtype": qtype, "src_ip": src_ip, "timestamp": timestamp}


class TestExtractDnsFeatures:

    def test_empty_queries(self):
        result = extract_dns_features([])
        assert result["mean_entropy"] == 0.0
        assert result["unique_qnames"] == 0

    def test_txt_null_ratio(self):
        """Half TXT queries → ratio 0.5."""
        queries = (
            [_query(qtype="A")] * 5
            + [_query(qtype="TXT")] * 5
        )
        result = extract_dns_features(queries)
        assert result["txt_null_ratio"] == pytest.approx(0.5)

    def test_all_normal_queries(self):
        """All A queries → txt_null_ratio = 0."""
        queries = [_query(qtype="A") for _ in range(10)]
        result = extract_dns_features(queries)
        assert result["txt_null_ratio"] == pytest.approx(0.0)

    def test_query_rate(self):
        """10 queries in 2 seconds → 5 qps."""
        queries = [
            _query(timestamp=float(i) * 0.2) for i in range(10)
        ]
        result = extract_dns_features(queries)
        # 10 queries over 1.8s ≈ 5.56 qps
        assert result["query_rate"] > 4.0

    def test_unique_qnames(self):
        queries = [
            _query(qname=f"host{i}.example.com") for i in range(5)
        ]
        result = extract_dns_features(queries)
        assert result["unique_qnames"] == 5

    def test_unique_subdomains_per_apex(self):
        """5 unique subdomains under same apex → mean = 5."""
        queries = [
            _query(qname=f"sub{i}.evil.com", timestamp=float(i))
            for i in range(5)
        ]
        result = extract_dns_features(queries)
        assert result["unique_subdomains_per_apex"] == pytest.approx(5.0)

    def test_dns_tunnel_signature(self):
        """DNS tunnel traffic: many unique subdomains + TXT + high rate."""
        # Simulate 50 TXT queries with unique encoded subdomains
        queries = [
            _query(
                qname=f"{'x' * 30}{i}.tunnel.com",
                qtype="TXT",
                timestamp=float(i) * 0.1,
            )
            for i in range(50)
        ]
        result = extract_dns_features(queries)

        assert result["txt_null_ratio"] == pytest.approx(1.0)
        assert result["unique_subdomains_per_apex"] >= 45
        assert result["query_rate"] > 5.0  # fast queries
        assert result["mean_label_length"] > 5  # long labels

    def test_normal_dns_traffic(self):
        """Normal browsing: few queries, A type, normal domains."""
        queries = [
            _query(qname="google.com", qtype="A", timestamp=0.0),
            _query(qname="facebook.com", qtype="A", timestamp=1.0),
            _query(qname="github.com", qtype="A", timestamp=5.0),
        ]
        result = extract_dns_features(queries)

        assert result["txt_null_ratio"] == pytest.approx(0.0)
        assert result["unique_subdomains_per_apex"] == pytest.approx(0.0)
        assert result["mean_ngram_score"] > -15  # natural domains (small corpus → scores ~-11)

    def test_all_feature_keys_present(self):
        queries = [_query()]
        result = extract_dns_features(queries)
        expected = {
            "mean_entropy", "mean_ngram_score", "mean_label_length",
            "max_label_length", "txt_null_ratio", "query_rate",
            "unique_qnames", "unique_subdomains_per_apex", "mean_digit_ratio",
        }
        assert expected == set(result.keys())
