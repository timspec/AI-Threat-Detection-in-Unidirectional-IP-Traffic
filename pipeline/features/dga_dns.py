"""
pipeline/features/dga_dns.py — Feature extraction for DGA domains & DNS tunnelling.

Two levels of analysis:

1. **Per-domain scoring** — ``score_domain(name)`` returns entropy,
   n-gram log-likelihood, and label-length stats for a single domain.
   DGA names score high entropy + low likelihood; natural names are the
   opposite.

2. **Aggregate DNS features** — ``extract_dns_features(queries)`` takes
   a list of DNS query records and returns per-source aggregate features
   (query rate, TXT/NULL ratio, unique subdomains per apex) that
   characterise DNS tunnelling.

The n-gram model is built **at import time** from a hardcoded list of
~200 common English words and real domain labels.  No internet call or
paid API is ever made.
"""

from __future__ import annotations

import math
import string
from collections import Counter, defaultdict
from typing import Any

from pipeline.features.common import shannon_entropy, safe_ratio


# ═══════════════════════════════════════════════════════════════════════════
# Hardcoded corpus — common English words + popular domain labels
# ═══════════════════════════════════════════════════════════════════════════
# This is intentionally bundled inline so the module is self-contained
# and never reaches out to the internet.

_CORPUS_WORDS: list[str] = [
    # ── Common English words (natural character patterns) ─────────
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "day", "get", "has", "him", "his",
    "how", "its", "may", "new", "now", "old", "see", "way", "who", "did",
    "about", "after", "again", "being", "below", "between", "both",
    "could", "does", "doing", "down", "during", "each", "even", "every",
    "first", "from", "give", "going", "great", "have", "here", "high",
    "home", "house", "into", "just", "keep", "know", "last", "left",
    "life", "like", "line", "long", "look", "made", "make", "many",
    "might", "more", "most", "much", "must", "name", "need", "never",
    "next", "only", "open", "other", "over", "part", "people", "place",
    "point", "right", "same", "school", "should", "show", "side", "since",
    "small", "some", "state", "still", "story", "such", "take", "tell",
    "than", "that", "them", "then", "there", "these", "they", "thing",
    "think", "this", "time", "turn", "under", "very", "want", "water",
    "well", "were", "what", "when", "where", "which", "while", "will",
    "with", "word", "work", "world", "would", "year", "your",
    "system", "network", "server", "client", "data", "file", "user",
    "service", "application", "security", "information", "computer",
    "software", "hardware", "internet", "protocol", "address", "domain",
    "database", "management", "process", "support", "update", "access",
    "account", "online", "digital", "cloud", "mobile", "platform",
    "content", "search", "media", "social", "market", "business",
    "company", "product", "customer", "email", "login", "password",
    # ── Popular domain labels (real-world domains) ────────────────
    "google", "facebook", "amazon", "microsoft", "apple", "netflix",
    "twitter", "instagram", "linkedin", "youtube", "reddit", "github",
    "stackoverflow", "wikipedia", "yahoo", "cloudflare", "akamai",
    "fastly", "shopify", "stripe", "paypal", "dropbox", "slack",
    "spotify", "pinterest", "tumblr", "wordpress", "blogger",
    "medium", "quora", "twitch", "discord", "telegram", "whatsapp",
    "signal", "zoom", "webex", "teams", "outlook", "office",
    "windows", "ubuntu", "debian", "fedora", "centos", "alpine",
    "docker", "kubernetes", "terraform", "ansible", "jenkins",
    "gitlab", "bitbucket", "jira", "confluence", "notion",
    "national", "international", "government", "education",
    "university", "research", "hospital", "health", "science",
    "technology", "engineering", "weather", "travel", "news",
]


# ═══════════════════════════════════════════════════════════════════════════
# N-gram language model (built at import time)
# ═══════════════════════════════════════════════════════════════════════════

class _NGramModel:
    """Character-level bigram + trigram language model.

    Built from a corpus of words.  Scores new strings by average
    log₂-probability of their n-grams under the model with Laplace
    (add-1) smoothing.
    """

    def __init__(self, corpus: list[str]) -> None:
        self._bigram_counts: Counter[str] = Counter()
        self._trigram_counts: Counter[str] = Counter()
        self._char_counts: Counter[str] = Counter()
        self._vocab_size: int = 0

        self._fit(corpus)

    def _fit(self, corpus: list[str]) -> None:
        """Extract n-gram frequencies from the corpus."""
        all_text = " ".join(w.lower() for w in corpus)

        for ch in all_text:
            self._char_counts[ch] += 1

        for i in range(len(all_text) - 1):
            self._bigram_counts[all_text[i : i + 2]] += 1

        for i in range(len(all_text) - 2):
            self._trigram_counts[all_text[i : i + 3]] += 1

        self._vocab_size = len(set(all_text))

    def bigram_log_likelihood(self, text: str) -> float:
        """Average log₂ probability of character bigrams in *text*.

        Uses Laplace (add-1) smoothing so unseen bigrams get a small
        non-zero probability instead of −∞.

        Returns
        -------
        float
            Negative value (log-prob).  Less negative → more natural.
            Returns 0.0 if text is too short.
        """
        text = text.lower()
        if len(text) < 2:
            return 0.0

        total_bigrams = sum(self._bigram_counts.values())
        vocab_sq = self._vocab_size ** 2  # possible bigrams

        log_sum = 0.0
        n = 0
        for i in range(len(text) - 1):
            bg = text[i : i + 2]
            count = self._bigram_counts.get(bg, 0)
            # Laplace smoothing
            prob = (count + 1) / (total_bigrams + vocab_sq)
            log_sum += math.log2(prob)
            n += 1

        return log_sum / n if n > 0 else 0.0

    def trigram_log_likelihood(self, text: str) -> float:
        """Average log₂ probability of character trigrams in *text*."""
        text = text.lower()
        if len(text) < 3:
            return 0.0

        total_trigrams = sum(self._trigram_counts.values())
        vocab_cu = self._vocab_size ** 3

        log_sum = 0.0
        n = 0
        for i in range(len(text) - 2):
            tg = text[i : i + 3]
            count = self._trigram_counts.get(tg, 0)
            prob = (count + 1) / (total_trigrams + vocab_cu)
            log_sum += math.log2(prob)
            n += 1

        return log_sum / n if n > 0 else 0.0

    def combined_score(self, text: str, bigram_weight: float = 0.4) -> float:
        """Weighted average of bigram and trigram log-likelihoods.

        Higher (less negative) → more natural language-like.
        Lower (more negative) → more DGA-like.
        """
        bi = self.bigram_log_likelihood(text)
        tri = self.trigram_log_likelihood(text)
        return bigram_weight * bi + (1 - bigram_weight) * tri


# Module-level model instance — built once at import time.
# No internet call, no file I/O — just in-memory computation.
_MODEL = _NGramModel(_CORPUS_WORDS)


# ═══════════════════════════════════════════════════════════════════════════
# Per-domain DGA scoring
# ═══════════════════════════════════════════════════════════════════════════

def _extract_label(domain: str) -> str:
    """Extract the registerable label (2LD) from a domain name.

    'sub.example.com' → 'example'
    'kq3xzv9f2j.net' → 'kq3xzv9f2j'
    'google.co.uk'   → 'google'  (simplified — ignores public suffix list)
    """
    parts = domain.rstrip(".").lower().split(".")
    if len(parts) >= 2:
        # Heuristic: if the second-to-last part is very short (≤3 chars)
        # like 'co', 'com', 'org', treat the third-to-last as the label.
        if len(parts) >= 3 and len(parts[-2]) <= 3:
            return parts[-3]
        return parts[-2]
    return parts[0] if parts else ""


def score_domain(domain: str) -> dict[str, Any]:
    """Score a single domain name for DGA-likeness.

    Parameters
    ----------
    domain : str
        Full domain name (e.g. ``'kq3xzv9f2j.com'``).

    Returns
    -------
    dict with:
        label            The extracted registerable label
        entropy          Shannon entropy of the label's characters
        bigram_ll        Bigram log-likelihood (higher → more natural)
        trigram_ll       Trigram log-likelihood
        ngram_score      Combined weighted n-gram score
        label_length     Length of the label
        num_labels       Number of dot-separated parts in the full domain
        digit_ratio      Fraction of characters that are digits
        consonant_ratio  Fraction of characters that are consonants
    """
    label = _extract_label(domain)
    parts = domain.rstrip(".").split(".")

    chars = list(label)
    entropy = shannon_entropy(chars) if chars else 0.0

    # N-gram likelihood
    bi_ll = _MODEL.bigram_log_likelihood(label)
    tri_ll = _MODEL.trigram_log_likelihood(label)
    ngram = _MODEL.combined_score(label)

    # Character composition
    if len(label) > 0:
        digit_count = sum(1 for c in label if c.isdigit())
        consonants = set("bcdfghjklmnpqrstvwxyz")
        consonant_count = sum(1 for c in label.lower() if c in consonants)
        digit_ratio = digit_count / len(label)
        consonant_ratio = consonant_count / len(label)
    else:
        digit_ratio = 0.0
        consonant_ratio = 0.0

    return {
        "label": label,
        "entropy": entropy,
        "bigram_ll": bi_ll,
        "trigram_ll": tri_ll,
        "ngram_score": ngram,
        "label_length": len(label),
        "num_labels": len(parts),
        "digit_ratio": digit_ratio,
        "consonant_ratio": consonant_ratio,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Aggregate DNS tunnel features (per-source, over a window of queries)
# ═══════════════════════════════════════════════════════════════════════════

# Common DNS query types
_TUNNEL_QTYPES = {"TXT", "NULL", "CNAME", "MX", "10", "16", "255"}


def extract_dns_features(
    queries: list[dict],
) -> dict[str, Any]:
    """Extract aggregate DNS features for tunnelling detection.

    Parameters
    ----------
    queries : list[dict]
        DNS query records, each containing at least:
        ``qname`` (str), ``qtype`` (str or int), ``src_ip`` (str),
        ``timestamp`` (float).

    Returns
    -------
    dict with:
        mean_entropy             Mean Shannon entropy across all queried labels
        mean_ngram_score         Mean n-gram score across all queried labels
        mean_label_length        Mean label length
        max_label_length         Maximum label length
        txt_null_ratio           Fraction of TXT / NULL queries
        query_rate               Queries per second
        unique_qnames            Number of unique query names
        unique_subdomains_per_apex  Mean unique subdomains per apex domain
        mean_digit_ratio         Mean digit ratio across labels
    """
    if not queries:
        return _empty_dns_features()

    # ── Per-domain scores ─────────────────────────────────────────
    domain_scores: list[dict] = []
    for q in queries:
        qname = q.get("qname", "")
        if qname:
            domain_scores.append(score_domain(qname))

    if not domain_scores:
        return _empty_dns_features()

    entropies = [s["entropy"] for s in domain_scores]
    ngram_scores = [s["ngram_score"] for s in domain_scores]
    label_lengths = [s["label_length"] for s in domain_scores]
    digit_ratios = [s["digit_ratio"] for s in domain_scores]

    # ── Query-type distribution ───────────────────────────────────
    qtypes = [str(q.get("qtype", "A")).upper() for q in queries]
    tunnel_count = sum(1 for qt in qtypes if qt in _TUNNEL_QTYPES)
    txt_null_ratio = safe_ratio(tunnel_count, len(qtypes))

    # ── Timing ────────────────────────────────────────────────────
    timestamps = [q.get("timestamp", 0.0) for q in queries]
    if len(timestamps) >= 2:
        window_dur = max(timestamps) - min(timestamps)
        query_rate = safe_ratio(len(queries), max(window_dur, 1e-9))
    else:
        query_rate = 0.0

    # ── Unique names ──────────────────────────────────────────────
    unique_qnames = len({q.get("qname", "") for q in queries})

    # ── Unique subdomains per apex ────────────────────────────────
    # Apex = last two labels (e.g. 'example.com')
    apex_subdomains: dict[str, set[str]] = defaultdict(set)
    for q in queries:
        qname = q.get("qname", "").rstrip(".").lower()
        parts = qname.split(".")
        if len(parts) >= 3:
            apex = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
            apex_subdomains[apex].add(subdomain)

    if apex_subdomains:
        mean_subs = sum(len(v) for v in apex_subdomains.values()) / len(apex_subdomains)
    else:
        mean_subs = 0.0

    return {
        "mean_entropy": sum(entropies) / len(entropies),
        "mean_ngram_score": sum(ngram_scores) / len(ngram_scores),
        "mean_label_length": sum(label_lengths) / len(label_lengths),
        "max_label_length": max(label_lengths),
        "txt_null_ratio": txt_null_ratio,
        "query_rate": query_rate,
        "unique_qnames": unique_qnames,
        "unique_subdomains_per_apex": mean_subs,
        "mean_digit_ratio": sum(digit_ratios) / len(digit_ratios),
    }


def _empty_dns_features() -> dict[str, Any]:
    return {
        "mean_entropy": 0.0,
        "mean_ngram_score": 0.0,
        "mean_label_length": 0.0,
        "max_label_length": 0,
        "txt_null_ratio": 0.0,
        "query_rate": 0.0,
        "unique_qnames": 0,
        "unique_subdomains_per_apex": 0.0,
        "mean_digit_ratio": 0.0,
    }
