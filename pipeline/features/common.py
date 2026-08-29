"""
pipeline/features/common.py — Shared feature-engineering utilities.

Provides reusable helper functions used by multiple threat-specific
feature extractors.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Sequence

# ── TCP flag bitmasks (standard RFC 793 values) ──────────────────────────
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def shannon_entropy(values: Sequence[Any]) -> float:
    """Compute Shannon entropy (in bits) of a discrete distribution.

    Parameters
    ----------
    values : sequence
        Any iterable of hashable items (e.g. IP addresses, port numbers).

    Returns
    -------
    float
        Entropy in bits.  ``0.0`` for an empty or single-value sequence;
        ``log₂(N)`` for a perfectly uniform distribution of N distinct
        values.

    Examples
    --------
    >>> shannon_entropy(["a", "a", "a"])       # all same → 0
    0.0
    >>> shannon_entropy(["a", "b"])             # perfectly uniform → 1.0
    1.0
    >>> round(shannon_entropy(["a", "b", "c", "d"]), 4)  # uniform → 2.0
    2.0
    """
    if not values:
        return 0.0

    counts = Counter(values)
    total = sum(counts.values())

    if total <= 1:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def safe_ratio(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Compute numerator / denominator, returning *default* if denominator is 0."""
    return numerator / denominator if denominator != 0 else default


def count_tcp_flags(packets: list[dict], flag_mask: int) -> int:
    """Count packets whose ``tcp_flags`` field has *flag_mask* set."""
    return sum(1 for p in packets if p.get("tcp_flags", 0) & flag_mask)
