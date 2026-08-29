"""
pipeline/aggregator/__init__.py — Alert fusion, scoring, and de-duplication package.
"""

from pipeline.aggregator.aggregator import (
    AlertAggregator,
    compute_severity,
    DEFAULT_THREAT_WEIGHTS,
    SEVERITY_THRESHOLDS,
)

__all__ = [
    "AlertAggregator",
    "compute_severity",
    "DEFAULT_THREAT_WEIGHTS",
    "SEVERITY_THRESHOLDS",
]
