"""Latency summary helpers. """

from __future__ import annotations

import math
from collections.abc import Sequence


def percentile(values: Sequence[float], p: float) -> float:
    """Nearest-rank percentile, ``0 < p <= 100``."""
    if not values:
        raise ValueError("percentile() needs at least one value")
    if not 0 < p <= 100:
        raise ValueError("p must be in (0, 100]")
    ordered = sorted(values)
    rank = math.ceil(p / 100 * len(ordered))
    return ordered[rank - 1]


def summarize(values: Sequence[float]) -> dict[str, float]:
    """n / average / p50 / p95 / max of a list of latencies in ms."""
    if not values:
        raise ValueError("summarize() needs at least one value")
    return {
        "n": float(len(values)),
        "avg": sum(values) / len(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "max": max(values),
    }
