"""pipeline.analysis.suite.triage_calibration_math

Small math helpers for triage calibration.

Kept separate to avoid pulling in heavier builder dependencies when the
functions are used for scoring.
"""

from __future__ import annotations

import math


def _clamp(p: float, lo: float, hi: float) -> float:
    return max(float(lo), min(float(hi), float(p)))


def smoothed_precision(tp: int, fp: int, *, alpha: float, beta: float) -> float:
    denom = float(tp + fp) + float(alpha) + float(beta)
    if denom <= 0:
        return 0.5
    return (float(tp) + float(alpha)) / denom


def log_odds(p: float, *, p_min: float, p_max: float) -> float:
    pp = _clamp(float(p), float(p_min), float(p_max))
    return math.log(pp / (1.0 - pp))


__all__ = [
    "smoothed_precision",
    "log_odds",
]
