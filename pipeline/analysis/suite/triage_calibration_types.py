"""pipeline.analysis.suite.triage_calibration_types

Types and schema constants for triage calibration.

This module is intentionally dependency-light so it can be imported by:
- the calibration builder
- calibration consumers (triage queue scoring, triage eval)
without creating circular imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

TRIAGE_CALIBRATION_SCHEMA_V1: str = "triage_calibration_v1"
TRIAGE_CALIBRATION_SCHEMA_VERSION: str = "triage_calibration_v2"

# Backwards compatible reader (we still accept v1 files).
TRIAGE_CALIBRATION_SUPPORTED_VERSIONS: set[str] = {
    TRIAGE_CALIBRATION_SCHEMA_V1,
    TRIAGE_CALIBRATION_SCHEMA_VERSION,
}


@dataclass(frozen=True)
class CalibrationParamsV1:
    """Parameter bundle for v1-style triage calibration.

    Note: this dataclass existed in the original monolithic module. It remains
    here to keep the public API stable.
    """

    # Smoothing
    alpha: float = 1.0
    beta: float = 1.0

    # Clamp for log-odds
    p_min: float = 0.01
    p_max: float = 0.99

    # Scoring params (stored in calibration json and used by triage_score_v1)
    agreement_lambda: float = 0.50
    severity_bonus: Mapping[str, float] = None  # type: ignore[assignment]

    # Per-OWASP selection guardrail
    #
    # A slice must have at least this many GT-scored clusters before we trust
    # its category-specific weights.
    min_support_by_owasp: int = 10

    def __post_init__(self) -> None:
        if self.severity_bonus is None:
            object.__setattr__(
                self,
                "severity_bonus",
                {
                    "HIGH": 0.25,
                    "MEDIUM": 0.10,
                    "LOW": 0.00,
                    "UNKNOWN": 0.00,
                },
            )


__all__ = [
    "TRIAGE_CALIBRATION_SCHEMA_V1",
    "TRIAGE_CALIBRATION_SCHEMA_VERSION",
    "TRIAGE_CALIBRATION_SUPPORTED_VERSIONS",
    "CalibrationParamsV1",
]
