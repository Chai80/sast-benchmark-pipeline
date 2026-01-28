"""pipeline.analysis.suite.triage_calibration

Internal implementation for suite-level triage calibration.

External code should continue to import from
:mod:`pipeline.analysis.suite.suite_triage_calibration`.

This package exists mainly to keep ``pipeline.analysis.suite`` from being
cluttered with many ``triage_calibration_*`` modules while keeping each file
small (≈<300 LOC).
"""

from .build import build_triage_calibration
from .core import (
    TRIAGE_CALIBRATION_SCHEMA_V1,
    TRIAGE_CALIBRATION_SCHEMA_VERSION,
    TRIAGE_CALIBRATION_SUPPORTED_VERSIONS,
    CalibrationParamsV1,
    load_triage_calibration,
    log_odds,
    smoothed_precision,
)
from .scoring import (
    tool_weights_for_owasp,
    tool_weights_from_calibration,
    triage_score_v1,
    triage_score_v1_for_row,
)

__all__ = [
    # Schemas / types
    "TRIAGE_CALIBRATION_SCHEMA_V1",
    "TRIAGE_CALIBRATION_SCHEMA_VERSION",
    "TRIAGE_CALIBRATION_SUPPORTED_VERSIONS",
    "CalibrationParamsV1",
    # Math helpers
    "smoothed_precision",
    "log_odds",
    # Readers / builders
    "load_triage_calibration",
    "build_triage_calibration",
    # Weight extraction
    "tool_weights_from_calibration",
    "tool_weights_for_owasp",
    # Scoring
    "triage_score_v1",
    "triage_score_v1_for_row",
]
