"""pipeline.analysis.suite.suite_triage_calibration

Suite-level triage calibration builder.

Historically this module contained the full implementation (700+ lines). To keep
files small and reduce "spaghetti" drift, the implementation has been split into
smaller, focused modules. This file remains as a compatibility facade so that
imports like:

    from pipeline.analysis.suite.suite_triage_calibration import build_triage_calibration

continue to work.
"""

from __future__ import annotations

from .triage_calibration_build import build_triage_calibration
from .triage_calibration_io import load_triage_calibration
from .triage_calibration_math import log_odds, smoothed_precision
from .triage_calibration_scoring import triage_score_v1, triage_score_v1_for_row
from .triage_calibration_types import (
    TRIAGE_CALIBRATION_SCHEMA_V1,
    TRIAGE_CALIBRATION_SCHEMA_VERSION,
    TRIAGE_CALIBRATION_SUPPORTED_VERSIONS,
    CalibrationParamsV1,
)
from .triage_calibration_weights import tool_weights_for_owasp, tool_weights_from_calibration

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
