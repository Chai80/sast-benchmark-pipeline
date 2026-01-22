"""pipeline.analysis.suite.suite_triage_eval

Suite-level evaluation for triage rankings.

This module is kept as a thin aggregator for compatibility. The implementation
lives under :mod:`pipeline.analysis.suite.triage_eval`.
"""

from __future__ import annotations

from pipeline.analysis.suite.triage_eval.metrics import CaseEval
from pipeline.analysis.suite.triage_eval.reports import build_triage_eval

__all__ = [
    "CaseEval",
    "build_triage_eval",
]
