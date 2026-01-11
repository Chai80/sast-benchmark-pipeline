"""pipeline.analyze_mode

Compatibility wrapper.

The implementation of analysis mode lives in :mod:`pipeline.execution.analyze_mode`.
This module re-exports the public API so existing imports keep working.
"""

from __future__ import annotations

from pipeline.execution.analyze_mode import AnalyzeRequest, run_analyze

__all__ = [
    "AnalyzeRequest",
    "run_analyze",
]
