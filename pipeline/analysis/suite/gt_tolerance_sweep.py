"""pipeline.analysis.suite.gt_tolerance_sweep

Deterministic GT tolerance sweep + (optional) auto-selection.

This module is a backward-compatible facade.

Implementation details are split into:
- pipeline.analysis.suite.gt_tolerance.sweep
- pipeline.analysis.suite.gt_tolerance.snapshot
- pipeline.analysis.suite.gt_tolerance.report
"""

from __future__ import annotations

from .gt_tolerance.report import select_gt_tolerance_auto, write_gt_tolerance_selection
from .gt_tolerance.snapshot import disable_suite_calibration
from .gt_tolerance.sweep import (
    DEFAULT_GT_TOLERANCE_CANDIDATES,
    parse_gt_tolerance_candidates,
    run_gt_tolerance_sweep,
)

__all__ = [
    "DEFAULT_GT_TOLERANCE_CANDIDATES",
    "disable_suite_calibration",
    "parse_gt_tolerance_candidates",
    "run_gt_tolerance_sweep",
    "select_gt_tolerance_auto",
    "write_gt_tolerance_selection",
]
