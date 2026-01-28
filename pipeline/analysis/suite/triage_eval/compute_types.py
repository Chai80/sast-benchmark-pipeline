"""pipeline.analysis.suite.triage_eval.compute_types

Shared types for triage evaluation computation.

The intent is to keep the main compute entrypoints small and split the large
implementation into focused submodules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class TriageEvalComputeResult:
    """All computed tables + summary sub-structures.

    The public build_triage_eval() entrypoint writes these tables to disk and
    assembles the final summary JSON.
    """

    by_case_rows: List[Dict[str, Any]]
    deltas_by_case_rows: List[Dict[str, Any]]
    topk_rows: List[Dict[str, Any]]

    tool_rows: List[Dict[str, Any]]
    tool_marginal_rows: List[Dict[str, Any]]

    macro: Dict[str, Dict[str, Dict[str, Any]]]
    micro: Dict[str, Dict[str, Dict[str, Any]]]
    delta_vs_baseline: Dict[str, Any]

    topk_focus: Dict[str, Any]
    calibration_context: Optional[Dict[str, Any]]

    cases_with_gt: List[str]
    cases_without_gt: List[str]
    cases_no_clusters: List[str]
    cases_with_gt_but_no_clusters: List[str]
    cases_with_gt_but_no_overlaps: List[str]


__all__ = [
    "TriageEvalComputeResult",
]
