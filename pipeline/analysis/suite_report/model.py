from __future__ import annotations

"""pipeline.analysis.suite_report.model

Dataclasses used by suite-level report generation.

This module is intentionally small: it defines the structures that flow between
loaders/compute/render helpers.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CaseRow:
    case_id: str
    tools_used: List[str]
    tools_missing: List[str]
    clusters: int
    triage_rows: int
    gt_matched: int
    gt_total: int
    match_rate: Optional[float]
    gap_total: Optional[int]
    top_severity: Optional[str]
    warnings: List[str]
    # relative pointers
    analysis_manifest: str
    triage_queue_csv: Optional[str]
    triage_queue_json: Optional[str]
    gt_score_json: Optional[str]
    gt_gap_queue_csv: Optional[str]
    hotspot_pack_json: Optional[str]
    # Tool findings counts (best-effort)
    #
    # - tool_findings: raw count from normalized.json (before Durinn analysis filters)
    # - tool_findings_filtered: count after Durinn filters (mode + exclude_prefixes/include_harness)
    tool_findings: Dict[str, Optional[int]]
    tool_findings_filtered: Dict[str, Optional[int]]


@dataclass(frozen=True)
class SuiteReportInputs:
    """Inputs for suite report generation.

    This structure is loaded from on-disk suite artifacts (suite.json, analysis
    manifests, aggregate tables, and optional QA/calibration outputs).
    """

    suite_dir: Path
    suite_id: str
    out_dirname: str
    analysis_dir: Path
    out_tables: Path

    suite: Dict[str, Any]
    plan: Dict[str, Any]
    scanners_requested: List[str]

    qa_manifest: Dict[str, Any]
    qa_scope: Optional[str]
    qa_no_reanalyze: Optional[bool]
    qa_calibration_manifest: Dict[str, Any]
    qa_result: Dict[str, Any]

    triage_calibration: Dict[str, Any]
    min_support_by_owasp: Optional[int]

    case_ids: List[str]


@dataclass
class _CaseScanSummary:
    """Per-case rows plus summary signals used by action items/pointers."""

    case_rows: List[CaseRow]
    tools_used_union: set[str]
    tools_missing_union: set[str]
    cases_missing_outputs: List[str]
    cases_no_clusters: List[str]
    cases_analyzed_ok: List[str]
    # Tools with 0 raw findings (normalized.json count)
    empty_tool_cases: Dict[str, List[str]]
    # Tools that had findings, but all were filtered out by Durinn filters (raw>0, filtered==0)
    filtered_to_zero_tool_cases: Dict[str, List[str]]
