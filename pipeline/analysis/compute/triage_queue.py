from __future__ import annotations

"""Triage queue computations.

This module contains the ranking logic behind the `triage_queue` stage.

The stage wrapper is responsible for I/O (writing CSV/JSON, storing rows).
"""

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pipeline.analysis.framework import AnalysisContext
from pipeline.analysis.suite.suite_triage_calibration import (
    load_triage_calibration,
    tool_weights_for_owasp,
    triage_score_v1,
)
from pipeline.analysis.utils.owasp import infer_owasp
from pipeline.analysis.stages.common.severity import max_severity, severity_rank
from pipeline.suites.layout import find_case_dir, suite_dir_from_case_dir


TRIAGE_QUEUE_SCHEMA_VERSION = "v1"

# NOTE: This list is a contract. Update tests if you change it.
TRIAGE_QUEUE_FIELDNAMES: List[str] = [
    "rank",
    "triage_score_v1",  # may be blank when no suite calibration exists
    "file_path",
    "start_line",
    "end_line",
    "tool_count",
    "tools",
    "total_findings",
    "max_severity",
    "sample_rule_id",
    "sample_title",
    "cluster_id",
]


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return float(default)


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _baseline_sort_key(r: Dict[str, Any]) -> tuple:
    """Legacy deterministic triage ordering."""

    return (
        -_as_int(r.get("_sev_rank"), 0),
        -_as_int(r.get("tool_count"), 0),
        -_as_int(r.get("total_findings"), 0),
        str(r.get("file_path") or ""),
        _as_int(r.get("start_line"), 0),
        # Final stable tie-break key (required for determinism)
        str(r.get("cluster_id") or ""),
    )


def rank_triage_rows(rows: List[Dict[str, Any]], *, calibrated: bool) -> List[Dict[str, Any]]:
    """Sort rows deterministically and assign 1-based rank.

    Contract:
      - If calibrated: primary sort triage_score_v1 desc, then fallback to legacy order.
      - If not calibrated: legacy deterministic order unchanged.
      - Always use stable tie-break keys (file_path, start_line, cluster_id).
    """

    if calibrated:
        rows.sort(
            key=lambda r: (-_as_float(r.get("triage_score_v1"), 0.0),) + _baseline_sort_key(r)
        )
    else:
        rows.sort(key=_baseline_sort_key)

    for i, r in enumerate(rows, start=1):
        r["rank"] = i
        r.pop("_sev_rank", None)
    return rows


def _choose_sample_item(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pick a representative finding from a cluster."""

    def _key(it: Dict[str, Any]) -> tuple:
        return (
            -severity_rank(it.get("severity")),
            str(it.get("tool") or ""),
            str(it.get("rule_id") or ""),
            str(it.get("title") or ""),
            str(it.get("finding_id") or ""),
        )

    best: Dict[str, Any] = {}
    best_key: tuple | None = None
    for it in items or []:
        if not isinstance(it, dict):
            continue
        k = _key(it)
        if best_key is None or k < best_key:
            best_key = k
            best = it
    return best


def _suite_dir_from_out_dir(out_dir: Path, *, suite_id: Optional[str]) -> Optional[Path]:
    """Best-effort resolve suite_dir from a per-case analysis out_dir."""

    try:
        case_dir = find_case_dir(out_dir)
        if not case_dir:
            return None
        suite_dir = suite_dir_from_case_dir(case_dir)
        if suite_id and suite_dir.name != str(suite_id):
            return None
        return suite_dir
    except Exception:
        return None


def _load_calibration_for_case(
    ctx: AnalysisContext,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, float], float, Dict[str, float], int]:
    """Best-effort load suite-level triage calibration for the case."""

    cal: Dict[str, Any] | None = None
    cal_weights: Dict[str, float] = {}
    agreement_lambda: float = 0.0
    severity_bonus: Dict[str, float] = {
        "HIGH": 0.25,
        "MEDIUM": 0.10,
        "LOW": 0.0,
        "UNKNOWN": 0.0,
    }
    min_support_by_owasp: int = 10

    # Best-effort category label for selecting per-OWASP calibration weights.
    case_owasp_id: str | None = None
    try:
        oid, _title = infer_owasp(ctx.case_id or "", out_dir=Path(ctx.out_dir))
        case_owasp_id = oid
    except Exception:
        case_owasp_id = None

    if not ctx.suite_id:
        return None, {}, agreement_lambda, severity_bonus, min_support_by_owasp

    suite_dir = _suite_dir_from_out_dir(Path(ctx.out_dir), suite_id=ctx.suite_id)
    if not suite_dir:
        return None, {}, agreement_lambda, severity_bonus, min_support_by_owasp

    try:
        cal_path = suite_dir / "analysis" / "triage_calibration.json"
        cal = load_triage_calibration(cal_path)
        if not cal:
            return None, {}, agreement_lambda, severity_bonus, min_support_by_owasp

        scoring = cal.get("scoring") if isinstance(cal, dict) else None
        if isinstance(scoring, dict):
            agreement_lambda = float(scoring.get("agreement_lambda", 0.0))
            try:
                min_support_by_owasp = int(scoring.get("min_support_by_owasp", 10))
            except Exception:
                min_support_by_owasp = 10

            sb = scoring.get("severity_bonus")
            if isinstance(sb, dict):
                severity_bonus = {str(k).upper(): float(v) for k, v in sb.items()}

        # Select per-OWASP weights when sufficiently supported; otherwise fall back to global.
        cal_weights = tool_weights_for_owasp(
            cal, owasp_id=case_owasp_id, min_support=min_support_by_owasp
        )
        return cal, cal_weights, agreement_lambda, severity_bonus, min_support_by_owasp
    except Exception:
        # Never fail per-case triage queue due to calibration issues.
        return None, {}, agreement_lambda, severity_bonus, min_support_by_owasp


def build_triage_queue_rows(
    ctx: AnalysisContext, clusters: Sequence[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Build a ranked triage queue.

    Returns (rows, meta). `meta` is safe to return from the stage.
    """

    cal, cal_weights, agreement_lambda, severity_bonus, _min_support = _load_calibration_for_case(
        ctx
    )

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        if not isinstance(c, dict):
            continue

        items = list(c.get("items") or [])
        tool_counts = Counter()
        for it in items:
            if not isinstance(it, dict):
                continue
            tool_counts[str(it.get("tool") or "")] += 1

        sev, sev_rank = max_severity(items)
        sample = _choose_sample_item(items)
        title = str(sample.get("title") or "")
        rule_id = str(sample.get("rule_id") or "")

        # Calibrated score (v1) when suite calibration exists.
        score_v1: str | float = ""
        if cal:
            try:
                score = triage_score_v1(
                    tools=list(c.get("tools") or []),
                    tool_count=int(c.get("tool_count") or 0),
                    max_severity=str(sev or "UNKNOWN"),
                    tool_weights=cal_weights,
                    agreement_lambda=agreement_lambda,
                    severity_bonus=severity_bonus,
                )
                score_v1 = float(f"{float(score):.6f}")
            except Exception:
                score_v1 = ""

        rows.append(
            {
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "tools": ",".join(c.get("tools") or []),
                "tool_count": int(c.get("tool_count") or 0),
                "total_findings": int(sum(tool_counts.values())),
                "max_severity": sev,
                "triage_score_v1": score_v1,
                "sample_rule_id": rule_id,
                "sample_title": title,
                "cluster_id": c.get("cluster_id"),
                "_sev_rank": sev_rank,
            }
        )

    rank_triage_rows(rows, calibrated=bool(cal))

    meta = {
        "rows": len(rows),
        "calibrated": bool(cal),
        "top_tool_count": int(rows[0]["tool_count"]) if rows else 0,
        "top_severity": (rows[0]["max_severity"] if rows else ""),
    }
    return rows, meta
