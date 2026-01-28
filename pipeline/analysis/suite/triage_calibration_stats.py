"""pipeline.analysis.suite.triage_calibration_stats

Helpers for computing derived calibration statistics from accumulated counts.

These helpers are pure-ish transformations of in-memory dicts and are separated
from the build orchestrator to keep the core logic easier to test and review.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

from .triage_calibration_math import log_odds, smoothed_precision
from .triage_calibration_types import CalibrationParamsV1
from .triage_calibration_utils import _round6, _to_int


def _build_suspicious_cases(
    *,
    included_cases: Sequence[str],
    per_case_clusters: Mapping[str, int],
    per_case_overlap_sum: Mapping[str, int],
) -> list[Dict[str, Any]]:
    """Cases with GT + clusters but zero overlaps (audit warning)."""

    out: list[Dict[str, Any]] = []
    for cid in included_cases:
        n = int(per_case_clusters.get(cid, 0) or 0)
        ov_sum = int(per_case_overlap_sum.get(cid, 0) or 0)
        if n > 0 and ov_sum == 0:
            out.append(
                {
                    "case_id": str(cid),
                    "cluster_count": int(n),
                    "gt_overlap_sum": int(ov_sum),
                }
            )
    return out


def _compute_tool_stats(
    *,
    tp: Mapping[str, int],
    fp: Mapping[str, int],
    params: CalibrationParamsV1,
) -> list[Dict[str, Any]]:
    """Compute tool stat rows in stable tool ordering."""

    tools_all = sorted(set(list(tp.keys()) + list(fp.keys())))
    out: list[Dict[str, Any]] = []

    for t in tools_all:
        t_tp = int(tp.get(t, 0) or 0)
        t_fp = int(fp.get(t, 0) or 0)
        p = smoothed_precision(t_tp, t_fp, alpha=params.alpha, beta=params.beta)
        w = log_odds(p, p_min=params.p_min, p_max=params.p_max)
        out.append(
            {
                "tool": str(t),
                "tp": int(t_tp),
                "fp": int(t_fp),
                "p_smoothed": _round6(p),
                "weight": _round6(w),
            }
        )

    return out


def _build_tool_stats_by_owasp(
    *,
    params: CalibrationParamsV1,
    tp_by_owasp: Mapping[str, Mapping[str, int]],
    fp_by_owasp: Mapping[str, Mapping[str, int]],
    support_clusters_by_owasp: Mapping[str, int],
    support_cases_by_owasp: Mapping[str, set[str]],
    overlap_sum_by_owasp: Mapping[str, int],
) -> Dict[str, Any]:
    """Build per-OWASP tool stats slices (deterministic key + list ordering)."""

    out: Dict[str, Any] = {}

    for n in range(1, 11):
        oid = f"A{n:02d}"
        if oid not in support_clusters_by_owasp:
            continue

        tp_slice = tp_by_owasp.get(oid) or {}
        fp_slice = fp_by_owasp.get(oid) or {}

        stats = _compute_tool_stats(tp=tp_slice, fp=fp_slice, params=params)

        out[oid] = {
            "support": {
                "clusters": int(support_clusters_by_owasp.get(oid, 0) or 0),
                "cases": int(len(support_cases_by_owasp.get(oid) or set())),
                "gt_positive_clusters": int(overlap_sum_by_owasp.get(oid, 0) or 0),
            },
            "tool_stats": stats,
        }

    return out


def _flatten_report_by_owasp_rows(
    *,
    tool_stats_by_owasp: Mapping[str, Any],
    params: CalibrationParamsV1,
) -> list[Dict[str, Any]]:
    """Flatten per-OWASP tool stats into an audit-friendly CSV report."""

    report_by_owasp_rows: list[Dict[str, Any]] = []
    min_support = int(params.min_support_by_owasp)

    for n in range(1, 11):
        oid = f"A{n:02d}"
        slice_obj = tool_stats_by_owasp.get(oid)
        if not isinstance(slice_obj, dict):
            continue

        support = slice_obj.get("support") if isinstance(slice_obj.get("support"), dict) else {}
        support_clusters = _to_int(support.get("clusters"), default=0)
        support_cases = _to_int(support.get("cases"), default=0)
        gt_positive_clusters = _to_int(support.get("gt_positive_clusters"), default=0)

        fallback_to_global = 1 if support_clusters < min_support else 0

        stats = slice_obj.get("tool_stats") if isinstance(slice_obj.get("tool_stats"), list) else []
        for row in stats:
            if not isinstance(row, dict):
                continue
            tool = str(row.get("tool") or "").strip()
            if not tool:
                continue
            report_by_owasp_rows.append(
                {
                    "owasp_id": oid,
                    "tool": tool,
                    "tp": _to_int(row.get("tp"), default=0),
                    "fp": _to_int(row.get("fp"), default=0),
                    "p_smoothed": row.get("p_smoothed"),
                    "weight": row.get("weight"),
                    "support_clusters": int(support_clusters),
                    "support_cases": int(support_cases),
                    "gt_positive_clusters": int(gt_positive_clusters),
                    "min_support_by_owasp": int(min_support),
                    "fallback_to_global": int(fallback_to_global),
                }
            )

    return report_by_owasp_rows


__all__ = [
    "_build_suspicious_cases",
    "_compute_tool_stats",
    "_build_tool_stats_by_owasp",
    "_flatten_report_by_owasp_rows",
]
