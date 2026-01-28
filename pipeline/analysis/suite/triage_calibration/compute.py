"""pipeline.analysis.suite.triage_calibration.compute

Pure-ish in-memory computations used by the triage calibration builder.

This module contains:
- accumulation of TP/FP counts (global + per OWASP slice)
- derived statistics / report row generation

It intentionally avoids filesystem writes.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

from .core import (
    CalibrationParamsV1,
    _normalize_owasp_id,
    _parse_tools_any,
    _round6,
    _to_int,
    log_odds,
    smoothed_precision,
)


def _case_has_gt(suite_dir: Path, case_id: str) -> bool:
    p = Path(suite_dir) / "cases" / str(case_id) / "gt" / "gt_score.json"
    return p.exists() and p.is_file()


@dataclass
class _CalibrationCounts:
    """Internal accumulator state for calibration stats."""

    tp: Dict[str, int]
    fp: Dict[str, int]

    tp_by_owasp: Dict[str, Dict[str, int]]
    fp_by_owasp: Dict[str, Dict[str, int]]

    support_clusters_by_owasp: Dict[str, int]
    support_cases_by_owasp: Dict[str, set[str]]
    overlap_sum_by_owasp: Dict[str, int]

    per_case_clusters: Dict[str, int]
    per_case_overlap_sum: Dict[str, int]


def _new_calibration_counts() -> _CalibrationCounts:
    return _CalibrationCounts(
        tp={},
        fp={},
        tp_by_owasp=defaultdict(lambda: defaultdict(int)),
        fp_by_owasp=defaultdict(lambda: defaultdict(int)),
        support_clusters_by_owasp=defaultdict(int),
        support_cases_by_owasp=defaultdict(set),
        overlap_sum_by_owasp=defaultdict(int),
        per_case_clusters={},
        per_case_overlap_sum={},
    )


def _partition_cases_by_gt(
    *,
    suite_dir: Path,
    case_ids: Sequence[str],
) -> Tuple[list[str], list[str], set[str]]:
    """Split case_ids into (included_cases, excluded_cases_no_gt, included_set)."""

    included_cases: list[str] = []
    excluded_cases_no_gt: list[str] = []

    for cid in case_ids:
        if _case_has_gt(suite_dir, cid):
            included_cases.append(str(cid))
        else:
            excluded_cases_no_gt.append(str(cid))

    included_set = set(included_cases)
    return included_cases, excluded_cases_no_gt, included_set


def _accumulate_calibration_counts(
    *,
    rows: Sequence[Mapping[str, Any]],
    included_set: set[str],
) -> _CalibrationCounts:
    """Accumulate TP/FP counts and per-slice support for included cases."""

    counts = _new_calibration_counts()

    for r in rows:
        cid = str(r.get("case_id") or "").strip()
        if not cid or cid not in included_set:
            continue

        counts.per_case_clusters[cid] = counts.per_case_clusters.get(cid, 0) + 1
        ov = _to_int(r.get("gt_overlap"), default=0)
        counts.per_case_overlap_sum[cid] = counts.per_case_overlap_sum.get(cid, 0) + ov

        tools = _parse_tools_any(r.get("tools_json") or r.get("tools") or "")
        for t in tools:
            if ov == 1:
                counts.tp[t] = counts.tp.get(t, 0) + 1
            else:
                counts.fp[t] = counts.fp.get(t, 0) + 1

        oid = _normalize_owasp_id(r.get("owasp_id"))
        if oid:
            counts.support_clusters_by_owasp[oid] += 1
            counts.support_cases_by_owasp[oid].add(cid)
            counts.overlap_sum_by_owasp[oid] += int(ov)
            for t in tools:
                if ov == 1:
                    counts.tp_by_owasp[oid][t] += 1
                else:
                    counts.fp_by_owasp[oid][t] += 1

    return counts


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
    "_CalibrationCounts",
    "_partition_cases_by_gt",
    "_accumulate_calibration_counts",
    "_build_suspicious_cases",
    "_compute_tool_stats",
    "_build_tool_stats_by_owasp",
    "_flatten_report_by_owasp_rows",
]
