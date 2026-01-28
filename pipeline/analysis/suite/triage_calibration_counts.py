"""pipeline.analysis.suite.triage_calibration_counts

Internal helpers for accumulating calibration counts.

The calibration builder reads triage_dataset rows and needs to count tool-level
TP/FP (globally and per OWASP slice) while excluding cases that have no GT.

These helpers are kept separate from the build orchestrator to keep each file
small and focused.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

from .triage_calibration_utils import _normalize_owasp_id, _parse_tools_any, _to_int


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


__all__ = [
    "_CalibrationCounts",
    "_partition_cases_by_gt",
    "_accumulate_calibration_counts",
]
