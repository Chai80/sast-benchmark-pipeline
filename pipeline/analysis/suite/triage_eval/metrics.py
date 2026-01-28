"""pipeline.analysis.suite.triage_eval.metrics

Shared helpers for parsing and metric computation for suite-level triage eval.

This module is an internal split of ``pipeline.analysis.suite.suite_triage_eval``.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

RankFn = Callable[[List[Dict[str, str]]], List[Dict[str, str]]]


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _to_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None:
            return float(default)
        return float(str(x))
    except Exception:
        return float(default)


def _parse_json_list(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        if isinstance(v, list):
            return [str(x) for x in v]
    except Exception:
        return []
    return []


def _parse_semicolon_list(raw: str) -> List[str]:
    if not raw:
        return []
    parts = [p.strip() for p in str(raw).split(";")]
    return [p for p in parts if p]


def _load_csv_rows(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


def _case_dirs(cases_dir: Path) -> List[Path]:
    if not cases_dir.exists():
        return []
    out = [p for p in cases_dir.iterdir() if p.is_dir()]
    out.sort(key=lambda p: p.name)
    return out


def _load_case_gt_ids(case_dir: Path) -> Tuple[Set[str], bool]:
    """Return (gt_ids, has_gt).

    has_gt is False if gt_score.json is missing or contains no GT ids.
    """
    p = Path(case_dir) / "gt" / "gt_score.json"
    if not p.exists():
        return set(), False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return set(), False

    rows: Any = None
    if isinstance(data, dict):
        rows = data.get("rows")
    elif isinstance(data, list):
        rows = data

    if not isinstance(rows, list):
        return set(), False

    gt_ids: Set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        gid = r.get("gt_id") or r.get("id")
        if gid:
            gt_ids.add(str(gid))

    return gt_ids, bool(gt_ids)


def _gt_ids_for_row(r: Dict[str, str]) -> List[str]:
    # Canonical list encoding.
    ids = _parse_json_list(str(r.get("gt_overlap_ids_json") or ""))
    if ids:
        return ids
    # Human-readable fallback.
    return _parse_semicolon_list(str(r.get("gt_overlap_ids") or ""))


def _tools_for_row(r: Dict[str, str]) -> List[str]:
    tools = _parse_json_list(str(r.get("tools_json") or ""))
    if tools:
        return tools
    raw = str(r.get("tools") or "")
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


@dataclass(frozen=True)
class CaseEval:
    case_id: str
    has_gt: bool
    gt_total: int
    n_clusters: int


def _micro_totals_for_rows(
    *,
    case_ids: Sequence[str],
    case_has_gt: Dict[str, bool],
    case_gt_total: Dict[str, int],
    k_list: Sequence[int],
    rows_by_case: Dict[str, List[Dict[str, str]]],
    rank_fn: RankFn,
) -> Dict[int, Dict[str, int]]:
    """Micro totals used for marginal value comparison (precision/coverage/neg)."""

    out: Dict[int, Dict[str, int]] = {
        int(k): {"tp": 0, "denom": 0, "covered": 0, "gt_total": 0, "neg": 0} for k in k_list
    }

    for cid in case_ids:
        if not case_has_gt.get(cid, False):
            continue
        gt_total = int(case_gt_total.get(cid, 0) or 0)

        case_rows = list(rows_by_case.get(cid) or [])
        ordered = rank_fn(case_rows) if case_rows else []

        for k in k_list:
            kk = int(k)
            k_eff = min(kk, len(ordered))
            top = ordered[:k_eff]

            tp = sum(1 for r in top if _to_int(r.get("gt_overlap"), 0) == 1)
            neg = sum(1 for r in top if _to_int(r.get("gt_overlap"), 0) == 0)

            covered_ids: Set[str] = set()
            if gt_total > 0:
                for r in top:
                    covered_ids.update(_gt_ids_for_row(r))
            covered = int(len(covered_ids)) if gt_total > 0 else 0

            out[kk]["tp"] += int(tp)
            out[kk]["denom"] += int(k_eff)
            out[kk]["neg"] += int(neg)
            if gt_total > 0:
                out[kk]["covered"] += int(covered)
                out[kk]["gt_total"] += int(gt_total)

    return out


def _metrics_from_totals(t: Mapping[str, int]) -> Dict[str, Any]:
    denom = int(t.get("denom", 0) or 0)
    gt_total = int(t.get("gt_total", 0) or 0)
    tp = int(t.get("tp", 0) or 0)
    covered = int(t.get("covered", 0) or 0)
    neg = int(t.get("neg", 0) or 0)
    return {
        "precision": None if denom == 0 else float(tp) / float(denom),
        "gt_coverage": None if gt_total == 0 else float(covered) / float(gt_total),
        "neg_in_topk": int(neg),
    }


def _compute_tool_cluster_counts(
    *,
    all_tools: Sequence[str],
    case_ids: Sequence[str],
    by_case: Dict[str, List[Dict[str, str]]],
    case_has_gt: Dict[str, bool],
) -> Dict[str, Dict[str, int]]:
    """Counts used to contextualize marginal value rows."""

    out: Dict[str, Dict[str, int]] = {
        str(t): {
            "clusters_with_tool": 0,
            "clusters_exclusive_total": 0,
            "clusters_exclusive_pos": 0,
            "clusters_exclusive_neg": 0,
        }
        for t in all_tools
    }

    for cid in case_ids:
        if not case_has_gt.get(cid, False):
            continue
        for r in by_case.get(cid) or []:
            tools = _tools_for_row(r)
            if not tools:
                continue

            for t in tools:
                tt = str(t)
                if tt not in out:
                    out[tt] = {
                        "clusters_with_tool": 0,
                        "clusters_exclusive_total": 0,
                        "clusters_exclusive_pos": 0,
                        "clusters_exclusive_neg": 0,
                    }
                out[tt]["clusters_with_tool"] += 1

            if len(tools) == 1:
                tt = str(tools[0])
                if tt not in out:
                    out[tt] = {
                        "clusters_with_tool": 0,
                        "clusters_exclusive_total": 0,
                        "clusters_exclusive_pos": 0,
                        "clusters_exclusive_neg": 0,
                    }

                out[tt]["clusters_exclusive_total"] += 1
                if _to_int(r.get("gt_overlap"), 0) == 1:
                    out[tt]["clusters_exclusive_pos"] += 1
                else:
                    out[tt]["clusters_exclusive_neg"] += 1

    for t, d in out.items():
        out[t] = {k: int(v) for k, v in d.items()}

    return out

