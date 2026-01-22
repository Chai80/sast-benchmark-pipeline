"""pipeline.analysis.suite.triage_eval.metrics

Shared helpers for parsing and metric computation for suite-level triage eval.

This module is an internal split of ``pipeline.analysis.suite.suite_triage_eval``.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

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

