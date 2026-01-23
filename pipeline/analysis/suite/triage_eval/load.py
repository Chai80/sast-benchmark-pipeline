"""pipeline.analysis.suite.triage_eval.load

Input loading for suite-level triage evaluation.

This module keeps I/O concerns (reading the triage dataset CSV and discovering
case directories) separate from metric computation and artifact writing.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .metrics import _case_dirs, _load_csv_rows
from .strategies import _load_suite_calibration, _rank_agreement, _rank_baseline, _rank_calibrated, _rank_calibrated_global


RankFn = Callable[[List[Dict[str, str]]], List[Dict[str, str]]]


def load_triage_dataset(
    *,
    suite_dir: Path,
    dataset_relpath: str,
) -> Tuple[Path, List[Dict[str, str]], Dict[str, List[Dict[str, str]]]]:
    """Load the suite triage dataset CSV and group rows by case_id."""

    suite_dir = Path(suite_dir).resolve()
    dataset_csv = suite_dir / dataset_relpath
    if not dataset_csv.exists():
        raise FileNotFoundError(f"triage_dataset.csv not found: {dataset_csv}")

    rows = _load_csv_rows(dataset_csv)

    by_case: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in rows:
        cid = str(r.get("case_id") or "").strip()
        if not cid:
            continue
        by_case[cid].append(r)

    return dataset_csv, rows, by_case


def resolve_case_ids(
    *,
    suite_dir: Path,
    by_case: Dict[str, List[Dict[str, str]]],
) -> Tuple[Path, List[str]]:
    """Resolve case IDs in stable order.

    Preferred source is the cases/ directory. If that doesn't exist (or is
    empty), we fall back to the dataset-derived case_ids.
    """

    cases_dir = (Path(suite_dir).resolve() / "cases").resolve()
    case_ids = [p.name for p in _case_dirs(cases_dir)]
    if not case_ids:
        case_ids = sorted(by_case.keys())
    return cases_dir, case_ids


def load_strategies(
    *,
    suite_dir: Path,
    out_dirname: str,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, RankFn]]:
    """Load optional suite calibration and construct ranking strategy fns."""

    cal = _load_suite_calibration(suite_dir, out_dirname=out_dirname)

    # Baseline evaluation must not be contaminated by calibration.
    # If calibration exists, triage_rank may already reflect calibrated ordering.
    use_triage_rank_for_baseline = not bool(cal)

    def _rank_base(rows: List[Dict[str, str]], *, _use: bool = use_triage_rank_for_baseline) -> List[Dict[str, str]]:
        return _rank_baseline(rows, use_triage_rank=_use)

    strategies: Dict[str, RankFn] = {
        "baseline": _rank_base,
        "agreement": _rank_agreement,
    }

    if cal:
        # Capture cal in default args for deterministic behavior.

        def _rank_cal_global(rows: List[Dict[str, str]], *, _cal: Dict[str, Any] = cal) -> List[Dict[str, str]]:
            return _rank_calibrated_global(rows, cal=_cal)

        def _rank_cal(rows: List[Dict[str, str]], *, _cal: Dict[str, Any] = cal) -> List[Dict[str, str]]:
            return _rank_calibrated(rows, cal=_cal)

        strategies["calibrated_global"] = _rank_cal_global
        strategies["calibrated"] = _rank_cal

    return cal, strategies


def normalize_ks(ks: Sequence[int]) -> List[int]:
    """Normalize/validate K values for top-K metrics."""

    k_list = sorted({int(k) for k in ks if int(k) > 0})
    if not k_list:
        k_list = [1, 3, 5, 10, 25, 50]
    return k_list
