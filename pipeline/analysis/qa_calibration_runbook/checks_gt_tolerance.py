from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.checks_gt_tolerance

Checklist checks related to GT tolerance selection/sweeps and overlap ambiguity.

These artifacts are optional and QA-driven: the suite can be analyzed without a
GT tolerance sweep, but when present we validate that the sweep and selection
outputs are well-formed.
"""

from pathlib import Path
from typing import Dict, List, Optional

from .checks_discovery import _check_exists
from .checks_io import _parse_json_list, _read_csv_dict_rows, _read_json, _to_int
from .model import QACheck


def _compute_gt_ambiguity_stats(dataset_csv: Path) -> Dict[str, int]:
    """Compute many-to-one / one-to-many ambiguity stats from triage_dataset.csv.

    This intentionally mirrors the sweep's ambiguity counters, but stays local
    to the QA checklist so we can surface warnings even when no sweep ran.
    """

    rows = _read_csv_dict_rows(dataset_csv)

    gt_id_to_cluster_count: Dict[str, int] = {}
    clusters_multi_gt = 0
    max_gt_ids_per_cluster = 0

    for r in rows:
        ids: List[str] = []

        raw_ids_json = str(r.get("gt_overlap_ids_json") or "").strip()
        if raw_ids_json:
            ids = _parse_json_list(raw_ids_json)

        # Fallback: semicolon list
        if not ids:
            raw_ids = str(r.get("gt_overlap_ids") or "").strip()
            if raw_ids:
                ids = [p.strip() for p in raw_ids.split(";") if p.strip()]

        if not ids:
            continue

        uniq = sorted(set(ids))
        if len(uniq) > 1:
            clusters_multi_gt += 1
        max_gt_ids_per_cluster = max(max_gt_ids_per_cluster, len(uniq))
        for gid in uniq:
            gt_id_to_cluster_count[gid] = int(gt_id_to_cluster_count.get(gid, 0)) + 1

    gt_ids_covered = len(gt_id_to_cluster_count)
    gt_ids_multi_cluster = sum(1 for _gid, c in gt_id_to_cluster_count.items() if int(c) > 1)
    max_clusters_per_gt_id = max([int(c) for c in gt_id_to_cluster_count.values()], default=0)

    return {
        "gt_ids_covered": int(gt_ids_covered),
        "clusters_multi_gt": int(clusters_multi_gt),
        "gt_ids_multi_cluster": int(gt_ids_multi_cluster),
        "max_gt_ids_per_cluster": int(max_gt_ids_per_cluster),
        "max_clusters_per_gt_id": int(max_clusters_per_gt_id),
    }


def _checks_gt_tolerance_selection(
    analysis_dir: Path,
    *,
    expect_gt_tolerance_selection: bool,
) -> tuple[list[QACheck], Optional[int]]:
    """Validate the GT tolerance selection artifact (optional, QA-driven)."""

    if not expect_gt_tolerance_selection:
        return [], None

    sel_json = Path(analysis_dir) / "gt_tolerance_selection.json"
    checks: List[QACheck] = []
    selected_gt_tolerance: Optional[int] = None

    checks.append(_check_exists("analysis/gt_tolerance_selection.json exists", sel_json))

    if not sel_json.exists():
        return checks, None

    try:
        payload = _read_json(sel_json)
    except Exception as e:  # pragma: no cover
        checks.append(
            QACheck(
                name="analysis/gt_tolerance_selection.json parses",
                ok=False,
                path=str(sel_json),
                detail=str(e),
            )
        )
        return checks, None

    sel_val = payload.get("selected_gt_tolerance") if isinstance(payload, dict) else None
    ok_val = False
    try:
        selected_gt_tolerance = int(sel_val)  # type: ignore[arg-type]
        ok_val = True
    except Exception:
        selected_gt_tolerance = None
        ok_val = False

    checks.append(
        QACheck(
            name="gt_tolerance_selection records selected_gt_tolerance",
            ok=ok_val,
            path=str(sel_json),
            detail="" if ok_val else f"selected_gt_tolerance={sel_val!r}",
        )
    )

    # Surface any selection warnings (non-fatal) directly in the checklist.
    warnings_list: List[str] = []
    if isinstance(payload, dict):
        sel_obj = payload.get("selection")
        if isinstance(sel_obj, dict):
            raw_warn = sel_obj.get("warnings")
            if isinstance(raw_warn, list):
                warnings_list = [str(w) for w in raw_warn if str(w).strip()]
        if not warnings_list:
            raw_warn2 = payload.get("warnings")
            if isinstance(raw_warn2, list):
                warnings_list = [str(w) for w in raw_warn2 if str(w).strip()]

    checks.append(
        QACheck(
            name="gt_tolerance_selection warnings",
            ok=True,
            warn=bool(warnings_list),
            path=str(sel_json),
            detail="; ".join(warnings_list) if warnings_list else "",
        )
    )

    return checks, selected_gt_tolerance


def _checks_gt_tolerance_sweep(
    analysis_dir: Path,
    tables_dir: Path,
    *,
    expect_gt_tolerance_sweep: bool,
) -> List[QACheck]:
    """Validate GT tolerance sweep artifacts and that each candidate analyzed cleanly."""

    if not expect_gt_tolerance_sweep:
        return []

    sweep_report = Path(tables_dir) / "gt_tolerance_sweep_report.csv"
    sweep_json = Path(analysis_dir) / "gt_tolerance_sweep.json"

    checks: List[QACheck] = []
    checks.append(
        _check_exists("analysis/_tables/gt_tolerance_sweep_report.csv exists", sweep_report)
    )
    checks.append(_check_exists("analysis/gt_tolerance_sweep.json exists", sweep_json))

    if not sweep_json.exists():
        return checks

    try:
        payload = _read_json(sweep_json)
    except Exception as e:
        checks.append(
            QACheck(
                name="analysis/gt_tolerance_sweep.json parses",
                ok=False,
                path=str(sweep_json),
                detail=str(e),
            )
        )
        return checks

    rows = payload.get("rows") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        checks.append(
            QACheck(
                name="gt_tolerance_sweep has analysis_rc=0 for all candidates",
                ok=False,
                path=str(sweep_json),
                detail="missing or invalid rows[] in sweep payload",
            )
        )
        return checks

    bad: List[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        t = _to_int(r.get("gt_tolerance"), 0)
        rc = _to_int(r.get("analysis_rc"), 0)
        if rc != 0:
            bad.append(f"{t}:{rc}")

    ok_rc = len(bad) == 0
    checks.append(
        QACheck(
            name="gt_tolerance_sweep has analysis_rc=0 for all candidates",
            ok=ok_rc,
            path=str(sweep_json),
            detail="" if ok_rc else f"non-zero analysis_rc for tolerances: {', '.join(bad)}",
        )
    )

    return checks


def _checks_gt_ambiguity(
    triage_dataset: Path,
    *,
    selected_gt_tolerance: Optional[int],
) -> List[QACheck]:
    """Surface GT ambiguity counters as non-fatal warnings."""

    triage_dataset = Path(triage_dataset)
    if not triage_dataset.exists():
        return []

    checks: List[QACheck] = []

    try:
        amb = _compute_gt_ambiguity_stats(triage_dataset)
    except Exception as e:  # pragma: no cover
        checks.append(
            QACheck(
                name="GT ambiguity stats computed",
                ok=False,
                path=str(triage_dataset),
                detail=str(e),
            )
        )
        return checks

    warn_amb = (int(amb.get("clusters_multi_gt", 0)) > 0) or (
        int(amb.get("gt_ids_multi_cluster", 0)) > 0
    )

    tol_suffix = (
        f" (gt_tolerance={selected_gt_tolerance})" if selected_gt_tolerance is not None else ""
    )
    detail = (
        f"many_to_one_clusters={int(amb.get('clusters_multi_gt', 0))}; "
        f"one_to_many_gt_ids={int(amb.get('gt_ids_multi_cluster', 0))}; "
        f"max_gt_ids_per_cluster={int(amb.get('max_gt_ids_per_cluster', 0))}; "
        f"max_clusters_per_gt_id={int(amb.get('max_clusters_per_gt_id', 0))}"
    )

    checks.append(
        QACheck(
            name=f"GT ambiguity warnings (many-to-one / one-to-many){tol_suffix}",
            ok=True,
            warn=bool(warn_amb),
            path=str(triage_dataset),
            detail=detail if warn_amb else "",
        )
    )
    return checks
