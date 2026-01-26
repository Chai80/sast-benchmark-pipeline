from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.checks

Filesystem-first validation helpers for the triage calibration workflow.

This module contains the check builders and the main
:func:`validate_calibration_suite_artifacts` entrypoint.

Rule of thumb: helpers here should only *read* artifacts. Writing artifacts is
handled in :mod:`pipeline.analysis.qa_calibration_runbook.write`.
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.analysis.io.config_receipts import summarize_scanner_config

from .model import CalibrationSuiteValidationOptions, QACheck


def print_checklist(checks: Sequence[QACheck]) -> None:
    """Print a compact PASS/FAIL checklist."""

    for c in checks:
        status = "FAIL" if (not c.ok) else ("WARN" if bool(getattr(c, "warn", False)) else "PASS")
        suffix = ""
        if c.path:
            suffix += f"  [{c.path}]"
        if c.detail:
            suffix += ("  " if suffix else "  ") + str(c.detail)
        print(f"  [{status}] {c.name}{suffix}")


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _read_csv_header(path: Path) -> List[str]:
    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, [])
    return [str(h).strip() for h in (header or []) if str(h).strip()]


def _read_csv_dict_rows(path: Path) -> List[Dict[str, str]]:
    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


def _parse_json_list(raw: str) -> List[str]:
    s = str(raw or "").strip()
    if not s:
        return []
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
    except Exception:
        return []
    return []


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


def _to_int(x: Any, default: int = 0) -> int:
    """Best-effort int parsing for checklist validation.

    Accepts strings, floats, ints; returns default on failure.
    """

    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _csv_has_any_nonempty_value(path: Path, *, column: str) -> bool:
    """Return True if *any* row has a non-empty value in the given column."""

    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or (column not in reader.fieldnames):
            return False
        for row in reader:
            v = row.get(column)
            if v is None:
                continue
            if str(v).strip() != "":
                return True
    return False


def _case_dirs(suite_dir: Path) -> List[Path]:
    cases_dir = Path(suite_dir) / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        return []
    out = [p for p in cases_dir.iterdir() if p.is_dir()]
    out.sort(key=lambda p: p.name)
    return out


def _discover_case_triage_queue_csv(case_dir: Path) -> Optional[Path]:
    """Best-effort locate triage_queue.csv for one case."""
    case_dir = Path(case_dir)
    preferred = case_dir / "analysis" / "_tables" / "triage_queue.csv"
    if preferred.exists():
        return preferred
    legacy = case_dir / "analysis" / "triage_queue.csv"
    if legacy.exists():
        return legacy
    return None


def _suite_plan_scanners(suite_dir: Path) -> List[str]:
    """Best-effort extract expected scanners from suite.json."""

    suite_json = Path(suite_dir) / "suite.json"
    if not suite_json.exists():
        return []
    try:
        raw = _read_json(suite_json)
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    plan = raw.get("plan")
    if not isinstance(plan, dict):
        return []
    scanners = plan.get("scanners")
    if not isinstance(scanners, list):
        return []
    return sorted(set([str(x).strip() for x in scanners if str(x).strip()]))


def _check_exists(
    name: str,
    path: Path,
    *,
    required: bool = True,
    missing_detail: str = "missing",
    ok_detail_if_not_required: str = "",
) -> QACheck:
    """Create a simple existence check.

    We keep this helper intentionally small: it removes repeated boilerplate
    without hiding behavior.
    """

    p = Path(path)
    if not required:
        return QACheck(name=name, ok=True, path=str(p), detail=str(ok_detail_if_not_required))

    ok = p.exists()
    return QACheck(name=name, ok=ok, path=str(p), detail="" if ok else str(missing_detail))


def _checks_scanner_receipts(suite_dir: Path) -> List[QACheck]:
    """Validate scanner receipts (profiles + config receipts) for reproducibility."""

    expected_scanners = _suite_plan_scanners(suite_dir)
    sc = summarize_scanner_config(suite_dir, scanners=expected_scanners)

    receipts_found = _to_int(sc.get("receipts_found"), 0)
    profile = sc.get("profile")
    profile_mode = str(sc.get("profile_mode") or "")
    missing_tools = sc.get("missing_tools") if isinstance(sc.get("missing_tools"), list) else []
    warnings_list = sc.get("warnings") if isinstance(sc.get("warnings"), list) else []

    ok_profile = bool(profile) and profile_mode != "unknown"
    ok_receipts = receipts_found > 0 and (len(missing_tools) == 0)
    warn_profile = profile_mode == "mixed"

    detail_parts: List[str] = []
    if not ok_receipts:
        if receipts_found <= 0:
            detail_parts.append("no config_receipt.json found under cases/*/tool_runs")
        if missing_tools:
            detail_parts.append(
                f"missing receipts for tools: {sorted(set([str(x) for x in missing_tools]))}"
            )
    if warn_profile:
        detail_parts.append(f"profile drift inside suite: profile_mode={profile_mode}")
    if warnings_list:
        detail_parts.append("; ".join([str(w) for w in warnings_list if str(w).strip()]))

    return [
        QACheck(
            name="profile recorded + config receipts exist",
            ok=bool(ok_profile and ok_receipts),
            warn=bool(warn_profile or (warnings_list and ok_profile and ok_receipts)),
            path=str(suite_dir / "cases"),
            detail="; ".join([p for p in detail_parts if str(p).strip()]),
        )
    ]


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


def _checks_calibration_artifacts(
    analysis_dir: Path,
    tables_dir: Path,
    *,
    expect_calibration: bool,
) -> List[QACheck]:
    """Validate suite-level calibration outputs."""

    checks: List[QACheck] = []

    triage_cal_json = Path(analysis_dir) / "triage_calibration.json"
    triage_cal_report = Path(tables_dir) / "triage_calibration_report.csv"

    checks.append(
        _check_exists(
            "analysis/triage_calibration.json exists",
            triage_cal_json,
            required=bool(expect_calibration),
            ok_detail_if_not_required="skipped (non-scored mode)",
        )
    )

    if expect_calibration and triage_cal_json.exists():
        try:
            cal_data = json.loads(triage_cal_json.read_text(encoding="utf-8"))
        except Exception as e:
            checks.append(
                QACheck(
                    name="analysis/triage_calibration.json parses",
                    ok=False,
                    path=str(triage_cal_json),
                    detail=str(e),
                )
            )
        else:
            included_cases = cal_data.get("included_cases") if isinstance(cal_data, dict) else None
            ok_inc = isinstance(included_cases, list) and len(included_cases) > 0
            checks.append(
                QACheck(
                    name="triage_calibration includes >=1 GT-supported case",
                    ok=ok_inc,
                    path=str(triage_cal_json),
                    detail=(
                        ""
                        if ok_inc
                        else "included_cases is empty - suite may have no GT cases; calibration not meaningful"
                    ),
                )
            )

    checks.append(
        _check_exists(
            "analysis/_tables/triage_calibration_report.csv exists",
            triage_cal_report,
            required=bool(expect_calibration),
            ok_detail_if_not_required="skipped (non-scored mode)",
        )
    )

    return checks


def _checks_triage_queue(
    suite_dir: Path,
    *,
    require_scored_queue: bool,
) -> List[QACheck]:
    """Validate per-case triage_queue.csv files and (optionally) that they are scored."""

    suite_dir = Path(suite_dir)
    checks: List[QACheck] = []

    queue_by_case: Dict[str, Path] = {}
    missing_queue_cases: List[str] = []
    for case_dir in _case_dirs(suite_dir):
        cid = case_dir.name
        p = _discover_case_triage_queue_csv(case_dir)
        if p is None:
            missing_queue_cases.append(cid)
        else:
            queue_by_case[cid] = p

    checks.append(
        QACheck(
            name="per-case triage_queue.csv exists",
            ok=(len(missing_queue_cases) == 0 and len(queue_by_case) > 0),
            detail=(
                ""
                if (len(missing_queue_cases) == 0 and len(queue_by_case) > 0)
                else (
                    "no triage_queue.csv found"
                    if not queue_by_case
                    else f"missing for cases: {sorted(missing_queue_cases)}"
                )
            ),
            path=str(suite_dir / "cases"),
        )
    )

    # If no queues exist, we cannot validate schema.
    if not queue_by_case:
        checks.append(
            QACheck(
                name="triage_queue.csv contains column triage_score_v1",
                ok=False,
                detail="no triage_queue.csv found under cases/*/analysis (analysis may have been skipped)",
                path=str(suite_dir / "cases"),
            )
        )
        return checks

    missing_col_cases: List[str] = []
    read_errors: List[str] = []
    for cid in sorted(queue_by_case.keys()):
        p = queue_by_case[cid]
        try:
            header = _read_csv_header(p)
            if "triage_score_v1" not in header:
                missing_col_cases.append(cid)
        except Exception as e:
            read_errors.append(f"{cid}: {e}")

    ok_schema = (not missing_col_cases) and (not read_errors)
    detail_parts: List[str] = []
    if missing_col_cases:
        detail_parts.append(f"missing triage_score_v1 for cases: {sorted(missing_col_cases)}")
    if read_errors:
        detail_parts.append(f"CSV read errors: {read_errors}")

    checks.append(
        QACheck(
            name="triage_queue.csv contains column triage_score_v1",
            ok=ok_schema,
            detail="; ".join(detail_parts),
            path=str(suite_dir / "cases"),
        )
    )

    if not require_scored_queue:
        checks.append(
            QACheck(
                name="triage_queue.csv has non-empty triage_score_v1",
                ok=True,
                detail="skipped (no reanalyze)",
                path=str(suite_dir / "cases"),
            )
        )
        return checks

    any_scored = False
    for cid in sorted(queue_by_case.keys()):
        p = queue_by_case[cid]
        try:
            if _csv_has_any_nonempty_value(p, column="triage_score_v1"):
                any_scored = True
                break
        except Exception:
            continue

    checks.append(
        QACheck(
            name="triage_queue.csv has non-empty triage_score_v1",
            ok=bool(any_scored),
            detail=""
            if any_scored
            else "all triage_score_v1 values are empty (calibration likely not applied)",
            path=str(suite_dir / "cases"),
        )
    )

    return checks


def _checks_triage_eval(tables_dir: Path, *, expect_calibration: bool) -> List[QACheck]:
    """Validate triage_eval strategy outputs and tool utility/marginal tables."""

    tables_dir = Path(tables_dir)
    eval_summary = tables_dir / "triage_eval_summary.json"

    tool_utility_csv = tables_dir / "triage_tool_utility.csv"
    tool_marginal_csv = tables_dir / "triage_tool_marginal.csv"

    if not expect_calibration:
        return [
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(eval_summary),
            ),
            QACheck(
                name="triage_eval_summary includes strategy calibrated_global",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(eval_summary),
            ),
            QACheck(
                name="analysis/_tables/triage_tool_utility.csv exists",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(tool_utility_csv),
            ),
            QACheck(
                name="analysis/_tables/triage_tool_marginal.csv exists",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(tool_marginal_csv),
            ),
        ]

    checks: List[QACheck] = []
    checks.append(
        _check_exists("analysis/_tables/triage_tool_utility.csv exists", tool_utility_csv)
    )
    checks.append(
        _check_exists("analysis/_tables/triage_tool_marginal.csv exists", tool_marginal_csv)
    )

    if not eval_summary.exists():
        checks.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated_global",
                ok=False,
                detail="missing triage_eval_summary.json",
                path=str(eval_summary),
            )
        )
        checks.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=False,
                detail="missing triage_eval_summary.json",
                path=str(eval_summary),
            )
        )
        return checks

    try:
        payload = _read_json(eval_summary)
        strategies = payload.get("strategies") if isinstance(payload, dict) else None
        strategies_list = list(strategies) if isinstance(strategies, list) else []
        ok_calibrated = "calibrated" in strategies_list
        ok_global = "calibrated_global" in strategies_list
        detail_calibrated = "" if ok_calibrated else f"strategies={strategies_list}"
        detail_global = "" if ok_global else f"strategies={strategies_list}"

        checks.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=ok_calibrated,
                detail=detail_calibrated,
                path=str(eval_summary),
            )
        )
        checks.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated_global",
                ok=ok_global,
                detail=detail_global,
                path=str(eval_summary),
            )
        )
        return checks
    except Exception as e:
        checks.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=False,
                detail=f"failed to read/parse JSON: {e}",
                path=str(eval_summary),
            )
        )

        checks.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated_global",
                ok=False,
                detail=f"failed to read/parse JSON: {e}",
                path=str(eval_summary),
            )
        )
        return checks


def validate_calibration_suite_artifacts(
    suite_dir: str | Path,
    *,
    require_scored_queue: bool = True,
    expect_calibration: bool = True,
    expect_gt_tolerance_sweep: bool = False,
    expect_gt_tolerance_selection: bool = False,
) -> List[QACheck]:
    """Validate suite-level artifacts for the triage calibration workflow.

    This is intentionally filesystem-first: it validates that expected artifacts
    were produced under runs/suites/<suite_id>/analysis/.

    Returns a list of checks. Use :func:`all_ok` to decide pass/fail.
    """

    options = CalibrationSuiteValidationOptions(
        require_scored_queue=bool(require_scored_queue),
        expect_calibration=bool(expect_calibration),
        expect_gt_tolerance_sweep=bool(expect_gt_tolerance_sweep),
        expect_gt_tolerance_selection=bool(expect_gt_tolerance_selection),
    )
    return _validate_calibration_suite_artifacts(suite_dir, options=options)


def _validate_calibration_suite_artifacts(
    suite_dir: str | Path,
    *,
    options: CalibrationSuiteValidationOptions,
) -> List[QACheck]:
    """Implementation helper that takes a single options object.

    This exists as scaffolding so future refactors can thread an options/context
    structure through the validation steps without growing the public signature.
    """

    suite_dir = Path(suite_dir).resolve()
    analysis_dir = suite_dir / "analysis"
    tables_dir = analysis_dir / "_tables"

    triage_dataset = tables_dir / "triage_dataset.csv"

    checks: List[QACheck] = []

    # 1) Reproducibility receipts (profiles/config)
    checks.extend(_checks_scanner_receipts(suite_dir))

    # 2) Optional GT tolerance artifacts (QA-driven)
    sel_checks, selected_gt_tolerance = _checks_gt_tolerance_selection(
        analysis_dir,
        expect_gt_tolerance_selection=bool(options.expect_gt_tolerance_selection),
    )
    checks.extend(sel_checks)
    checks.extend(
        _checks_gt_tolerance_sweep(
            analysis_dir,
            tables_dir,
            expect_gt_tolerance_sweep=bool(options.expect_gt_tolerance_sweep),
        )
    )

    # 3) Required suite artifacts
    checks.append(_check_exists("analysis/_tables/triage_dataset.csv exists", triage_dataset))
    checks.extend(_checks_gt_ambiguity(triage_dataset, selected_gt_tolerance=selected_gt_tolerance))
    checks.extend(
        _checks_calibration_artifacts(
            analysis_dir,
            tables_dir,
            expect_calibration=bool(options.expect_calibration),
        )
    )

    # 4) Per-case triage queue checks (schema + scored signal)
    checks.extend(
        _checks_triage_queue(suite_dir, require_scored_queue=bool(options.require_scored_queue))
    )

    # 5) triage_eval (strategies + tool utility/marginal)
    checks.extend(
        _checks_triage_eval(tables_dir, expect_calibration=bool(options.expect_calibration))
    )

    return checks
