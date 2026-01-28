from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.checks_triage

Checklist checks for per-case triage artifacts and triage evaluation outputs.

These checks validate that:
- each case has a triage_queue.csv (and optionally that it contains applied scores)
- suite-level triage evaluation artifacts exist and include expected strategies
"""

from pathlib import Path
from typing import Dict, List

from .checks_discovery import _case_dirs, _check_exists, _discover_case_triage_queue_csv
from .checks_io import _csv_has_any_nonempty_value, _read_csv_header, _read_json
from .model import QACheck


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
    checks.append(_check_exists("analysis/_tables/triage_tool_utility.csv exists", tool_utility_csv))
    checks.append(_check_exists("analysis/_tables/triage_tool_marginal.csv exists", tool_marginal_csv))

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
