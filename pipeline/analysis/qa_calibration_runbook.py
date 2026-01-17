from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook

Filesystem-first validation helpers for the triage calibration workflow.

Why this exists
---------------
The calibration pipeline is intentionally incremental:

1) Per-case analysis writes triage_features.csv (and triage_queue.csv).
2) Suite-level builders aggregate triage_dataset.csv and triage_calibration.json.
3) Per-case triage queue can optionally be re-analyzed to *apply* calibration
   weights (triage_score_v1 populated).

This module implements a small, deterministic QA checklist that validates the
expected suite artifacts exist under:

  runs/suites/<suite_id>/analysis/

The CLI exposes this via `--mode suite --qa-calibration`.

NOTE: For non-scored suites (no GT), some calibration artifacts may be empty or
not meaningful. See docs/triage_calibration.md for guidance.
"""

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


@dataclass(frozen=True)
class QACheck:
    """One checklist line item."""

    name: str
    ok: bool
    path: str = ""
    detail: str = ""


def render_checklist(checks: List[QACheck], *, title: str = "QA calibration checklist") -> str:
    """Render a concise PASS/FAIL checklist suitable for CLI output."""

    lines: List[str] = []
    lines.append(f"\n🔎 {title}")
    for c in checks:
        icon = "✅" if c.ok else "❌"
        lines.append(f"{icon} {c.name}")
        # Only show details for failures to keep output concise.
        if not c.ok:
            if c.path:
                lines.append(f"    path: {c.path}")
            if c.detail:
                lines.append(f"    {c.detail}")

    overall_ok = all(c.ok for c in checks)
    lines.append(f"\nOverall: {'PASS' if overall_ok else 'FAIL'}")
    return "\n".join(lines)


def all_ok(checks: Sequence[QACheck]) -> bool:
    return all(bool(c.ok) for c in checks)


def print_checklist(checks: Sequence[QACheck]) -> None:
    """Print a compact PASS/FAIL checklist."""

    for c in checks:
        status = "PASS" if c.ok else "FAIL"
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


def validate_calibration_suite_artifacts(
    suite_dir: str | Path,
    *,
    require_scored_queue: bool = True,
    expect_calibration: bool = True,
) -> List[QACheck]:
    """Validate suite-level artifacts for the triage calibration workflow.

    Returns a list of checks. Use :func:`all_ok` to decide pass/fail.

    Parameters
    ----------
    suite_dir:
        Suite directory like runs/suites/<suite_id> (or a resolved LATEST).
    require_scored_queue:
        If True, require at least one non-empty triage_score_v1 in a per-case
        triage_queue.csv. This is the strongest filesystem signal that calibration
        weights were actually applied (i.e., you ran the *second analyze pass*).

        Set this to False only if you intentionally skipped re-analyzing cases.
    expect_calibration:
        If True, require calibration artifacts and that triage_eval includes the
        calibrated strategy. For non-scored suites (no GT / no calibration), set
        this to False to relax calibration-specific checks.
    """

    suite_dir = Path(suite_dir).resolve()
    out: List[QACheck] = []

    analysis_dir = suite_dir / "analysis"
    tables_dir = analysis_dir / "_tables"

    # --- Expected suite-level artifacts ---------------------------------
    triage_dataset = tables_dir / "triage_dataset.csv"
    out.append(
        QACheck(
            name="analysis/_tables/triage_dataset.csv exists",
            ok=triage_dataset.exists(),
            path=str(triage_dataset),
            detail="" if triage_dataset.exists() else "missing",
        )
    )

    triage_cal_json = analysis_dir / "triage_calibration.json"
    out.append(
        QACheck(
            name="analysis/triage_calibration.json exists",
            ok=(triage_cal_json.exists() if expect_calibration else True),
            path=str(triage_cal_json),
            detail=(
                ""
                if (triage_cal_json.exists() and expect_calibration)
                else ("missing" if expect_calibration else "skipped (non-scored mode)")
            ),
        )
    )

    if expect_calibration and triage_cal_json.exists():
        try:
            cal_data = json.loads(triage_cal_json.read_text(encoding="utf-8"))
        except Exception as e:
            out.append(
                QACheck(
                    name="analysis/triage_calibration.json parses",
                    ok=False,
                    path=str(triage_cal_json),
                    detail=str(e),
                )
            )
        else:
            included_cases = cal_data.get("included_cases")
            ok_inc = isinstance(included_cases, list) and len(included_cases) > 0
            out.append(
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

    triage_cal_report = tables_dir / "triage_calibration_report.csv"
    out.append(
        QACheck(
            name="analysis/_tables/triage_calibration_report.csv exists",
            ok=(triage_cal_report.exists() if expect_calibration else True),
            path=str(triage_cal_report),
            detail=(
                ""
                if (triage_cal_report.exists() and expect_calibration)
                else ("missing" if expect_calibration else "skipped (non-scored mode)")
            ),
        )
    )

    # --- triage_queue existence + schema check --------------------------
    # We validate across *all* cases in the suite (deterministic order)
    # so schema drift does not go unnoticed.
    queue_by_case: Dict[str, Path] = {}
    missing_queue_cases: List[str] = []
    for case_dir in _case_dirs(suite_dir):
        cid = case_dir.name
        p = _discover_case_triage_queue_csv(case_dir)
        if p is None:
            missing_queue_cases.append(cid)
        else:
            queue_by_case[cid] = p

    out.append(
        QACheck(
            name="per-case triage_queue.csv exists",
            ok=(len(missing_queue_cases) == 0 and len(queue_by_case) > 0),
            detail=(
                ""
                if (len(missing_queue_cases) == 0 and len(queue_by_case) > 0)
                else (
                    "no triage_queue.csv found" if not queue_by_case else f"missing for cases: {sorted(missing_queue_cases)}"
                )
            ),
            path=str(suite_dir / "cases"),
        )
    )

    # If no queues exist, we cannot validate schema.
    if queue_by_case:
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

        out.append(
            QACheck(
                name="triage_queue.csv contains column triage_score_v1",
                ok=ok_schema,
                detail="; ".join(detail_parts),
                path=str(suite_dir / "cases"),
            )
        )

        # End-to-end signal: at least one triage_queue row should have a scored value
        # once calibration has been built and the suite re-analyzed.
        if require_scored_queue:
            any_scored = False
            for cid in sorted(queue_by_case.keys()):
                p = queue_by_case[cid]
                try:
                    if _csv_has_any_nonempty_value(p, column="triage_score_v1"):
                        any_scored = True
                        break
                except Exception:
                    continue

            out.append(
                QACheck(
                    name="triage_queue.csv has non-empty triage_score_v1",
                    ok=bool(any_scored),
                    detail="" if any_scored else "all triage_score_v1 values are empty (calibration likely not applied)",
                    path=str(suite_dir / "cases"),
                )
            )
        else:
            out.append(
                QACheck(
                    name="triage_queue.csv has non-empty triage_score_v1",
                    ok=True,
                    detail="skipped (no reanalyze)",
                    path=str(suite_dir / "cases"),
                )
            )
    else:
        # Preserve the legacy check name for compatibility with downstream tooling.
        out.append(
            QACheck(
                name="triage_queue.csv contains column triage_score_v1",
                ok=False,
                detail="no triage_queue.csv found under cases/*/analysis (analysis may have been skipped)",
                path=str(suite_dir / "cases"),
            )
        )

    # --- triage_eval strategy check -------------------------------------
    eval_summary = tables_dir / "triage_eval_summary.json"

    if not expect_calibration:
        out.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(eval_summary),
            )
        )
        return out

    if not eval_summary.exists():
        out.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=False,
                detail="missing triage_eval_summary.json",
                path=str(eval_summary),
            )
        )
    else:
        try:
            payload = _read_json(eval_summary)
            strategies = payload.get("strategies") if isinstance(payload, dict) else None
            strategies_list = list(strategies) if isinstance(strategies, list) else []
            ok = "calibrated" in strategies_list
            detail = "" if ok else f"strategies={strategies_list}"
            out.append(
                QACheck(
                    name="triage_eval_summary includes strategy calibrated",
                    ok=ok,
                    detail=detail,
                    path=str(eval_summary),
                )
            )
        except Exception as e:
            out.append(
                QACheck(
                    name="triage_eval_summary includes strategy calibrated",
                    ok=False,
                    detail=f"failed to read/parse JSON: {e}",
                    path=str(eval_summary),
                )
            )

    return out
