from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.checks

Filesystem-first validation helpers for the triage calibration workflow.

This module contains the check builders and the main
:func:`validate_calibration_suite_artifacts` entrypoint.

Rule of thumb: helpers here should only *read* artifacts. Writing artifacts is
handled in :mod:`pipeline.analysis.qa_calibration_runbook.write`.

Implementation note
-------------------
Historically, this file grew into a very large "god module". It now acts as a
thin facade to keep the public API stable while splitting the implementation
into smaller, focused modules (each <~300 LOC).
"""

from pathlib import Path
from typing import List, Sequence

from .checks_artifacts import _checks_calibration_artifacts, _checks_scanner_receipts
from .checks_discovery import _check_exists
from .checks_gt_tolerance import (
    _checks_gt_ambiguity,
    _checks_gt_tolerance_selection,
    _checks_gt_tolerance_sweep,
)
from .checks_triage import _checks_triage_eval, _checks_triage_queue
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
    checks.extend(_checks_triage_eval(tables_dir, expect_calibration=bool(options.expect_calibration)))

    return checks
