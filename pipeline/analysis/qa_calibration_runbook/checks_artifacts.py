from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.checks_artifacts

Checklist checks for suite-level artifacts.

This module contains checks that validate that suite-level analysis artifacts
exist and are structurally plausible.
"""

import json
from pathlib import Path
from typing import List

from pipeline.analysis.io.config_receipts import summarize_scanner_config

from .checks_discovery import _check_exists, _suite_plan_scanners
from .checks_io import _to_int
from .model import QACheck


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
            path=str(Path(suite_dir) / "cases"),
            detail="; ".join([p for p in detail_parts if str(p).strip()]),
        )
    ]


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
