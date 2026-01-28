from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.checks_discovery

Filesystem discovery helpers for the QA calibration checklist.

These helpers locate expected files under a suite directory and provide small
check-building utilities.
"""

from pathlib import Path
from typing import List, Optional

from .checks_io import _read_json
from .model import QACheck


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
