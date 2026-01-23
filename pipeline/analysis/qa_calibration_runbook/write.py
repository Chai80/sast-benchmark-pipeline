from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.write

Serialization + artifact writers for QA calibration checklists.

This module is the only place that writes checklist artifacts to disk.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.analysis.io.write_artifacts import write_json

from .model import (
    QA_CHECKLIST_SCHEMA_V1,
    QA_CHECKLIST_JSON_FILENAME,
    QA_CHECKLIST_MD_FILENAME,
    QA_CHECKLIST_TXT_LEGACY_FILENAME,
    QACheck,
    all_ok,
)
from .render_md import render_checklist, render_checklist_markdown


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def checklist_to_dict(
    checks: Sequence[QACheck],
    *,
    suite_dir: str | Path,
    suite_id: Optional[str] = None,
    title: str = "QA calibration checklist",
) -> Dict[str, Any]:
    """Serialize a QA checklist to a stable JSON payload.

    This is intentionally small and filesystem-first. The checklist itself
    *proves what ran* by asserting required artifacts exist.
    """

    sd = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else sd.name

    checks_list: List[Dict[str, Any]] = []
    pass_n = 0
    warn_n = 0
    fail_n = 0
    for c in checks:
        ok = bool(c.ok)
        warn = bool(getattr(c, "warn", False))
        if ok and warn:
            warn_n += 1
        elif ok:
            pass_n += 1
        else:
            fail_n += 1

        checks_list.append(
            {
                "name": str(c.name),
                "ok": bool(ok),
                "warn": bool(warn),
                "path": str(c.path or ""),
                "detail": str(c.detail or ""),
            }
        )

    overall_ok = all_ok(checks)

    return {
        "schema_version": QA_CHECKLIST_SCHEMA_V1,
        "generated_at": _now_iso_utc(),
        "title": str(title),
        "suite": {
            "suite_id": sid,
            "suite_dir": str(sd),
        },
        "summary": {
            "overall": "PASS" if overall_ok else "FAIL",
            "overall_ok": bool(overall_ok),
            "checks_total": int(len(checks_list)),
            "pass": int(pass_n),
            "warn": int(warn_n),
            "fail": int(fail_n),
        },
        "checks": checks_list,
    }


def write_qa_checklist_artifacts(
    checks: Sequence[QACheck],
    *,
    suite_dir: str | Path,
    suite_id: Optional[str] = None,
    title: str = "QA calibration checklist",
    out_dirname: str = "analysis",
    json_filename: str = QA_CHECKLIST_JSON_FILENAME,
    md_filename: str = QA_CHECKLIST_MD_FILENAME,
    legacy_txt_filename: str = QA_CHECKLIST_TXT_LEGACY_FILENAME,
) -> Dict[str, str]:
    """Write checklist artifacts under runs/suites/<suite_id>/analysis/.

    Outputs
    -------
    - analysis/qa_checklist.json (canonical, stable for CI)
    - analysis/qa_checklist.md (human-friendly)
    - analysis/qa_calibration_checklist.txt (legacy alias for compatibility)
    """

    sd = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else sd.name
    out_dir = (sd / out_dirname).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = checklist_to_dict(checks, suite_dir=sd, suite_id=sid, title=title)
    out_json = (out_dir / json_filename).resolve()
    write_json(out_json, payload)

    md = render_checklist_markdown(checks, title=title, suite_dir=sd, suite_id=sid)
    out_md = (out_dir / md_filename).resolve()
    out_md.write_text(md, encoding="utf-8")

    # Preserve the existing legacy filename used by tests and scripts.
    txt = render_checklist(list(checks), title=title)
    out_txt = (out_dir / legacy_txt_filename).resolve()
    out_txt.write_text(txt, encoding="utf-8")

    return {
        "out_json": str(out_json),
        "out_md": str(out_md),
        "out_txt": str(out_txt),
    }
