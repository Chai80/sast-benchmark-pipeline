from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.render_md

Rendering functions for QA calibration checklists.

This module is formatting-only (no file I/O).
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from .model import QACheck, all_ok


def render_checklist(
    checks: List[QACheck], *, title: str = "QA calibration checklist"
) -> str:
    """Render a concise PASS/FAIL checklist suitable for CLI output."""

    lines: List[str] = []
    lines.append(f"\n🔎 {title}")
    for c in checks:
        icon = (
            "❌" if (not c.ok) else ("⚠️" if bool(getattr(c, "warn", False)) else "✅")
        )
        lines.append(f"{icon} {c.name}")
        # Show details for failures and warnings.
        if (not c.ok) or bool(getattr(c, "warn", False)):
            if c.path:
                lines.append(f"    path: {c.path}")
            if c.detail:
                lines.append(f"    {c.detail}")

    overall_ok = all(c.ok for c in checks)
    lines.append(f"\nOverall: {'PASS' if overall_ok else 'FAIL'}")
    return "\n".join(lines)


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def render_checklist_markdown(
    checks: Sequence[QACheck],
    *,
    title: str = "QA calibration checklist",
    suite_dir: Optional[str | Path] = None,
    suite_id: Optional[str] = None,
) -> str:
    """Render a markdown checklist for humans (GitHub-friendly)."""

    sd: Optional[Path] = None
    if suite_dir is not None:
        try:
            sd = Path(suite_dir).resolve()
        except Exception:
            sd = None

    sid = str(suite_id) if suite_id else (sd.name if sd is not None else "")
    overall_ok = all_ok(checks)

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    if sid:
        lines.append(f"- suite_id: `{sid}`")
    if sd is not None:
        lines.append(f"- suite_dir: `{sd}`")
    lines.append(f"- generated_at: `{_now_iso_utc()}`")
    lines.append(f"- overall: **{'PASS' if overall_ok else 'FAIL'}**")
    lines.append("")

    lines.append("## Checks")
    lines.append("")
    for c in checks:
        ok = bool(c.ok)
        warn = bool(getattr(c, "warn", False))
        icon = "✅" if ok else "❌"
        if ok and warn:
            icon = "⚠️"
        lines.append(f"- {icon} {c.name}")
        if (not ok) or warn:
            if c.path:
                lines.append(f"  - path: `{c.path}`")
            if c.detail:
                lines.append(f"  - detail: {c.detail}")

    lines.append("")
    return "\n".join(lines) + "\n"
