from __future__ import annotations

"""pipeline.analysis.suite_report

Feature package for suite report generation.

Public API:
- build_suite_report(...)
- write_suite_report(...)
- render_suite_report_markdown(...)

The implementation is split into small modules:
- model.py: dataclasses
- loaders.py: filesystem-first artifact loading
- compute.py: derive report sections
- render_md.py: markdown formatting
"""

from pathlib import Path
from typing import Any, Dict, Optional

from pipeline.analysis.io.write_artifacts import write_json, write_markdown

from .compute import build_suite_report_model
from .loaders import load_suite_report_inputs
from .render_md import render_suite_report_markdown

__all__ = [
    "build_suite_report",
    "write_suite_report",
    "render_suite_report_markdown",
]


def build_suite_report(
    suite_dir: str | Path,
    *,
    suite_id: Optional[str] = None,
    out_dirname: str = "analysis",
) -> Dict[str, Any]:
    """Build the suite report model (JSON-serializable dict)."""

    suite_dir = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else suite_dir.name

    inputs = load_suite_report_inputs(
        suite_dir=suite_dir, suite_id=sid, out_dirname=out_dirname
    )
    return build_suite_report_model(inputs)


def write_suite_report(
    suite_dir: str | Path,
    *,
    suite_id: Optional[str] = None,
    out_dirname: str = "analysis",
    out_md_filename: str = "suite_report.md",
    out_json_filename: str = "suite_report.json",
) -> Dict[str, str]:
    """Build + write suite report artifacts (markdown + JSON)."""

    suite_dir = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else suite_dir.name

    analysis_dir = suite_dir / out_dirname
    out_md = (analysis_dir / out_md_filename).resolve()
    out_json = (analysis_dir / out_json_filename).resolve()

    inputs = load_suite_report_inputs(
        suite_dir=suite_dir, suite_id=sid, out_dirname=analysis_dir.name
    )
    report = build_suite_report_model(inputs)
    md = render_suite_report_markdown(report)

    out_md.parent.mkdir(parents=True, exist_ok=True)
    write_markdown(out_md, md)

    # Standard JSON writer (stable formatting across pipeline outputs)
    write_json(out_json, report)

    return {
        "out_md": str(out_md),
        "out_json": str(out_json),
    }
