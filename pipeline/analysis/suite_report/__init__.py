from __future__ import annotations

"""pipeline.analysis.suite_report

Feature package for suite report generation.

Public API:
- build_suite_report(...)
- write_suite_report(...)
- render_suite_report_markdown(...)
- render_suite_report_html(...)

The implementation is split into small modules:
- model.py: dataclasses
- loaders.py: filesystem-first artifact loading
- compute.py: derive report sections
- render_md.py: markdown formatting
- render_html.py: HTML formatting
"""

from pathlib import Path
from typing import Any, Dict, Optional

from pipeline.analysis.io.write_artifacts import write_json, write_markdown, write_text

from .compute import build_suite_report_model
from .loaders import load_suite_report_inputs
from .render_html import render_suite_report_html
from .render_md import render_suite_report_markdown

# Where suite-level human-friendly reports are written.
# This lives at the suite root (``runs/suites/<suite_id>/``) so it's easy to find
# without digging into analysis internals.
DEFAULT_SUITE_REPORT_DIRNAME = "SuiteReportAnalytics"

__all__ = [
    "DEFAULT_SUITE_REPORT_DIRNAME",
    "build_suite_report",
    "write_suite_report",
    "render_suite_report_markdown",
    "render_suite_report_html",
]


def _compute_base_href(*, suite_dir: Path, report_dir: Path) -> str:
    """Compute a base href for HTML so suite-relative links keep working.

    The HTML report is written under ``<suite_dir>/<report_dirname>/``.
    Setting ``<base href='../'>`` (or deeper) makes links like
    ``cases/<case_id>/...`` resolve correctly from inside the report folder.
    """

    try:
        rel = report_dir.resolve().relative_to(suite_dir.resolve())
        depth = len(rel.parts)
        if depth <= 0:
            return ""
        return "../" * depth
    except Exception:
        # If report_dir isn't under suite_dir (custom absolute path), safest is
        # to omit base href.
        return ""


def _join_suite_rel_path(*, dirname: str, filename: str) -> str:
    """Join dirname + filename into a suite-relative path string.

    This avoids leading slashes when dirname is empty and keeps paths in POSIX
    form for HTML links.
    """

    d = (dirname or "").strip().replace("\\", "/").strip().rstrip("/")
    if not d or d == ".":
        return filename
    return f"{d}/{filename}"



def build_suite_report(
    suite_dir: str | Path,
    *,
    suite_id: Optional[str] = None,
    out_dirname: str = "analysis",
) -> Dict[str, Any]:
    """Build the suite report model (JSON-serializable dict)."""

    suite_dir = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else suite_dir.name

    inputs = load_suite_report_inputs(suite_dir=suite_dir, suite_id=sid, out_dirname=out_dirname)
    return build_suite_report_model(inputs)


def write_suite_report(
    suite_dir: str | Path,
    *,
    suite_id: Optional[str] = None,
    out_dirname: str = "analysis",
    report_dirname: str = DEFAULT_SUITE_REPORT_DIRNAME,
    out_md_filename: str = "suite_report.md",
    out_json_filename: str = "suite_report.json",
    out_html_filename: str = "suite_summary.html",
    write_html: bool = True,
) -> Dict[str, str]:
    """Build + write suite report artifacts.

    Inputs are loaded from the suite analysis directory (default: ``analysis``),
    but **report outputs are written to a dedicated folder at the suite root**.

    Artifacts written
    ----------------
    - Markdown: ``<suite_dir>/<report_dirname>/suite_report.md``
    - JSON    : ``<suite_dir>/<report_dirname>/suite_report.json``
    - HTML    : ``<suite_dir>/<report_dirname>/suite_summary.html`` (optional)

    Notes
    -----
    The HTML writer is intentionally dependency-free (standard library only).
    """

    suite_dir = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else suite_dir.name

    # Inputs live under the analysis folder.
    analysis_dir = suite_dir / out_dirname

    # Outputs live at the suite root in a dedicated report folder.
    report_dir = suite_dir / report_dirname

    out_md = (report_dir / out_md_filename).resolve()
    out_json = (report_dir / out_json_filename).resolve()
    out_html = (report_dir / out_html_filename).resolve()

    inputs = load_suite_report_inputs(
        suite_dir=suite_dir, suite_id=sid, out_dirname=analysis_dir.name
    )
    report = build_suite_report_model(inputs)

    md = render_suite_report_markdown(report)

    base_href = _compute_base_href(suite_dir=suite_dir, report_dir=report_dir)
    self_links = {
        "suite_report_md": _join_suite_rel_path(dirname=report_dirname, filename=out_md_filename),
        "suite_report_json": _join_suite_rel_path(dirname=report_dirname, filename=out_json_filename),
    }

    html = render_suite_report_html(report, base_href=base_href, self_links=self_links)

    out_md.parent.mkdir(parents=True, exist_ok=True)
    write_markdown(out_md, md)

    # Standard JSON writer (stable formatting across pipeline outputs)
    write_json(out_json, report)

    if write_html:
        # HTML is best-effort but should be very unlikely to fail.
        write_text(out_html, html)

    return {
        "out_md": str(out_md),
        "out_json": str(out_json),
        **({"out_html": str(out_html)} if write_html else {}),
    }
