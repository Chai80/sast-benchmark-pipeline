from __future__ import annotations

"""pipeline.analysis.suite.suite_report

Backward-compatible wrapper for :mod:`pipeline.analysis.suite_report`.

The original implementation lived in this module and grew into a large "dumping
ground" mixing I/O, formatting, and business logic. The code has been moved into
`pipeline/analysis/suite_report/` (feature package) while keeping this module as
a stable import path for CLI and tests.
"""

from typing import Any, Dict, Optional
from pathlib import Path

from pipeline.analysis.suite_report import (
    build_suite_report,
    render_suite_report_markdown,
    write_suite_report,
)

__all__ = [
    "build_suite_report",
    "write_suite_report",
    "render_suite_report_markdown",
    "_render_markdown",
]


def _render_markdown(report: Dict[str, Any]) -> str:
    """Backward-compatible alias for render_suite_report_markdown()."""

    return render_suite_report_markdown(report)
