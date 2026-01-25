from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook

Feature package for the QA calibration runbook.

This package contains:
- model.py: checklist dataclass + constants
- checks.py: filesystem-first validation (no writes)
- render_md.py: rendering to text/markdown
- write.py: JSON serialization + writing artifacts

A thin wrapper remains at :mod:`pipeline.analysis.qa.qa_calibration_runbook` for
backwards-compatible imports.
"""

from .model import (
    QA_CHECKLIST_SCHEMA_V1,
    QA_CHECKLIST_JSON_FILENAME,
    QA_CHECKLIST_MD_FILENAME,
    QA_CHECKLIST_TXT_LEGACY_FILENAME,
    QACheck,
    CalibrationSuiteValidationOptions,
    all_ok,
)
from .render_md import render_checklist, render_checklist_markdown
from .write import checklist_to_dict, write_qa_checklist_artifacts
from .checks import print_checklist, validate_calibration_suite_artifacts

__all__ = [
    "QACheck",
    "CalibrationSuiteValidationOptions",
    "all_ok",
    "render_checklist",
    "render_checklist_markdown",
    "checklist_to_dict",
    "write_qa_checklist_artifacts",
    "print_checklist",
    "validate_calibration_suite_artifacts",
    "QA_CHECKLIST_SCHEMA_V1",
    "QA_CHECKLIST_JSON_FILENAME",
    "QA_CHECKLIST_MD_FILENAME",
    "QA_CHECKLIST_TXT_LEGACY_FILENAME",
]
