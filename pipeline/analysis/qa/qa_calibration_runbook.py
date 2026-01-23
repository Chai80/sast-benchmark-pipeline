from __future__ import annotations

"""pipeline.analysis.qa.qa_calibration_runbook

Backward-compatible wrapper for :mod:`pipeline.analysis.qa_calibration_runbook`.

The original implementation grew large and mixed I/O, validation, and
formatting. It has been split into a feature package under
`pipeline/analysis/qa_calibration_runbook/` while preserving this import path for
CLI and tests.
"""

from pipeline.analysis.qa_calibration_runbook import (
    QA_CHECKLIST_SCHEMA_V1,
    QA_CHECKLIST_JSON_FILENAME,
    QA_CHECKLIST_MD_FILENAME,
    QA_CHECKLIST_TXT_LEGACY_FILENAME,
    QACheck,
    all_ok,
    checklist_to_dict,
    print_checklist,
    render_checklist,
    render_checklist_markdown,
    validate_calibration_suite_artifacts,
    write_qa_checklist_artifacts,
)

__all__ = [
    "QACheck",
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
