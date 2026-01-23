from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.model

Small data model for the QA calibration runbook.

The runbook produces a checklist (a list of :class:`QACheck`) which can be
rendered for humans and serialized for CI.
"""

from dataclasses import dataclass
from typing import Sequence

QA_CHECKLIST_SCHEMA_V1 = "qa_checklist_v1"

# Canonical filenames for deterministic CI scraping.
QA_CHECKLIST_JSON_FILENAME = "qa_checklist.json"
QA_CHECKLIST_MD_FILENAME = "qa_checklist.md"

# Backwards-compatible alias for existing scripts/tests.
QA_CHECKLIST_TXT_LEGACY_FILENAME = "qa_calibration_checklist.txt"


@dataclass(frozen=True)
class QACheck:
    """One checklist line item."""

    name: str
    ok: bool
    path: str = ""
    detail: str = ""
    warn: bool = False


def all_ok(checks: Sequence[QACheck]) -> bool:
    return all(bool(c.ok) for c in checks)
